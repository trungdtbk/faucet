"""Valve IPv4/IPv6 routing implementation."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASISo
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time

import ipaddr

import valve_of
import valve_packet

from ryu.lib.packet import arp, icmp, icmpv6, ipv4, ipv6
from ryu.ofproto import ether
from ryu.ofproto import inet


class LinkNeighbor(object):
    """Describes a link (layer 2) neighbor, as a nexthop."""

    def __init__(self, eth_src, now):
        self.eth_src = eth_src
        self.cache_time = now

class RouteTable(object):
    """Maintain RIB entries
    """
    def __init__(self):
        self._routes = {}
        self.max_paths = 16

    def add_route(self, ip_dst, ip_gw):
        """Add a new or update an existing route
        Return the route object
        """
        nexthop_set = self._routes.get(ip_dst, set())
        if ip_gw in nexthop_set:
            return False
        nexthop_set.add(ip_gw)
        self._routes[ip_dst] = nexthop_set
        return True

    def del_route(self, ip_dst, ip_gw=None):
        """Delete a route object from the table
        Returns:
            None
        """

        if ip_gw == None:
            self._routes.pop(ip_dst, set())
        else:
            nexthop_set = self._routes.get(ip_dst, set())
            nexthop_set.discard(ip_gw)
            self._routes[ip_gw] = nexthop_set

    def get_nexthops(self, ip_dst):
        """Get a route object belonging to ip_dst
        """
        return self._routes.get(ip_dst, set())

    def get_routes(self):
        return self._routes

    def get_all_gw(self):
        """Return all ip gateway
        """
        nexthops = set()
        for nexthop_set in self._routes.itervalues():
            nexthops.update(nexthop_set)
        return nexthops


class ValveRouteManager(object):
    """Base class to implement RIB/FIB."""

    def __init__(self, logger, valve):
        self.logger = logger
        self.valve = valve

        self.faucet_mac = self.valve.FAUCET_MAC
        self.arp_neighbor_timeout = self.valve.dp.arp_neighbor_timeout
        self.eth_src_table = self.valve.dp.eth_src_table
        self.eth_dst_table = self.valve.dp.eth_dst_table
        self.route_priority = self.valve.dp.highest_priority
        self.valve_in_match = self.valve.valve_in_match
        self.valve_flowdel = self.valve.valve_flowdel
        self.valve_flowmod = self.valve.valve_flowmod
        self.valve_flowcontroller = self.valve.valve_flowcontroller

        self.arp_cache = {}
        self.nd_cache = {}
        # Map ip_gw with group id
        self.ip_gw_to_group_id = {}
        self.ip_gw_to_metadata = {}
        self.pid_to_vmac = {}
        self.ip_gw_to_tunnel = {} # IP nexthop to tunnel ID
        self.path_table = {} #Mapping between PID & (ip_dst, ip_gw)
        self.local_paths = set()
        self.tunnel_table = self.valve.dp.tunnel_table

        # Testing
        #self.ip_gw_to_tunnel[ipaddr.IPAddress("10.0.0.5")] = 100
        self.routes = RouteTable()

        self.max_paths = 16 # Maximum number of forwardingpaths per prefixes
        self.metadata_table = {}

    def _get_metadata(self, pid):
        """
        Return metatada for path identifier
        """
        return int(pid)

    def _get_vmac(self, ip=None):
        """Compute virtual MAC from IPAddress
        """
        if ip in self.pid_to_vmac:
            return self.pid_to_vmac[ip]
        elif ip is None:
            return self.faucet_mac

        ip = ipaddr.IPAddress(hash(int(ip)) & ((1<<32) -1))
        mac = '0E:00:' + '{:02X}:{:02X}:{:02X}:{:02X}'.format(
                *map(int, str(ip).split('.')))
        self.pid_to_vmac[ip] = mac
        return mac

    def _vlan_vid(self, vlan, in_port):
        vid = None
        if vlan.port_is_tagged(in_port):
            vid = vlan.vid
        return vid

    def _eth_type(self):
        """Return EtherType for FIB entries."""
        pass

    def _routes(self):
        pass

    def _neighbor_cache(self):
        pass

    def _neighbor_resolver_pkt(self, vid, controller_ip, ip_gw):
        pass

    def _neighbor_resolver(self, ip_gw, controller_ip, vlan, ports):
        ofmsgs = []
        if ports:
            self.logger.info('Resolving %s', ip_gw)
            port_num = ports[0].number
            vid = self._vlan_vid(vlan, port_num)
            resolver_pkt = self._neighbor_resolver_pkt(
                vid, controller_ip, ip_gw)
            for port in ports:
                ofmsgs.append(valve_of.packetout(
                    port.number, resolver_pkt.data))
        return ofmsgs

    def _add_resolved_route(self, vlan, ip_gw, ip_dst, eth_dst,
                                  is_updated=None):
        ofmsgs = []
        if is_updated is not None:
            if is_updated:
                self.logger.info(
                    'Updating next hop for route %s via %s (%s)',
                    ip_dst, ip_gw, eth_dst)
            else:
                self.logger.info(
                    'Adding new route %s via %s (%s)',
                    ip_dst, ip_gw, eth_dst)

            prefixlen = ipaddr.IPNetwork(ip_dst).prefixlen
            priority = self.route_priority + prefixlen
            pid = self.path_table[(ip_dst, ip_gw)]
            if ip_gw in self.local_paths or pid is None:
                inst = [
                        valve_of.apply_actions([
                            valve_of.set_eth_src(self.faucet_mac),
                            valve_of.set_eth_dst(eth_dst),
                            valve_of.dec_ip_ttl()])]
                inst.append(valve_of.goto_table(self.eth_dst_table))
            else:
                inst = [
                    valve_of.apply_actions([
                        valve_of.pop_vlan(),
                        valve_of.set_eth_src(self.faucet_mac),
                        valve_of.set_eth_dst(eth_dst),
                        valve_of.dec_ip_ttl()] +
                        valve_of.push_mpls_act(pid))]
                inst.append(valve_of.goto_table(self.tunnel_table))
            if pid is not None:
                priority += 1
            in_match = self.valve_in_match(
                self.fib_table, eth_type=self._eth_type(),
                vlan=vlan, nw_dst=ip_dst,
                metadata=pid)
            ofmsgs.append(self.valve_flowmod(
                self.fib_table,
                in_match,
                priority=priority,
                inst=inst))

        return ofmsgs

    def _update_nexthop(self, vlan, in_port, eth_src, resolved_ip_gw):
        ofmsgs = []
        is_updated = None
        neighbor_cache = self._neighbor_cache()
        group_cmd = None
        group_id = None
        if resolved_ip_gw in neighbor_cache:
            cached_eth_dst = neighbor_cache[resolved_ip_gw].eth_src
            if cached_eth_dst != eth_src:
                is_updated = True
                # Modify the existing group in the group table
                group_id = self.ip_gw_to_group_id[resolved_ip_gw]
                group_cmd = valve_of.groupmod
        else:
            is_updated = False
            # Create a new group in group table
            group_cmd = valve_of.groupadd
            group_id = (hash(int(resolved_ip_gw))  & ((1<<32) -1)) +\
                    valve_of.ROUTE_GROUP_OFFSET
            self.ip_gw_to_group_id[resolved_ip_gw] = group_id

        if is_updated is not None:
            # Find port from vlan
            port = None
            for port in vlan.untagged + vlan.tagged:
                if port.number == in_port:
                    break
            actions = []
            actions.append(valve_of.output_port(port.number))
            buckets=[valve_of.bucket(actions=actions)]
            ofmsgs.append(group_cmd(group_id=group_id, buckets=buckets))

            if resolved_ip_gw not in self.local_paths:
                actions = []
                if resolved_ip_gw in self.ip_gw_to_tunnel:
                    actions.extend(valve_of.push_mpls_act(
                            self.ip_gw_to_tunnel[resolved_ip_gw]))
                actions.append(valve_of.output_port(in_port))
                inst = [valve_of.apply_actions(actions)]
                ofmsgs.append(self.valve_flowmod(
                    self.tunnel_table,
                    match=self.valve_in_match(
                        self.tunnel_table,
                        eth_dst=eth_src),
                    priority=self.route_priority,
                    inst=inst))
            all_routes = self.routes.get_routes()
            for ip_dst, gw_set in all_routes.iteritems():
                if resolved_ip_gw in gw_set:
                    ofmsgs.extend(self._add_resolved_route(vlan,
                        resolved_ip_gw, ip_dst, eth_src, is_updated))

        now = time.time()
        link_neighbor = LinkNeighbor(eth_src, now)
        neighbor_cache[resolved_ip_gw] = link_neighbor

        return ofmsgs

    def resolve_gateways(self, vlan, now):
        """Re/resolve all gateways.

        Args:
            vlan (vlan): VLAN containing this RIB/FIB.
            now (float): seconds since epoch.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        untagged_ports = vlan.untagged_flood_ports(False)
        tagged_ports = vlan.tagged_flood_ports(False)
        neighbor_cache = self._neighbor_cache()
        for ip_gw in set(self.routes.get_all_gw()):
            for controller_ip in vlan.controller_ips:
                if ip_gw in controller_ip:
                    cache_age = None
                    if ip_gw in neighbor_cache:
                        cache_time = neighbor_cache[ip_gw].cache_time
                        cache_age = now - cache_time
                    if (cache_age is None or
                            cache_age > self.arp_neighbor_timeout):
                        for ports in untagged_ports, tagged_ports:
                            ofmsgs.extend(self._neighbor_resolver(
                                ip_gw, controller_ip, vlan, ports))
        return ofmsgs

    def add_route(self, ip_gw, ip_dst, vip=None, pid=None, local=True):
        """Add a route to the RIB.

        Args:
            ip_gw (ipaddr.IPAddress): IP address of nexthop.
            ip_dst (ipaddr.IPNetwork): destination IP network.
            vip (ipaddr.IPAddress): virtual ip of Valve as nexthop to hosts
            pid (int): path identifier
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        vmac = None
        if vip in self.pid_to_vmac:
            vmac = self.pid_to_vmac[vip]
        elif vip is not None:
            ip = ipaddr.IPAddress(hash(int(vip)) & ((1<<32) -1))
            vmac = '0E:00:' + '{:02X}:{:02X}:{:02X}:{:02X}'.format(
                    *map(int, str(ip).split('.')))
        else:
            vmac = self.faucet_mac

        vlan = None
        for vlan in self.valve.dp.vlans.values():
            for controller_ip in vlan.controller_ips:
                if ip_gw in controller_ip:
                    if vip is None:
                        self.local_paths.add(ip_gw)
                        vip = controller_ip.ip
                        pid = None
                    break
        if vlan is None:
            self.logger.info("add route %s via %s failed", ip_dst, ip_gw)
            return ofmsgs
        if local:
            self.local_paths.add(ip_gw)

        if vip not in self.pid_to_vmac:
            # Add a controller rule to this VMAC
            ofmsgs.append(self.valve_flowcontroller(
                self.eth_src_table,
                self.valve_in_match(
                    self.eth_src_table,
                    eth_type=ether.ETH_TYPE_ARP,
                    nw_dst=ipaddr.IPNetwork(vip)),
                    priority=self.route_priority + vip.max_prefixlen))
            if pid is not None:
                ofmsgs.append(self.valve_flowmod(
                    self.eth_src_table,
                    match=self.valve_in_match(
                        self.eth_src_table,
                        eth_type=self._eth_type(),
                        eth_dst=vmac),
                    priority=self.route_priority + 1,
                    inst=[
                        valve_of.write_metadata(pid),
                        valve_of.goto_table(self.fib_table)]))
        self.pid_to_vmac[vip] = vmac
        self.routes.add_route(ip_gw=ip_gw, ip_dst=ip_dst)
        old_pid = self.path_table.get((ip_dst, ip_gw), None)
        if old_pid is not None and old_pid != pid:
            ofmsgs.extend(self.del_route(
                ip_dst=ip_dst,
                ip_gw=ip_gw))
        self.path_table[(ip_dst, ip_gw)] = pid
        if local and pid is not None:
            ofmsgs.append(self.valve_flowmod(
                self.eth_src_table,
                match=self.valve_in_match(
                    self.eth_src_table,
                    eth_type=ether.ETH_TYPE_MPLS,
                    mpls_label=pid,
                    eth_dst=self.faucet_mac),
                priority=self.route_priority + 1,
                inst=[
                    valve_of.apply_actions(
                        [valve_of.pop_mpls_act()]),
                    valve_of.write_metadata(pid),
                    valve_of.goto_table(self.fib_table)]))

        neighbor_cache = self._neighbor_cache()
        if ip_gw in neighbor_cache:
            eth_dst = neighbor_cache[ip_gw].eth_src
            ofmsgs.extend(self._add_resolved_route(
                vlan=vlan,
                ip_gw=ip_gw,
                ip_dst=ip_dst,
                eth_dst=eth_dst,
                is_updated=False))

        self.logger.info("add route %s via %s (pid: %s)", ip_dst, ip_gw, pid)

        return ofmsgs

    def del_route(self, ip_dst, ip_gw):
        """Delete a route from the RIB.

        Only one route with this exact destination is supported.

        Args:
            ip_dst (ipaddr.IPNetwork): destination IP network.
            ip_gw (ipaddr.IPAddress): if None, delete all routes to ip_dst
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        self.routes.del_route(ip_dst, ip_gw)
        self.local_paths.discard(ip_gw)
        pid = self.path_table.pop((ip_dst, ip_gw), None)
        """
        ofmsgs.append(
                self.valve_flowdel(
                    self.eth_src_table,
                    match=self.valve_in_match(
                        self.eth_src_table,
                        eth_type=self._eth_type(),
                        eth_dst=
        """
        match = self.valve_in_match(
                self.fib_table,
                eth_type=self._eth_type(),
                nw_dst=ip_dst,
                metadata=pid)
        ofmsgs.extend(self.valve_flowdel(self.fib_table, match))

        return ofmsgs

    def control_plane_handler(self, in_port, vlan, eth_src, eth_dst, pkt):
        pass


class ValveIPv4RouteManager(ValveRouteManager):
    """Implement IPv4 RIB/FIB."""

    def __init__(self, logger, valve):
        super(ValveIPv4RouteManager, self).__init__(logger, valve)

        self.fib_table = self.valve.dp.ipv4_fib_table

    def _eth_type(self):
        return ether.ETH_TYPE_IP

    def _neighbor_cache(self):
        return self.arp_cache

    def _neighbor_resolver_pkt(self, vid, controller_ip, ip_gw):
        return valve_packet.arp_request(
            self.faucet_mac, vid, controller_ip.ip, ip_gw)

    def add_controller_ip(self, vlan, controller_ip, controller_ip_host):
        ofmsgs = []
        max_prefixlen = controller_ip_host.prefixlen
        priority = self.route_priority + max_prefixlen
        ofmsgs.append(self.valve_flowcontroller(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=ether.ETH_TYPE_ARP,
                nw_dst=controller_ip_host,
                vlan=vlan),
            priority=priority))
        # Initialize IPv4 FIB
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self._eth_type(),
                eth_dst=self.faucet_mac),
            priority=self.route_priority + 1,
            inst=[
                valve_of.goto_table(self.fib_table)]))
        ofmsgs.append(self.valve_flowcontroller(
            self.fib_table,
            self.valve_in_match(
                self.fib_table,
                vlan=vlan,
                eth_type=self._eth_type(),
                nw_proto=inet.IPPROTO_ICMP,
                nw_src=controller_ip,
                nw_dst=controller_ip_host),
            priority=priority))
        return ofmsgs

    def control_plane_arp_handler(self, in_port, vlan, eth_src, eth_dst, arp_pkt):
        ofmsgs = []
        opcode = arp_pkt.opcode
        src_ip = ipaddr.IPv4Address(arp_pkt.src_ip)
        dst_ip = ipaddr.IPv4Address(arp_pkt.dst_ip)
        if (opcode == arp.ARP_REQUEST and
                vlan.ip_in_controller_subnet(src_ip) and
                vlan.ip_in_controller_subnet(dst_ip)):
            vid = self._vlan_vid(vlan, in_port)
            arp_reply = valve_packet.arp_reply(
                self.pid_to_vmac.get(dst_ip, self.faucet_mac),
                eth_src, vid, dst_ip, src_ip)
            ofmsgs.append(valve_of.packetout(in_port, arp_reply.data))
            self.logger.info(
                'Responded to ARP request for %s from %s', src_ip, dst_ip)
        elif (opcode == arp.ARP_REPLY and
              eth_dst == self.faucet_mac and
              vlan.ip_in_controller_subnet(src_ip) and
              vlan.ip_in_controller_subnet(dst_ip)):
            self.logger.info('ARP response %s for %s', eth_src, src_ip)
            ofmsgs.extend(self._update_nexthop(vlan, in_port, eth_src, src_ip))
        return ofmsgs

    def control_plane_icmp_handler(self, in_port, vlan, eth_src,
                                   ipv4_pkt, icmp_pkt):
        ofmsgs = []
        src_ip = ipaddr.IPv4Address(ipv4_pkt.src)
        dst_ip = ipaddr.IPv4Address(ipv4_pkt.dst)
        if (icmp_pkt is not None and
                vlan.ip_in_controller_subnet(src_ip) and
                vlan.ip_in_controller_subnet(dst_ip)):
            vid = self._vlan_vid(vlan, in_port)
            echo_reply = valve_packet.echo_reply(
                self.faucet_mac, eth_src, vid, dst_ip, src_ip, icmp_pkt.data)
            ofmsgs.append(valve_of.packetout(in_port, echo_reply.data))
        return ofmsgs

    def control_plane_handler(self, in_port, vlan, eth_src, eth_dst, pkt):
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is not None:
            return self.control_plane_arp_handler(
                in_port, vlan, eth_src, eth_dst, arp_pkt)

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt is not None:
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt is not None:
                return self.control_plane_icmp_handler(
                    in_port, vlan, eth_src, ipv4_pkt, icmp_pkt)

        return []


class ValveIPv6RouteManager(ValveRouteManager):
    """Implement IPv6 FIB."""

    def __init__(self, logger, valve):
        super(ValveIPv6RouteManager, self).__init__(logger, valve)

        self.fib_table = self.valve.dp.ipv6_fib_table

    def _eth_type(self):
        return ether.ETH_TYPE_IPV6

    def _neighbor_cache(self):
        return self.nd_cache

    def _neighbor_resolver_pkt(self, vid, controller_ip, ip_gw):
        return valve_packet.nd_request(
            self.faucet_mac, vid, controller_ip.ip, ip_gw)

    def add_controller_ip(self, vlan, controller_ip, controller_ip_host):
        ofmsgs = []
        max_prefixlen = controller_ip_host.prefixlen
        priority = self.route_priority + max_prefixlen
        ofmsgs.append(self.valve_flowcontroller(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self._eth_type(),
                vlan=vlan,
                nw_proto=inet.IPPROTO_ICMPV6,
                ipv6_nd_target=controller_ip_host,
                icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT),
            priority=priority))
        ofmsgs.append(self.valve_flowcontroller(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self._eth_type(),
                eth_dst=self.faucet_mac,
                vlan=vlan,
                nw_proto=inet.IPPROTO_ICMPV6,
                icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT),
            priority=priority))
        # Initialize IPv6 FIB
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self._eth_type(),
                eth_dst=self.faucet_mac,
                vlan=vlan),
            priority=self.route_priority,
            inst=[valve_of.goto_table(self.fib_table)]))
        ofmsgs.append(self.valve_flowcontroller(
            self.fib_table,
            self.valve_in_match(
                self.fib_table,
                eth_type=self._eth_type(),
                vlan=vlan,
                nw_proto=inet.IPPROTO_ICMPV6,
                nw_dst=controller_ip_host,
                icmpv6_type=icmpv6.ICMPV6_ECHO_REQUEST),
            priority=priority))
        return ofmsgs

    def control_plane_icmpv6_handler(self, in_port, vlan, eth_src,
                                     ipv6_pkt, icmpv6_pkt):
        vid = self._vlan_vid(vlan, in_port)
        src_ip = ipaddr.IPv6Address(ipv6_pkt.src)
        dst_ip = ipaddr.IPv6Address(ipv6_pkt.dst)
        icmpv6_type = icmpv6_pkt.type_
        ofmsgs = []
        if (icmpv6_type == icmpv6.ND_NEIGHBOR_SOLICIT and
                vlan.ip_in_controller_subnet(src_ip)):
            nd_reply = valve_packet.nd_reply(
                self.faucet_mac, eth_src, vid,
                icmpv6_pkt.data.dst, src_ip, ipv6_pkt.hop_limit)
            ofmsgs.extend([valve_of.packetout(in_port, nd_reply.data)])
        elif (icmpv6_type == icmpv6.ND_NEIGHBOR_ADVERT and
              vlan.ip_in_controller_subnet(src_ip)):
            resolved_ip_gw = ipaddr.IPv6Address(icmpv6_pkt.data.dst)
            self.logger.info('ND response %s for %s', eth_src, resolved_ip_gw)
            ofmsgs.extend(self._update_nexthop(
                vlan, in_port, eth_src, resolved_ip_gw))
        elif icmpv6_type == icmpv6.ICMPV6_ECHO_REQUEST:
            icmpv6_echo_reply = valve_packet.icmpv6_echo_reply(
                self.faucet_mac, eth_src, vid,
                dst_ip, src_ip, ipv6_pkt.hop_limit,
                icmpv6_pkt.data.id, icmpv6_pkt.data.seq, icmpv6_pkt.data.data)
            ofmsgs.extend([valve_of.packetout(in_port, icmpv6_echo_reply.data)])
        return ofmsgs

    def control_plane_handler(self, in_port, vlan, eth_src, eth_dst, pkt):
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        if ipv6_pkt is not None:
            icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
            if icmpv6_pkt is not None:
                return self.control_plane_icmpv6_handler(
                    in_port, vlan, eth_src, ipv6_pkt, icmpv6_pkt)
        return []
