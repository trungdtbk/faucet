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

    def __init__(self, dp_id, port_no, eth_src, now):
        self.dp_id = dp_id
        self.port_no = port_no
        self.eth_src = eth_src
        self.cache_time = now

class Route(object):

    def __init__(self, dest):
        self._dest = dest
        self._nexthops = set()

    def add_nexthop(self, nexthop):
        self._nexthops.add(nexthop)

    def del_nexthop(self, nexthop):
        self._nexthops.discard(nexthop)

    @property
    def nexthops(self):
        return self._nexthops

class RouteTable(object):

    def __init__(self):
        self._routes = {}
        self._default_routes = {}

    def add_route(self, ip_dst, ip_gw, default=True):
        """Add a new or update an existing route
        Return the route object
        """
        nexthop_set = self._routes.get(ip_dst, set())
        nexthop_set.add(ip_gw)
        self._routes[ip_dst] = nexthop_set
        if default:
            self._default_routes[ip_dst] = ip_gw

    def del_route(self, ip_dst):
        """Delete a route object from the table
        Return the deleted route
        """
        self._routes.pop(ip_dst, None)
        self._default_routes.pop(ip_dst, None)

    def get_nexthops(self, ip_dst):
        """Get a route object belonging to ip_dst
        """
        return self._routes.get(ip_dst, set())

    def get_default_nexthop(self, ip_dst):
        return self._default_routes.get(ip_dst, None)

    def del_nexthop(self, ip_dst, ip_gw):
        """Delete a nexthop belong to a route
        """
        nexthop_set = self._routes.get(ip_dst, set())
        nexthop_set.discard(ip_gw)
        self._routes[ip_dst] = nexthop_set
        if ip_gw == self._default_routes.get(ip_dst, None):
            self._default_routes.pop(ip_dst, None)

    def get_default_routes(self):
        return self._default_routes

    def get_routes(self):
        return self._routes

    def get_all_nexthops(self):
        """Return all nexthops
        """
        nexthops = set()
        for nexthop_set in self._routes.itervalues():
            nexthops.update(nexthop_set)
        return nexthops

class ValveRouteManager(object):
    """Base class to implement RIB/FIB."""

    def __init__(self, logger, faucet_mac, arp_neighbor_timeout,
                 fib_table, ip_multi_table, eth_src_table, eth_dst_table,
                 route_priority,
                 valve_in_match, valve_flowdel, valve_flowmod,
                 valve_flowcontroller):
        self.logger = logger
        self.faucet_mac = faucet_mac
        self.arp_neighbor_timeout = arp_neighbor_timeout
        self.fib_table = fib_table
        self.ip_multi_table = ip_multi_table
        self.eth_src_table = eth_src_table
        self.eth_dst_table = eth_dst_table
        self.route_priority = route_priority
        self.valve_in_match = valve_in_match
        self.valve_flowdel = valve_flowdel
        self.valve_flowmod = valve_flowmod
        self.valve_flowcontroller = valve_flowcontroller

        self.arp_cache = {}
        self.nd_cache = {}
        self.ipv4_routes = {}
        self.ipv6_routes = {}

        self.route_table = RouteTable()

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

    def _add_resolved_route(self, ip_gw, ip_dst, eth_dst, is_updated=None):
        ofmsgs = []
        if is_updated is not None:
            in_match = self.valve_in_match(
                self.fib_table, eth_type=self._eth_type(), nw_dst=ip_dst)
            prefixlen = ipaddr.IPNetwork(ip_dst).prefixlen
            priority = self.route_priority + prefixlen
            if is_updated:
                self.logger.info(
                    'Updating next hop for route %s via %s (%s)',
                    ip_dst, ip_gw, eth_dst)
                """
                ofmsgs.extend(self.valve_flowdel(
                    self.fib_table,
                    in_match,
                    priority=priority))
                """
            else:
                self.logger.info(
                    'Adding new route %s via %s (%s)',
                    ip_dst, ip_gw, eth_dst)

            priority = self.route_priority + prefixlen

            if ip_gw in self.route_table.get_nexthops(ip_dst):
                if ip_gw == self.route_table.get_default_nexthop(ip_dst):
                    self.logger.info("Updating default route %s via %s (%s)",
                            ip_dst, ip_gw, eth_dst)

                    in_match = self.valve_in_match(self.fib_table,
                                                   eth_type=self._eth_type(),
                                                   nw_dst=ip_dst)
                    ofmsgs.append(self.valve_flowmod(
                        self.fib_table,
                        in_match,
                        priority=priority,
                        inst=[valve_of.apply_actions(
                            [valve_of.set_eth_src(self.faucet_mac),
                             valve_of.set_eth_dst(eth_dst),
                             valve_of.dec_ip_ttl()])] +
                        [valve_of.goto_table(self.ip_multi_table)]))
                else:
                    self.logger.info("Updating additional route %s via %s (%s)",
                            ip_dst, ip_gw, eth_dst)

                    ofmsgs.append(self.valve_flowmod(
                        table_id=self.ip_multi_table,
                        match=self.valve_in_match(
                            table_id=self.ip_multi_table,
                            metadata=self.get_label(ip_gw)),
                        priority=priority,
                        inst=[valve_of.apply_actions(
                            [valve_of.set_eth_dst(eth_dst)]),
                            valve_of.goto_table(self.eth_dst_table)]))

        return ofmsgs

    def _update_nexthop(self, dp_id, in_port, eth_src, resolved_ip_gw):
        ofmsgs = []
        is_updated = None
        neighbor_cache = self._neighbor_cache()
        if resolved_ip_gw in neighbor_cache:
            cached_eth_dst = neighbor_cache[resolved_ip_gw].eth_src
            if cached_eth_dst != eth_src:
                is_updated = True
        else:
            is_updated = False

        for ip_dst in self.route_table.get_routes().iterkeys():
            if resolved_ip_gw in self.route_table.get_nexthops(ip_dst):
                ofmsgs.extend(self._add_resolved_route(
                    resolved_ip_gw, ip_dst, eth_src, is_updated))

        now = time.time()
        link_neighbor = LinkNeighbor(dp_id, in_port, eth_src, now)
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
        for ip_gw in set(self.route_table.get_all_nexthops()):
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

    def add_route(self, ip_gw, ip_dst, default=True):
        """Add a route to the RIB.

        Args:
            ip_gw (ipaddr.IPAddress): IP address of nexthop.
            ip_dst (ipaddr.IPNetwork): destination IP network.
            default: True/False: whether the ip_gw is the default gw
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        neighbor_cache = self._neighbor_cache()
        self.route_table.add_route(ip_dst=ip_dst, ip_gw=ip_gw, default=default)
        if ip_gw in neighbor_cache:
            eth_dst = neighbor_cache[ip_gw].eth_src
            ofmsgs.extend(self._add_resolved_route(
                ip_gw=ip_gw,
                ip_dst=ip_dst,
                eth_dst=eth_dst,
                is_updated=False))
        return ofmsgs

    def del_route(self, ip_dst):
        """Delete a route from the RIB.

        Only one route with this exact destination is supported.

        Args:
            ip_dst (ipaddr.IPNetwork): destination IP network.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        route = self.route_table.del_route(ip_dst)
        if route:
            route_match = self.valve_in_match(
                self.fib_table, eth_type=self._eth_type(), nw_dst=ip_dst)
            ofmsgs.extend(self.valve_flowdel(
                self.fib_table, route_match))
        return ofmsgs

    def control_plane_handler(self, dp_id, in_port, vlan, eth_src, eth_dst, pkt):
        pass

    def get_routes(self):
        return self.route_table.get_default_routes()

    def get_label(self, ip_gw):
        return int(ipaddr.IPAddress(ip_gw))

class ValveIPv4RouteManager(ValveRouteManager):
    """Implement IPv4 RIB/FIB."""

    def _eth_type(self):
        return ether.ETH_TYPE_IP

    def _routes(self):
        return self.ipv4_routes

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
                eth_dst=self.faucet_mac,
                vlan=vlan),
            priority=self.route_priority,
            inst=[valve_of.goto_table(self.fib_table)]))
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

    def control_plane_arp_handler(self,
            dp_id, in_port, vlan, eth_src, eth_dst, arp_pkt):
        ofmsgs = []
        opcode = arp_pkt.opcode
        src_ip = ipaddr.IPv4Address(arp_pkt.src_ip)
        dst_ip = ipaddr.IPv4Address(arp_pkt.dst_ip)

        if (opcode == arp.ARP_REQUEST and
                vlan.ip_in_controller_subnet(src_ip) and
                vlan.ip_in_controller_subnet(dst_ip)):
            vid = self._vlan_vid(vlan, in_port)
            arp_reply = valve_packet.arp_reply(
                self.faucet_mac, eth_src, vid, dst_ip, src_ip)
            ofmsgs.append(valve_of.packetout(in_port, arp_reply.data))
            self.logger.info(
                'Responded to ARP request for %s from %s', src_ip, dst_ip)
        elif (opcode == arp.ARP_REPLY and
              eth_dst == self.faucet_mac and
              vlan.ip_in_controller_subnet(src_ip) and
              vlan.ip_in_controller_subnet(dst_ip)):
            self.logger.info('ARP response %s for %s', eth_src, src_ip)
            ofmsgs.extend(self._update_nexthop(
                                        dp_id, in_port, eth_src, src_ip))
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

    def control_plane_handler(self, dp_id, in_port, vlan, eth_src, eth_dst, pkt):
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is not None:
            return self.control_plane_arp_handler(
                dp_id, in_port, vlan, eth_src, eth_dst, arp_pkt)

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt is not None:
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt is not None:
                return self.control_plane_icmp_handler(
                    in_port, vlan, eth_src, ipv4_pkt, icmp_pkt)

        return []


class ValveIPv6RouteManager(ValveRouteManager):
    """Implement IPv6 FIB."""

    def _eth_type(self):
        return ether.ETH_TYPE_IPV6

    def _routes(self):
        return self.ipv6_routes

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

    def control_plane_icmpv6_handler(self, dp_id, in_port, vlan, eth_src,
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
                                dp_id, in_port, eth_src, resolved_ip_gw))
        elif icmpv6_type == icmpv6.ICMPV6_ECHO_REQUEST:
            icmpv6_echo_reply = valve_packet.icmpv6_echo_reply(
                self.faucet_mac, eth_src, vid,
                dst_ip, src_ip, ipv6_pkt.hop_limit,
                icmpv6_pkt.data.id, icmpv6_pkt.data.seq, icmpv6_pkt.data.data)
            ofmsgs.extend([valve_of.packetout(in_port, icmpv6_echo_reply.data)])
        return ofmsgs

    def control_plane_handler(self, dp_id, in_port, vlan, eth_src, eth_dst, pkt):
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        if ipv6_pkt is not None:
            icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
            if icmpv6_pkt is not None:
                return self.control_plane_icmpv6_handler(
                    dp_id, in_port, vlan, eth_src, ipv6_pkt, icmpv6_pkt)
        return []
