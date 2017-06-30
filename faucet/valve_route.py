"""Valve IPv4/IPv6 routing implementation."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2017 The Contributors
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

import ipaddress

from ryu.lib.packet import arp, icmp, icmpv6, ipv4, ipv6
from ryu.ofproto import ether
from ryu.ofproto import inet

import valve_of
import valve_packet
from valve_util import btos


class AnyVlan(object):
    """Wildcard VLAN."""

    vid = valve_of.vid_present(0)


class NextHop(object):
    """Describes a directly connected (at layer 2) nexthop."""

    def __init__(self, vlan, eth_src, now):
        self.vlan = vlan
        self.eth_src = eth_src
        self.cache_time = now
        self.last_retry_time = None
        self.resolve_retries = 0


class ValveRouteManager(object):
    """Base class to implement RIB/FIB."""

    IPV = None
    ETH_TYPE = None
    METADATA_FULL_MASK = (1<<64) - 1

    def __init__(self, dp, logger, faucet_mac, arp_neighbor_timeout,
                 max_hosts_per_resolve_cycle, max_host_fib_retry_count,
                 max_resolve_backoff_time, proactive_learn,
                 fib_table, eth_src_table, eth_dst_table, flood_table,
                 route_priority,
                 valve_in_match, valve_flowdel, valve_flowmod,
                 valve_flowcontroller, use_group_table, routers):
        self.dp = dp
        self.logger = logger
        self.faucet_mac = faucet_mac
        self.arp_neighbor_timeout = arp_neighbor_timeout
        self.max_hosts_per_resolve_cycle = max_hosts_per_resolve_cycle
        self.max_host_fib_retry_count = max_host_fib_retry_count
        self.max_resolve_backoff_time = max_resolve_backoff_time
        self.proactive_learn = proactive_learn
        self.fib_table = fib_table
        self.eth_src_table = eth_src_table
        self.eth_dst_table = eth_dst_table
        self.flood_table = flood_table
        self.route_priority = route_priority
        self.valve_in_match = valve_in_match
        self.valve_flowdel = valve_flowdel
        self.valve_flowmod = valve_flowmod
        self.valve_flowcontroller = valve_flowcontroller
        self.use_group_table = use_group_table
        # TODO: if any router config present, we globally route between
        # all VLANs - we want however to be able to restrict routing
        # as required.
        self.routers = routers
        self.ip_gw_to_group_id = {}

        self.neighbor_cache = {}

    def _vlan_vid(self, vlan, port):
        vid = None
        if vlan.port_is_tagged(port):
            vid = vlan.vid
        return vid

    def _router_routes(self, router):
        return router.routes_by_ipv(self.IPV)

    def _router_nexthop_cache(self, router):
        return router.neigh_cache_by_ipv(self.IPV)

    def _nexthop_cache_entry(self, ip_gw):
        if ip_gw in self.neighbor_cache:
            return self.neighbor_cache[ip_gw]
        return None

    def _neighbor_resolver_pkt(self, vid, eth_src, faucet_vip, ip_gw):
        pass

    def resolve_gw_on_vlan(self, vlan, eth_src, faucet_vip, ip_gw):
        return vlan.flood_pkt(
            self._neighbor_resolver_pkt, eth_src, faucet_vip, ip_gw)

    def _nexthop_actions(self, eth_src, eth_dst, vlan):
        ofmsgs = []
        if self.routers:
            ofmsgs.append(valve_of.set_vlan_vid(vlan.vid))
        ofmsgs.extend([
            valve_of.set_eth_src(eth_src),
            valve_of.set_eth_dst(eth_dst),
            valve_of.dec_ip_ttl()])
        return ofmsgs

    def _route_match(self, vlan, ip_dst, metadata=None, metadata_mask=None):
        return self.valve_in_match(
            self.fib_table, vlan=vlan, eth_type=self.ETH_TYPE,
            nw_dst=ip_dst, metadata=metadata, metadata_mask=metadata_mask)

    def _route_priority(self, ip_dst):
        prefixlen = ipaddress.ip_network(ip_dst).prefixlen
        return self.route_priority + prefixlen

    def _add_resolved_route(self, router, vlan, ip_gw, ip_dst, eth_dst, is_updated):
        ofmsgs = []
        if is_updated:
            self.logger.info(
                'Updating next hop for route %s via %s (%s)',
                ip_dst, ip_gw, eth_dst)
            ofmsgs.extend(self._del_route_flows(router, ip_dst))
        else:
            self.logger.info(
                'Adding new route %s via %s (%s)',
                ip_dst, ip_gw, eth_dst)
        if self.use_group_table:
            inst = [valve_of.apply_actions([valve_of.group_act(
                group_id=self.ip_gw_to_group_id[(ip_gw, router.vmac)])])]
        else:
            inst = [
                valve_of.apply_actions(
                    self._nexthop_actions(router.vmac, eth_dst, vlan)),
                valve_of.goto_table(self.eth_dst_table)]
        in_match = self._route_match(AnyVlan(), ip_dst, router.rid)
        ofmsgs.append(self.valve_flowmod(
            self.fib_table,
            in_match,
            priority=self._route_priority(ip_dst),
            inst=inst))
        return ofmsgs

    def _group_id_from_ip_gw(self, resolved_ip_gw, eth_src):
        gid = hash(str((resolved_ip_gw, eth_src))) + valve_of.ROUTE_GROUP_OFFSET
        gid = gid &((1<<32) -1)
        return  gid

    def _update_nexthop_cache(self, vlan, eth_src, ip_gw):
        now = time.time()
        nexthop = NextHop(vlan, eth_src, now)
        self.neighbor_cache[ip_gw] = nexthop

    def _nexthop_group_buckets(self, vlan, port, eth_src, eth_dst):
        actions = self._nexthop_actions(eth_src, eth_dst, vlan)
        if not vlan.port_is_tagged(port):
            actions.append(valve_of.pop_vlan())
        actions.append(valve_of.output_port(port.number))
        buckets = [valve_of.bucket(actions=actions)]
        return buckets

    def _update_nexthop_group(self, is_updated, resolved_ip_gw,
                              vlan, port, eth_src, eth_dst):
        group_mod_method = None
        group_id = None
        buckets = self._nexthop_group_buckets(vlan, port, eth_src, eth_dst)
        ofmsgs = []
        if is_updated:
            group_mod_method = valve_of.groupmod
            group_id = self.ip_gw_to_group_id[(resolved_ip_gw, eth_src)]
        else:
            group_mod_method = valve_of.groupadd
            group_id = self._group_id_from_ip_gw(resolved_ip_gw, eth_src)
            self.ip_gw_to_group_id[(resolved_ip_gw, eth_src)] = group_id
            ofmsgs.append(valve_of.groupdel(group_id=group_id))
        ofmsgs.append(
            group_mod_method(group_id=group_id, buckets=buckets))
        return ofmsgs

    def _update_nexthop(self, vlan, port, eth_src, resolved_ip_gw):
        is_updated = False
        _cached_nexthop = self._cached_nexthop(resolved_ip_gw)
        ofmsgs = []

        if _cached_nexthop is not None and _cached_nexthop.eth_src != eth_src:
            is_updated = True

        for router in list(self.routers.values()):
            routes = self._router_routes(router)
            if self.use_group_table:
                ofmsgs.extend(
                    self._update_nexthop_group(
                        is_updated, resolved_ip_gw,
                        vlan, port, router.vmac, eth_src))
            for ip_dst, ip_gw in list(routes.items()):
                if ip_gw == resolved_ip_gw:
                    ofmsgs.extend(self._add_resolved_route(
                        router, vlan, ip_gw, ip_dst, eth_src, is_updated))

        self._update_nexthop_cache(vlan, eth_src, resolved_ip_gw)
        return ofmsgs

    def _add_unresolved_nexthops(self, ip_gws):
        """Populates any missing nexthop cache entries.

        Args:
           vlan (vlan): VLAN containing this RIB/FIB.
           ip_gws (list): tuple, IP gateway and controller IP in same subnet.
        """
        for ip_gw, _ in ip_gws:
            if self._cached_nexthop(ip_gw) is None:
                self._update_nexthop_cache(None, None, ip_gw)

    def _retry_backoff(self, now, resolve_retries, last_retry_time):
        backoff_seconds = min(
            2**resolve_retries, self.max_resolve_backoff_time)
        if now - last_retry_time > backoff_seconds:
            return True
        return False

    def _unresolved_nexthops(self, ip_gws, now):
        """Return unresolved or expired IP gateways, never tried/oldest first.

        Args:
           router (Router): Router containing this RIB/FIB.
           ip_gws (list): tuple, IP gateway and controller IP in same subnet.
           now (float): seconds since epoch.
        Returns:
           list: tuple, gateway, controller IP in same subnet, last retry time.
        """
        ip_gws_never_tried = []
        ip_gws_with_retry_time = []
        for ip_gw, faucet_vip in ip_gws:
            if self._nexthop_fresh(ip_gw, now):
                continue
            nexthop_cache_entry = self._nexthop_cache_entry(ip_gw)
            last_retry_time = nexthop_cache_entry.last_retry_time
            ip_gw_with_retry_time = (ip_gw, faucet_vip, last_retry_time)
            if last_retry_time is None:
                ip_gws_never_tried.append(ip_gw_with_retry_time)
            else:
                if self._retry_backoff(
                        now, nexthop_cache_entry.resolve_retries, last_retry_time):
                    ip_gws_with_retry_time.append(ip_gw_with_retry_time)
        ip_gws_with_retry_time_sorted = list(
            sorted(ip_gws_with_retry_time, key=lambda x: x[-1]))
        return ip_gws_never_tried + ip_gws_with_retry_time_sorted

    def _is_host_fib_route(self, router, host_ip):
        """Return True if IP destination is a host FIB route.

        Args:
            vlan (vlan): VLAN containing this RIB/FIB.
            ip_gw (ipaddress.ip_address): potential host FIB route.
        Returns:
            True if a host FIB route (and not used as a gateway).
        """
        routes = self._router_routes(router)
        in_fib = False
        for ip_dst, ip_gw in list(routes.items()):
            if ip_gw == host_ip:
                in_fib = True
                if ip_dst.prefixlen < ip_dst.max_prefixlen:
                    return False
        return in_fib

    def advertise(self, router):
        return []

    def resolve_gateways(self, vlan, now):
        """Re/resolve all gateways.

        Args:
            vlan (vlan): VLAN containing this RIB/FIB.
            now (float): seconds since epoch.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        for router in list(self.routers.values()):
            ip_gws = router.ip_gws(vlan.vid, self.IPV)
            self._add_unresolved_nexthops(ip_gws)
            all_unresolved_nexthops = self._unresolved_nexthops(ip_gws, now)
            cycle_unresolved_nexthops = all_unresolved_nexthops[
                :self.max_hosts_per_resolve_cycle]
            deferred_unresolved_nexthops = (len(all_unresolved_nexthops) -
                                            len(cycle_unresolved_nexthops))
            if deferred_unresolved_nexthops:
                self.logger.info('deferring resolution of %u nexthops',
                                 deferred_unresolved_nexthops)
            for ip_gw, faucet_vip, last_retry_time in cycle_unresolved_nexthops:
                nexthop_cache_entry = self._nexthop_cache_entry(ip_gw)
                if (self._is_host_fib_route(router, ip_gw) and
                        nexthop_cache_entry.resolve_retries >= self.max_host_fib_retry_count):
                    self.logger.info(
                        'expiring dead host FIB route %s (age %us)',
                        ip_gw,
                        now - nexthop_cache_entry.cache_time)
                    ofmsgs.extend(self._del_host_fib_route(router, ip_gw))
                else:
                    nexthop_cache_entry.last_retry_time = now
                    nexthop_cache_entry.resolve_retries += 1
                    resolve_flows = self.resolve_gw_on_vlan(
                        vlan, router.vmac, faucet_vip, ip_gw)
                    if last_retry_time is None:
                        self.logger.info(
                            'resolving %s (%u flows)', ip_gw, len(resolve_flows))
                    else:
                        self.logger.info(
                            'resolving %s retry %u (last attempt was %us ago; %u flows)',
                            ip_gw,
                            nexthop_cache_entry.resolve_retries,
                            now - last_retry_time,
                            len(resolve_flows))
                    ofmsgs.extend(resolve_flows)
        return ofmsgs

    def _cached_nexthop(self, ip_gw):
        nexthop_cache_entry = self.neighbor_cache.get(ip_gw)
        if (nexthop_cache_entry is not None and
                nexthop_cache_entry.eth_src is not None):
            return nexthop_cache_entry
        return None

    def _host_ip_to_host_int(self, host_ip):
        return ipaddress.ip_interface(ipaddress.ip_network(host_ip))

    def _host_from_faucet_vip(self, faucet_vip):
        return self._host_ip_to_host_int(faucet_vip.ip)

    def _vlan_nexthop_cache_limit(self, vlan):
        pass

    def _proactive_resolve_neighbor(self, vlans, dst_ip):
        ofmsgs = []
        if not self.proactive_learn:
            return []
        """
        for vlan in vlans:
            limit = self._vlan_nexthop_cache_limit(vlan)
            if vlan.ip_in_vip_subnet(dst_ip) and not vlan.is_faucet_vip(dst_ip):
                if self._is_host_fib_route(vlan, dst_ip):
                    self.logger.info(
                        'not proactively learning %s, already trying', dst_ip)
                    break
                if (limit is not None and
                        len(self._vlan_nexthop_cache(vlan)) >= limit):
                    self.logger.info(
                        'not proactively learning %s, at limit %u', dst_ip, limit)
                    break
                for faucet_vip in vlan.faucet_vips_by_ipv(self.IPV):
                    if dst_ip in faucet_vip.network:
                        priority = self._route_priority(dst_ip)
                        dst_int = self._host_ip_to_host_int(dst_ip)
                        in_match = self._route_match(vlan, dst_int)
                        ofmsgs.append(self.valve_flowmod(
                            self.fib_table,
                            in_match,
                            priority=priority,
                            hard_timeout=self.arp_neighbor_timeout))
                        ofmsgs.extend(
                            self._add_host_fib_route(vlan, dst_ip))
                        resolve_flows = self.resolve_gw_on_vlan(
                            vlan, faucet_vip, dst_ip)
                        ofmsgs.extend(resolve_flows)
                        self.logger.info(
                            'proactively resolving %s (%u flows)',
                            dst_ip, len(resolve_flows))
                        return ofmsgs
        """
        return ofmsgs

    def add_route(self, router, ip_gw, ip_dst):
        """Add a route to the RIB.

        Args:
            vlan (vlan): VLAN containing this RIB.
            ip_gw (ipaddress.ip_address): IP address of nexthop.
            ip_dst (ipaddress.ip_network): destination IP network.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        if router.is_router_vip(ip_dst):
            return ofmsgs
        routes = self._router_routes(router)
        routes[ip_dst] = ip_gw
        _cached_nexthop = self._cached_nexthop(ip_gw)
        if _cached_nexthop is not None:
            ofmsgs.extend(self._add_resolved_route(
                router,
                vlan=_cached_nexthop.vlan,
                ip_gw=ip_gw,
                ip_dst=ip_dst,
                eth_dst=_cached_nexthop.eth_src,
                is_updated=False))
        return ofmsgs

    def _add_host_fib_route(self, router, host_ip):
        """Add a host FIB route.

        Args:
            vlan (vlan): VLAN containing this RIB.
            host_ip (ipaddress.ip_address): IP address of host.
        Returns:
            list: OpenFlow messages.
        """
        host_route = ipaddress.ip_network(host_ip.exploded)
        return self.add_route(router, host_ip, host_route)

    def _del_host_fib_route(self, router, host_ip):
        """Delete a host FIB route.

        Args:
            vlan (vlan): VLAN containing this RIB.
            host_ip (ipaddress.ip_address): IP address of host.
        Returns:
            list: OpenFlow messages.
        """
        host_route = ipaddress.ip_network(host_ip.exploded)
        return self.del_route(router, host_route)

    def _ip_pkt(self, pkt):
        """Return an IP packet from an Ethernet packet.

        Args:
            pkt: ryu.lib.packet from host.
        Returns:
            IP ryu.lib.packet parsed from pkt.
        """
        pass

    def _nexthop_fresh(self, ip_gw, now):
        nexthop_cache_entry = self._cached_nexthop(ip_gw)
        if nexthop_cache_entry is not None:
            if nexthop_cache_entry.eth_src is not None:
                cache_time = nexthop_cache_entry.cache_time
                cache_age = now - cache_time
                if cache_age < self.arp_neighbor_timeout:
                    return True
        return False

    def add_host_fib_route_from_pkt(self, pkt_meta):
        """Add a host FIB route given packet from host.

        Args:
            pkt_meta (PacketMeta): received packet.
        Returns:
            list: OpenFlow messages.
        """
        ip_pkt = self._ip_pkt(pkt_meta.pkt)
        ofmsgs = []
        if not ip_pkt:
            return ofmsgs
        src_ip = ipaddress.ip_address(btos(ip_pkt.src))
        if not src_ip:
            return ofmsgs
        for router in list(self.routers.values()):
            router_vip = router.vip_by_intf(pkt_meta.vlan.vid, self.IPV)
            if src_ip and router_vip and src_ip in router_vip.network:
                now = time.time()
                nexthop_fresh = self._nexthop_fresh(src_ip, now)
                self._update_nexthop_cache(pkt_meta.vlan, pkt_meta.eth_src, src_ip)
                if not nexthop_fresh:
                    if self.use_group_table:
                        ofmsgs.extend(
                            self._update_nexthop_group(
                                False,
                                src_ip,
                                pkt_meta.vlan,
                                pkt_meta.port,
                                router.vmac,
                                pkt_meta.eth_src))
                    ofmsgs.extend(
                        self._add_host_fib_route(router, src_ip))
        return ofmsgs

    def _del_route_flows(self, router, ip_dst):
        ofmsgs = []
        vlan = AnyVlan()
        if ip_dst.prefixlen == 0:
            route_match = self.valve_in_match(
                self.fib_table, vlan=vlan,
                eth_type=self.ETH_TYPE,
                metadata=router.rid)
        else:
            route_match = self.valve_in_match(
                self.fib_table, vlan=vlan,
                eth_type=self.ETH_TYPE, nw_dst=ip_dst,
                metadata=router.rid)
        ofmsgs.extend(self.valve_flowdel(
            self.fib_table, route_match,
            priority=self._route_priority(ip_dst),
            strict=True))
        return ofmsgs

    def del_route(self, router, ip_dst):
        """Delete a route from the RIB.

        Only one route with this exact destination is supported.

        Args:
            router (router): Router containing this RIB.
            ip_dst (ipaddress.ip_network): destination IP network.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        if router.is_router_vip(ip_dst):
            return ofmsgs
        routes = self._router_routes(router)
        if ip_dst in routes:
            del routes[ip_dst]
            ofmsgs.extend(self._del_route_flows(router, ip_dst))
            # TODO: need to delete nexthop group if groups are in use.
        return ofmsgs

    def control_plane_handler(self, pkt_meta):
        pass

    def _router_by_connected_ip(self, src_ip, dst_ip):
        for router in list(self.routers.values()):
            if router.from_connected_to_vip(src_ip, dst_ip):
                return router
        return None

    def _router_by_vip(self, vip):
        for router in list(self.routers.values()):
            if router.is_router_vip(vip):
                return router
        return None

    def _add_faucet_vip(self, vlan, vip, vmac, routerid):
        return []

    def add_router_vips(self, vlan):
        ofmsgs = []
        assert self.dp.stack is None, 'stacking + routing not yet supported'
        for rid, router in list(self.routers.items()):
            vip = router.vip_by_intf(vlan.vid, self.IPV)
            if vip:
                ofmsgs.extend(self._add_faucet_vip(vlan, vip, router.vmac, rid))
        return ofmsgs

class ValveIPv4RouteManager(ValveRouteManager):
    """Implement IPv4 RIB/FIB."""

    IPV = 4
    ETH_TYPE = ether.ETH_TYPE_IP

    def _vlan_nexthop_cache_limit(self, vlan):
        return vlan.proactive_arp_limit

    def _neighbor_resolver_pkt(self, vid, eth_src, faucet_vip, ip_gw):
        return valve_packet.arp_request(
            vid, eth_src, faucet_vip.ip, ip_gw)

    def _ip_pkt(self, pkt):
        return pkt.get_protocol(ipv4.ipv4)

    def _add_faucet_vip(self, vlan, faucet_vip, vmac, metadata=None):
        ofmsgs = []
        max_prefixlen = faucet_vip.ip.max_prefixlen
        faucet_vip_host = self._host_from_faucet_vip(faucet_vip)
        priority = self.route_priority + max_prefixlen
        learn_connected_priority = self.route_priority + faucet_vip.network.prefixlen
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=ether.ETH_TYPE_ARP,
                nw_dst=faucet_vip_host,
                vlan=vlan),
            priority=priority,
            inst=[valve_of.apply_actions([valve_of.output_controller()])]))
        # Initialize IPv4 FIB
        fib_inst = []
        if metadata:
            fib_inst.append(valve_of.write_metadata(metadata))
        fib_inst.append(valve_of.goto_table(self.fib_table))
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self.ETH_TYPE,
                eth_dst=vmac,
                vlan=vlan),
            priority=self.route_priority,
            inst=fib_inst))
        ofmsgs.append(self.valve_flowcontroller(
            self.fib_table,
            self.valve_in_match(
                self.fib_table,
                vlan=vlan,
                eth_type=self.ETH_TYPE,
                nw_proto=inet.IPPROTO_ICMP,
                nw_src=faucet_vip,
                nw_dst=faucet_vip_host),
            priority=priority))
        if self.proactive_learn:
            ofmsgs.append(self.valve_flowcontroller(
                self.fib_table,
                self.valve_in_match(
                    self.fib_table,
                    vlan=vlan,
                    eth_type=self.ETH_TYPE,
                    nw_dst=faucet_vip),
                priority=learn_connected_priority))
        return ofmsgs

    def _control_plane_arp_handler(self, pkt_meta, arp_pkt):
        src_ip = ipaddress.IPv4Address(btos(arp_pkt.src_ip))
        dst_ip = ipaddress.IPv4Address(btos(arp_pkt.dst_ip))
        vlan = pkt_meta.vlan
        opcode = arp_pkt.opcode
        ofmsgs = []
        router = self._router_by_vip(dst_ip)
        if router:
            port = pkt_meta.port
            eth_src = pkt_meta.eth_src
            if opcode == arp.ARP_REQUEST:
                ofmsgs.extend(
                    self._add_host_fib_route(router, src_ip))
                ofmsgs.extend(self._update_nexthop(vlan, port, eth_src, src_ip))
                vid = self._vlan_vid(vlan, port)
                arp_reply = valve_packet.arp_reply(
                    vid, router.vmac, eth_src, dst_ip, src_ip)
                ofmsgs.append(
                    valve_of.packetout(port.number, arp_reply.data))
                self.logger.info(
                    'Responded to ARP request for %s from %s (%s)',
                    dst_ip, src_ip, eth_src)
            elif (opcode == arp.ARP_REPLY and
                  pkt_meta.eth_dst == router.vmac):
                ofmsgs.extend(
                    self._update_nexthop(vlan, port, eth_src, src_ip))
                self.logger.info(
                    'ARP response %s (%s)', src_ip, eth_src)
        return ofmsgs

    def _control_plane_icmp_handler(self, pkt_meta, ipv4_pkt, icmp_pkt):
        src_ip = ipaddress.IPv4Address(btos(ipv4_pkt.src))
        dst_ip = ipaddress.IPv4Address(btos(ipv4_pkt.dst))
        vlan = pkt_meta.vlan
        icmpv4_type = icmp_pkt.type
        ofmsgs = []
        router = self._router_by_vip(dst_ip)
        if not router:
            return ofmsgs
        if (icmpv4_type == icmp.ICMP_ECHO_REQUEST and
                pkt_meta.eth_dst == router.vmac):
            port = pkt_meta.port
            vid = self._vlan_vid(vlan, port)
            echo_reply = valve_packet.echo_reply(
                vid, router.vmac, pkt_meta.eth_src,
                dst_ip, src_ip, icmp_pkt.data)
            ofmsgs.append(
                valve_of.packetout(port.number, echo_reply.data))
        return ofmsgs

    def control_plane_handler(self, pkt_meta):
        vlan = pkt_meta.vlan
        arp_pkt = pkt_meta.pkt.get_protocol(arp.arp)
        if arp_pkt is not None:
            return self._control_plane_arp_handler(pkt_meta, arp_pkt)
        ipv4_pkt = pkt_meta.pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt is not None:
            icmp_pkt = pkt_meta.pkt.get_protocol(icmp.icmp)
            if icmp_pkt is not None:
                icmp_replies = self._control_plane_icmp_handler(
                    pkt_meta, ipv4_pkt, icmp_pkt)
                if icmp_replies:
                    return icmp_replies
            dst_ip = ipaddress.IPv4Address(btos(ipv4_pkt.dst))
            vlan = pkt_meta.vlan
            return self._proactive_resolve_neighbor([vlan], dst_ip)
        return []


class ValveIPv6RouteManager(ValveRouteManager):
    """Implement IPv6 FIB."""

    IPV = 6
    ETH_TYPE = ether.ETH_TYPE_IPV6

    def _vlan_nexthop_cache_limit(self, vlan):
        return vlan.proactive_nd_limit

    def _neighbor_resolver_pkt(self, vid, eth_src, faucet_vip, ip_gw):
        return valve_packet.nd_request(
            vid, eth_src, faucet_vip.ip, ip_gw)

    def _ip_pkt(self, pkt):
        return pkt.get_protocol(ipv6.ipv6)

    def _add_faucet_vip(self, vlan, faucet_vip, vmac, metadata=None):
        ofmsgs = []
        max_prefixlen = faucet_vip.ip.max_prefixlen
        faucet_vip_host = self._host_from_faucet_vip(faucet_vip)
        priority = self.route_priority + max_prefixlen
        learn_connected_priority = self.route_priority + faucet_vip.network.prefixlen
        faucet_vip_host_nd_mcast = valve_packet.ipv6_link_eth_mcast(
            valve_packet.ipv6_solicited_node_from_ucast(faucet_vip.ip))
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self.ETH_TYPE,
                vlan=vlan,
                nw_proto=inet.IPPROTO_ICMPV6,
                eth_dst=faucet_vip_host_nd_mcast,
                icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT),
            priority=priority,
            inst=[
                valve_of.apply_actions([valve_of.output_controller()]),
                valve_of.goto_table(self.flood_table)]))
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self.ETH_TYPE,
                eth_dst=vmac,
                vlan=vlan,
                nw_proto=inet.IPPROTO_ICMPV6,
                icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT),
            priority=priority,
            inst=[valve_of.apply_actions([valve_of.output_controller()])]))
        if faucet_vip.ip in valve_packet.IPV6_LINK_LOCAL:
            ofmsgs.append(self.valve_flowmod(
                self.eth_src_table,
                self.valve_in_match(
                    self.eth_src_table,
                    eth_type=self.ETH_TYPE,
                    vlan=vlan,
                    nw_proto=inet.IPPROTO_ICMPV6,
                    eth_dst=valve_packet.IPV6_ALL_ROUTERS_MCAST,
                    icmpv6_type=icmpv6.ND_ROUTER_SOLICIT),
                priority=priority,
                inst=[
                    valve_of.apply_actions([valve_of.output_controller()]),
                    valve_of.goto_table(self.flood_table)]))
        # Initialize IPv6 FIB
        fib_inst = []
        if metadata:
            fib_inst.append(valve_of.write_metadata(metadata))
        fib_inst.append(valve_of.goto_table(self.fib_table))
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self.ETH_TYPE,
                eth_dst=vmac,
                vlan=vlan),
            priority=self.route_priority,
            inst=fib_inst))
        ofmsgs.append(self.valve_flowcontroller(
            self.fib_table,
            self.valve_in_match(
                self.fib_table,
                eth_type=self.ETH_TYPE,
                vlan=vlan,
                nw_proto=inet.IPPROTO_ICMPV6,
                nw_dst=faucet_vip_host,
                icmpv6_type=icmpv6.ICMPV6_ECHO_REQUEST),
            priority=priority,
            max_len=128))
        if self.proactive_learn:
            ofmsgs.append(self.valve_flowcontroller(
                self.fib_table,
                self.valve_in_match(
                    self.fib_table,
                    vlan=vlan,
                    eth_type=self.ETH_TYPE,
                    nw_dst=faucet_vip),
                priority=learn_connected_priority))
        return ofmsgs

    def _control_plane_icmpv6_handler(self, pkt_meta, ipv6_pkt, icmpv6_pkt):
        vlan = pkt_meta.vlan
        src_ip = ipaddress.IPv6Address(btos(ipv6_pkt.src))
        dst_ip = ipaddress.IPv6Address(btos(ipv6_pkt.dst))
        icmpv6_type = icmpv6_pkt.type_
        ofmsgs = []
        port = pkt_meta.port
        vid = self._vlan_vid(vlan, port)
        eth_src = pkt_meta.eth_src
        if icmpv6_type == icmpv6.ND_NEIGHBOR_SOLICIT:
            solicited_ip = btos(icmpv6_pkt.data.dst)
            router = self._router_by_vip(ipaddress.ip_address(solicited_ip))
            if router:
                ofmsgs.extend(
                    self._add_host_fib_route(router, src_ip))
                ofmsgs.extend(self._update_nexthop(vlan, port, eth_src, src_ip))
                nd_reply = valve_packet.nd_advert(
                    vid, router.vmac, eth_src,
                    solicited_ip, src_ip, ipv6_pkt.hop_limit)
                ofmsgs.append(
                    valve_of.packetout(port.number, nd_reply.data))
                self.logger.info(
                    'Responded to ND solicit for %s to %s (%s)',
                    solicited_ip, src_ip, eth_src)
        elif icmpv6_type == icmpv6.ND_NEIGHBOR_ADVERT:
            ofmsgs.extend(self._update_nexthop(vlan, port, eth_src, src_ip))
            self.logger.info(
                'ND advert %s (%s)', src_ip, eth_src)
        elif icmpv6_type == icmpv6.ND_ROUTER_SOLICIT:
            for router in list(self.routers.values()):
                if not router.ip_in_vip_subnet(src_ip):
                    continue
                link_local_vips, other_vips = self._link_and_other_vips(router)
                for vip in link_local_vips:
                    if src_ip in vip.network:
                        ra_advert = valve_packet.router_advert(
                            vid, router.vmac, eth_src,
                            vip.ip, src_ip, other_vips)
                        ofmsgs.append(
                            valve_of.packetout(port.number, ra_advert.data))
                        self.logger.info(
                            'Responded to RS solicit from %s (%s) to VIP %s',
                            src_ip, eth_src, vip)
                        break
        if icmpv6_type == icmpv6.ICMPV6_ECHO_REQUEST:
            router = self._router_by_vip(dst_ip)
            if router and pkt_meta.eth_dst == router.vmac:
                icmpv6_echo_reply = valve_packet.icmpv6_echo_reply(
                    vid, router.vmac, eth_src,
                    dst_ip, src_ip, ipv6_pkt.hop_limit,
                    icmpv6_pkt.data.id, icmpv6_pkt.data.seq,
                    icmpv6_pkt.data.data)
                ofmsgs.append(
                    valve_of.packetout(port.number, icmpv6_echo_reply.data))
        return ofmsgs

    def control_plane_handler(self, pkt_meta):
        pkt = pkt_meta.pkt
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        if ipv6_pkt is not None:
            icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
            if icmpv6_pkt is not None:
                icmp_replies = self._control_plane_icmpv6_handler(
                    pkt_meta, ipv6_pkt, icmpv6_pkt)
                if icmp_replies:
                    return icmp_replies
            dst_ip = ipaddress.IPv6Address(btos(ipv6_pkt.dst))
            return self._proactive_resolve_neighbor([pkt_meta.vlan], dst_ip)
        return []

    def _link_and_other_vips(self, router):
        link_local_vips = []
        other_vips = []
        for faucet_vip in router.vips_by_ipv(self.IPV):
            if faucet_vip.ip in valve_packet.IPV6_LINK_LOCAL:
                link_local_vips.append(faucet_vip)
            else:
                other_vips.append(faucet_vip)
        return link_local_vips, other_vips

    def advertise(self, vlan):
        ofmsgs = []
        for router in list(self.routers.values()):
            if vlan.vid not in router.interfaces:
                continue
            link_local_vips, other_vips = self._link_and_other_vips(router)
            for link_local_vip in link_local_vips:
                # https://tools.ietf.org/html/rfc4861#section-6.1.2
                ofmsgs.extend(vlan.flood_pkt(
                    valve_packet.router_advert, router.vmac,
                    valve_packet.IPV6_ALL_NODES_MCAST,
                    link_local_vip.ip, valve_packet.IPV6_ALL_NODES,
                    other_vips))
        return ofmsgs
