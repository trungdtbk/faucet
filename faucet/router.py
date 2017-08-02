"""Configure routing between VLANs."""

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
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ipaddress
import collections

try:
    from conf import Conf
    from valve_util import btos
except ImportError:
    from faucet.conf import Conf
    from faucet.valve_util import btos


class Interface(Conf):

    ipv4 = None
    ipv6 = None

    defaults = {
        'ipv4': None,
        'ipv6': None,
    }

    defaults_type = {
        'ipv4': str,
        'ipv6': str,
    }

    def __init__(self, _id, conf=None):
        if conf is None:
            conf = {}
        self.update(conf)
        self._id = _id
        self.vips_by_ipv = {}
        for vip in [self.ipv4, self.ipv6]:
            if vip:
                vip = ipaddress.ip_interface(btos(vip))
                self.vips_by_ipv[vip.version] = vip

    def ip_is_vip(self, ipa):
        if (ipa.version in self.vips_by_ipv and
            self.vips_by_ipv[ipa.version].ip == ipa):
            return True
        return False

    def ip_in_vip_subnet(self, ipa):
        if (ipa.version in self.vips_by_ipv and
            ipa in self.vips_by_ipv[ipa.version].network):
            return True
        return False

    def ipvs(self):
        return list(self.vips_by_ipv.keys())

    def vip_by_ipv(self, ipv):
        return self.vips_by_ipv.get(ipv, None)

class Router(Conf):
    """Implement FAUCET configuration for a router."""

    vlans = None
    router_id = None
    default = None
    bgp_as = None
    bgp_local_address = None
    bgp_port = None
    bgp_routerid = None
    bgp_neighbor_addresses = []
    bgp_neighbour_addresses = []
    bgp_neighbor_as = None
    bgp_neighbour_as = None
    routes = None

    defaults = {
        'vlans': {},
        'router_id': None,
        'default' : False,
        'bgp_as': None,
        'bgp_local_address': None,
        'bgp_port': 9179,
        'bgp_routerid': None,
        'bgp_neighbour_addresses': [],
        'bgp_neighbor_addresses': [],
        'bgp_neighbour_as': None,
        'bgp_neighbor_as': None,
        'routes': None,
    }

    defaults_type = {
        'vlans': dict,
        'router_id': int,
        'default': bool,
        'bgp_as': int,
        'bgp_local_address': str,
        'bgp_port': int,
        'bgp_routerid': str,
        'bgp_neighbour_addresses': list,
        'bgp_neighbor_addresses': list,
        'bgp_neighbour_as': int,
        'bgp_neighbor_as': int,
        'routes': list,
    }

    def __init__(self, _id, conf=None):
        if conf is None:
            conf = {}
        self._id = _id
        self.update(conf)
        self.set_defaults()
        self._id = _id
        self.dyn_ipvs = set()
        self.dyn_routes_by_ipv = collections.defaultdict(dict)
        self.dyn_neigh_cache_by_ipv = collections.defaultdict(dict)
        self.interfaces = {}
        if self.vlans:
            for vid, int_conf in list(self.vlans.items()):
                self.interfaces[vid] = Interface(vid, int_conf)
                self.dyn_ipvs.update(self.interfaces[vid].ipvs())

        if self.bgp_as:
            assert self.bgp_port
            assert ipaddress.IPv4Address(btos(self.bgp_routerid))
            for neighbor_ip in self.bgp_neighbor_addresses:
                assert ipaddress.ip_address(btos(neighbor_ip))
            assert self.bgp_neighbor_as

        if self.routes:
            self.routes = [route['route'] for route in self.routes]
            for route in self.routes:
                ip_gw = ipaddress.ip_address(btos(route['ip_gw']))
                ip_dst = ipaddress.ip_network(btos(route['ip_dst']))
                assert ip_gw.version == ip_dst.version
                self.dyn_routes_by_ipv[ip_gw.version][ip_dst] = ip_gw

        self.faucet_mac = self._router_id_to_mac()


    def set_defaults(self):
        for key, value in list(self.defaults.items()):
            self._set_default(key, value)
        self._set_default('router_id', self._id)
        self._set_default('bgp_neighbor_as', self.bgp_neighbour_as)
        self._set_default(
            'bgp_neighbor_addresses', self.bgp_neighbour_addresses)

    def _router_id_to_mac(self):
       m1 = (self.router_id & 0xFF000000)>>24
       m2 = (self.router_id & 0x00FF0000)>>16
       m3 = (self.router_id & 0x0000FF00)>>8
       m4 = (self.router_id & 0x000000FF)>>0
       return '0e:00:{:02x}:{:02x}:{:02x}:{:02x}'.format(*[m1, m2, m3, m4])

    def ip_is_vip(self, vid, ipa):
        if vid in self.interfaces:
            intf = self.interfaces[vid]
            return intf.ip_is_vip(ipa)
        return False

    def is_faucet_vip(self, ipa):
        for intf in list(self.interfaces.values()):
            if intf.ip_is_vip(ipa):
                return True
        return False

    def ip_in_vip_subnet(self, ipa):
        for intf in list(self.interfaces.values()):
            if intf.ip_in_vip_subnet(ipa):
                return True
        return False

    def is_default(self):
        return self.default

    def ipvs(self):
        return self.dyn_ipvs

    def vip_by_ipv(self, vid, ipv):
        if vid in self.interfaces:
            intf = self.interfaces[vid]
            return intf.vip_by_ipv(ipv)
        return None

    def routes_by_ipv(self, ipv):
        return self.dyn_routes_by_ipv[ipv]

    def neigh_cache_by_ipv(self, ipv):
        return self.dyn_neigh_cache_by_ipv[ipv]

    def cached_nexthop_entry(self, ip_gw):
        cached_entry = self.nexthop_cache_entry(ip_gw)
        if cached_entry is not None and cached_entry.eth_src is not None:
            return cached_entry
        return None

    def nexthop_cache_entry(self, ip_gw):
        neigh_cache = self.neigh_cache_by_ipv(ip_gw.version)
        if ip_gw in neigh_cache:
            return neigh_cache[ip_gw]
        return None

    def faucet_vips_by_ipv(self, ipv):
        faucet_vips = []
        for intf in list(self.interfaces.values()):
            vip = intf.vip_by_ipv(ipv)
            if vip is not None:
                faucet_vips.append(vip)
        return faucet_vips

    def ip_gws(self, ipv):
        ip_gws = []
        for ip_gw in list(self.dyn_routes_by_ipv[ipv].values()):
            for vip in self.faucet_vips_by_ipv(ipv):
                if ip_gw in vip.network:
                    ip_gws.append((ip_gw, vip))
        return ip_gws

    def from_connected_to_vip(self, vid, src_ip, dst_ip):
        """Return True if src_ip in connected network and dst_ip is a VIP.

        Args:
            src_ip (ipaddress.ip_address): source IP.
            dst_ip (ipaddress.ip_address): destination IP
        Returns:
            True if local traffic for a VIP.
        """
        if self.is_faucet_vip(dst_ip) and self.ip_in_vip_subnet(src_ip):
            return True
        return False
