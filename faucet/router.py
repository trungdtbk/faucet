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

import collections
import ipaddress

from conf import Conf
from valve_util import btos

class Interface(Conf):

    faucet_vips = []

    defaults = {
        'faucet_vips': []
    }

    def __init__(self, id_, conf):
        self._id = id_
        self.vid = self._id
        self.update(conf)
        self.dyn_ips = {}
        for ip in self.faucet_vips:
            ip = ipaddress.ip_interface(btos(ip))
            self.dyn_ips[ip.version] = ip

    def is_intf_ip(self, ipa):
        vip = self.dyn_ips.get(ipa.version)
        if vip and vip.ip == ipa:
            return True
        return False

    def is_intf_subnet(self, ipa):
        vip = self.dyn_ips.get(ipa.version)
        if vip and ipa in vip.network:
            return True
        return False

    def vip_by_ipv(self, ipv):
        return self.dyn_ips.get(ipv)

    def vips(self):
        return list(self.dyn_ips.values())

class Router(Conf):
    """Implement FAUCET configuration for a router."""

    bgp_as = None
    bgp_local_address = None
    bgp_port = None
    bgp_routerid = None
    bgp_neighbor_addresses = []
    bgp_neighbour_addresses = []
    bgp_neighbor_as = None
    bgp_neighbour_as = None
    routes = None
    interfaces = None
    rid = None

    defaults = {
        'bgp_as': 0,
        'bgp_local_address': None,
        'bgp_port': 9179,
        'bgp_routerid': '',
        'bgp_neighbour_addresses': [],
        'bgp_neighbor_addresses': [],
        'bgp_neighbour_as': 0,
        'bgp_neighbor_as': None,
        'routes': None,
        'interfaces': None,
        'rid': None
    }

    def __init__(self, id_, conf=None, dp_id=None):
        if conf is None:
            conf = {}
        self._id = id_
        self.dp_id = dp_id
        self.update(conf)
        self._set_default('rid', self._id)
        self.dyn_vips_by_ipv = collections.defaultdict(list)
        self.dyn_routes_by_ipv = collections.defaultdict(dict)
        self.dyn_ipvs = []
        self.dyn_interfaces = {}

        if self.routes:
            self.routes = [route['route'] for route in self.routes]
            for route in self.routes:
                ip_gw = ipaddress.ip_address(btos(route['ip_gw']))
                ip_dst = ipaddress.ip_network(btos(route['ip_dst']))
                assert ip_gw.version == ip_dst.version
                self.dyn_routes_by_ipv[ip_gw.version][ip_dst] = ip_gw
        if self.interfaces:
            for id_, conf in list(self.interfaces.items()):
                _, id_ = id_.split('-')
                id_ = int(id_)
                if not conf:
                    conf = {}
                intf = Interface(id_, conf)
                self.dyn_interfaces[id_] = intf
                for ip in intf.vips():
                    self.dyn_vips_by_ipv[ip.version].append(ip)
            self.dyn_ipvs = list(self.dyn_vips_by_ipv.keys())
        self.interfaces = self.dyn_interfaces

        self.vmac = self._id_to_mac().lower()

    def _id_to_mac(self):
        m1 = (self.rid & 0xFF000000)>>24
        m2 = (self.rid & 0x00FF0000)>>16
        m3 = (self.rid & 0x0000FF00)>>8
        m4 = (self.rid & 0x000000FF)>>0
        return '0E:00:{:02X}:{:02X}:{:02X}:{:02X}'.format(*[m1, m2, m3, m4])

    def ipvs(self):
        return self.dyn_ipvs

    def vips_by_ipv(self, ipv):
        return self.dyn_vips_by_ipv[ipv]

    def vips(self):
        vips = []
        for ipv in self.dyn_ipvs:
            vips.extend(self.vips_by_ipv(ipv))
        return vips

    def vip_by_intf(self, intf_id, ipv):
        intf = self.dyn_interfaces.get(intf_id)
        if intf:
            return intf.vip_by_ipv(ipv)
        return None

    def is_router_vip(self, ipa):
        """Return True if IP is a VIP on this Router."""
        for ip in self.dyn_vips_by_ipv[ipa.version]:
            if ipa == ip.ip:
                return True
        return False

    def ip_in_vip_subnet(self, ipa):
        """Return True if IP in same IP network as a VIP on this VLAN."""
        for vip in self.vips_by_ipv(ipa.version):
            if ipa in vip.network:
                return True
        return False

    def from_connected_to_vip(self, src_ip, dst_ip):
        """Return True if src_ip in connected network and dst_ip is a VIP.

        Args:
            src_ip (ipaddress.ip_address): source IP.
            dst_ip (ipaddress.ip_address): destination IP
        Returns:
            True if local traffic for a VIP.
        """
        for vip in self.vips_by_ipv(dst_ip.version):
            if vip and vip.ip == dst_ip and src_ip in vip.network:
                return True
        return False

    def routes_by_ipv(self, ipv):
        """Return route table for specified IP version on this VLAN."""
        return self.dyn_routes_by_ipv[ipv]

    def ip_gws(self, vid, ipv):
        ip_gws = []
        intf = self.dyn_interfaces.get(vid)
        if not intf:
            return []
        vip = intf.vip_by_ipv(ipv)
        routes = self.routes_by_ipv(ipv)
        for ip_gw in set(routes.values()):
            if ip_gw in vip.network:
                ip_gws.append((ip_gw, vip))
        return ip_gws
