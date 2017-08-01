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
        self.vip_by_ipv = {}
        for vip in (self.ipv4, self.ipv6):
            if vip:
                vip = ipaddress.ip_interface(btos(self.ipv4))
                self.vip_by_ipv[vip.version] = vip

    def ip_is_vip(self, ipa):
        if ipa.version in self.vip_by_ipv and self.vip_by_ipv[ipa.version] == ipa:
            return True
        return False

    def ip_in_vip_subnet(self, ipa):
        if (ipa.version in self.vip_by_ipv and
            ipa in self.vip_by_ipv[ipa.version].network):
            return True
        return False

class Router(Conf):
    """Implement FAUCET configuration for a router."""

    vlans = None
    router_id = None
    default = None

    defaults = {
        'vlans': None,
        'router_id': None,
        'default' : False,
    }

    defaults_type = {
        'vlans': dict,
        'router_id': int,
        'default': bool,
    }

    def __init__(self, _id, conf=None):
        if conf is None:
            conf = {}
        self.update(conf)
        self._id = _id
        self._set_default('router_id', self._id)
        self.interfaces = {}
        if self.vlans:
            for vid, int_conf in list(self.vlans.items()):
                self.interfaces[vid] = Interface(vid, int_conf)
        self.faucet_mac = self._router_id_to_mac()

    def _router_id_to_mac(self):
       m1 = (self.router_id & 0xFF000000)>>24
       m1 = (self.router_id & 0x00FF0000)>>16
       m3 = (self.router_id & 0x0000FF00)>>8
       m4 = (self.router_id & 0x000000FF)>>0
       return '0e:00:{:02x}:{:02x}:{:02x}:{:02x}'.format(*[m1, m2, m3, m4])

    def ip_is_vip(self, vid, ipa):
        if vid in self.interfaces:
            intf = self.interfaces[vid]
            return intf.ip_is_vip(ipa)
        return False

    def ip_in_vip_subnet(self, vid, ipa):
        if vid in self.interfaces:
            intf = self.interfaces[vid]
            return intf.ip_in_vip_subnet(ipa)
        return False

    def is_default(self):
        return self.default
