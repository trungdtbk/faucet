"""VLAN configuration."""

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

try:
    from conf import Conf
    from valve_util import btos
    import valve_of
except ImportError:
    from faucet.conf import Conf
    from faucet.valve_util import btos
    from faucet import valve_of


FAUCET_MAC = '0e:00:00:00:00:01'


class VLAN(Conf):
    """Implement FAUCET configuration for a VLAN."""

    tagged = None
    untagged = None
    vid = None
    faucet_vips = None
    faucet_mac = None
    max_hosts = None
    unicast_flood = None
    acl_in = None
    proactive_arp_limit = None
    proactive_nd_limit = None
    # Define dynamic variables with prefix dyn_ to distinguish from variables set
    # configuration
    dyn_host_cache = None

    defaults = {
        'name': None,
        'description': None,
        'acl_in': None,
        'faucet_vips': None,
        'faucet_mac': FAUCET_MAC,
        # set MAC for FAUCET VIPs on this VLAN
        'unicast_flood': True,
        'max_hosts': 255,
        # Limit number of hosts that can be learned on a VLAN.
        'vid': None,
        'proactive_arp_limit': None,
        # Don't proactively ARP for hosts if over this limit (None unlimited)
        'proactive_nd_limit': None,
        # Don't proactively ND for hosts if over this limit (None unlimited)
        }

    defaults_types = {
        'name': str,
        'description': str,
        'acl_in': (int, str),
        'faucet_vips': list,
        'faucet_mac': str,
        'unicast_flood': bool,
        'max_hosts': int,
        'vid': int,
        'proactive_arp_limit': int,
        'proactive_nd_limit': int,
    }

    def __init__(self, _id, dp_id, conf=None):
        if conf is None:
            conf = {}
        self._id = _id
        self.dp_id = dp_id
        self.update(conf)
        self.set_defaults()
        self._id = _id
        self.tagged = []
        self.untagged = []
        self.dyn_host_cache = {}
        self.dyn_ipvs = []

    def add_tagged(self, port):
        self.tagged.append(port)

    def add_untagged(self, port):
        self.untagged.append(port)

    @property
    def host_cache(self):
        """Return host (L2) cache for this VLAN."""
        return self.dyn_host_cache

    @host_cache.setter
    def host_cache(self, value):
        self.dyn_host_cache = value

    def set_defaults(self):
        for key, value in list(self.defaults.items()):
            self._set_default(key, value)
        self._set_default('vid', self._id)
        self._set_default('name', str(self._id))

    def __str__(self):
        port_list = [str(x) for x in self.get_ports()]
        ports = ','.join(port_list)
        return 'VLAN vid:%s ports:%s' % (self.vid, ports)

    def __repr__(self):
        return self.__str__()

    def get_ports(self):
        """Return list of all ports on this VLAN."""
        return list(self.tagged) + list(self.untagged)

    def mirrored_ports(self):
        """Return list of ports that are mirrored on this VLAN."""
        return [port for port in self.get_ports() if port.mirror]

    def mirror_destination_ports(self):
        """Return list of ports that are mirrored to, on this VLAN."""
        return [port for port in self.get_ports() if port.mirror_destination]

    def flood_ports(self, configured_ports, exclude_unicast):
        ports = []
        for port in configured_ports:
            if not port.running:
                continue
            if exclude_unicast:
                if not port.unicast_flood:
                    continue
            ports.append(port)
        return ports

    def tagged_flood_ports(self, exclude_unicast):
        return self.flood_ports(self.tagged, exclude_unicast)

    def untagged_flood_ports(self, exclude_unicast):
        return self.flood_ports(self.untagged, exclude_unicast)

    def flood_pkt(self, packet_builder, *args):
        ofmsgs = []
        for vid, ports in (
                (self.vid, self.tagged_flood_ports(False)),
                (None, self.untagged_flood_ports(False))):
            if ports:
                pkt = packet_builder(self, vid, *args)
                for port in ports:
                    ofmsgs.append(valve_of.packetout(port.number, pkt.data))
        return ofmsgs

    def port_is_tagged(self, port):
        """Return True if port number is an tagged port on this VLAN."""
        return port in self.tagged

    def port_is_untagged(self, port):
        """Return True if port number is an untagged port on this VLAN."""
        return port in self.untagged
