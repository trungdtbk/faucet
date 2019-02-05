"""Implement experimental API."""

#### THIS API IS EXPERIMENTAL.
#### Discuss with faucet-dev list before relying on this API,
#### review http://www.hyrumslaw.com/.
#### It is subject to change without notice.

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
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

class FaucetExperimentalAPI:
    """An experimental API for communicating with Faucet.

    Contains methods for interacting with a running Faucet controller from
    within a RyuApp. This app should be run together with Faucet in the same
    ryu-manager process.
    """

    def __init__(self, *_args, **_kwargs):
        self.faucet = None

    def is_registered(self):
        """Return True if registered and ready to serve API requests."""
        return self.faucet is not None

    def _register(self, faucet):
        """Register with FAUCET RyuApp."""
        if self.faucet is None:
            self.faucet = faucet

    def reload_config(self):
        """Reload config from config file in FAUCET_CONFIG env variable."""
        if self.faucet is not None:
            self.faucet.reload_config(None)

    def get_config(self):
        """Get the current running config of Faucet as a python dictionary."""
        if self.faucet is not None:
            return self.faucet.get_config()
        return None

    def get_tables(self, dp_id):
        """Get current FAUCET tables as a dict of table name: table no."""
        if self.faucet is not None:
            return self.faucet.get_tables(dp_id)
        return None

    def push_config(self, config):
        """Push supplied config to FAUCET."""
        raise NotImplementedError # pragma: no cover

    def add_port_acl(self, port, acl):
        """Add an ACL to a port."""
        raise NotImplementedError # pragma: no cover

    def add_vlan_acl(self, vlan, acl):
        """Add an ACL to a VLAN."""
        raise NotImplementedError # pragma: no cover

    def delete_port_acl(self, port, acl):
        """Delete an ACL from a port."""
        raise NotImplementedError # pragma: no cover

    def delete_vlan_acl(self, vlan, acl):
        """Delete an ACL from a VLAN."""
        raise NotImplementedError # pragma: no cover

    @staticmethod
    def _select_vlan(vlans, vid=None, ipa=None):
        """Select a vlan based on vid or IP."""
        if vid and vid in vlans:
            return vlans[vid]
        if ipa:
            for vlan in vlans.values():
                if vlan.ip_in_vip_subnet(ipa):
                    return vlan
        return None

    @staticmethod
    def _select_valves(valves, dpid=None):
        """Return a list of valves with dpid or all if not specified."""
        if dpid and dpid in valves:
            return [valves[dpid]]
        return valves.values()

    def modify_route(self, prefix, nexthop, dpid=None, vid=None, pathid=None, add=True): # pylint: disable=too-many-arguments
        """Add/del a route from a given DP and VLAN or all DPs if not specified."""
        prefix = ipaddress.ip_network(str(prefix))
        nexthop = ipaddress.ip_address(str(nexthop))
        valve_ofmsgs = {}
        for valve in self._select_valves(self.faucet.valves_manager.valves, dpid):
            vlan = self._select_vlan(valve.dp.vlans, vid, nexthop)
            if vlan:
                if add:
                    method = valve.add_route
                else:
                    method = valve.del_route
                ofmsgs = method(vlan, ip_dst=prefix, ip_gw=nexthop, pathid=pathid)
                if ofmsgs:
                    valve_ofmsgs[valve] = ofmsgs
        self.faucet.valves_manager._send_ofmsgs_by_valve(valve_ofmsgs) # pylint: disable=protected-access

    def add_route(self, prefix, nexthop, dpid=None, vid=None, pathid=None): # pylint: disable=too-many-arguments
        """Add a route from a given DP and VLAN or all DPs if not specified."""
        self.modify_route(prefix, nexthop, dpid, vid, pathid)

    def del_route(self, prefix, nexthop, dpid=None, vid=None, pathid=None): # pylint: disable=too-many-arguments
        """Delete a route from a given DP and VLAN or all DPs if not specified."""
        self.modify_route(prefix, nexthop, dpid, vid, pathid, False)

    def modify_ext_vip(self, vip, pathid, dpid=None, vid=None, add=True): # pylint: disable=too-many-arguments
        """Add/del a VIP from the classification table for a given DP and VLAN."""
        vip = ipaddress.ip_address(str(vip))
        valve_ofmsgs = {}
        for valve in self._select_valves(self.faucet.valves_manager.valves, dpid):
            vlan = self._select_vlan(valve.dp.vlans, vid, vip)
            if vlan:
                if add:
                    method = valve.add_ext_vip
                else:
                    method = valve.del_ext_vip
                ofmsgs = method(vlan, vip, pathid)
                if ofmsgs:
                    valve_ofmsgs[valve] = ofmsgs
        self.faucet.valves_manager._send_ofmsgs_by_valve(valve_ofmsgs) # pylint: disable=protected-access

    def add_ext_vip(self, vip, pathid, dpid=None, vid=None):
        """Add a VIP from the classification table for a given DP and VLAN."""
        self.modify_ext_vip(vip, pathid, dpid, vid)

    def del_ext_vip(self, vip, pathid, dpid=None, vid=None):
        """Del a VIP from the classification table for a given DP and VLAN."""
        self.modify_ext_vip(vip, pathid, dpid, vid, False)
