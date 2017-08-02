"""BGP implementation for FAUCET."""

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
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import ipaddress
from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker
try:
    from valve_util import btos
except ImportError:
    from faucet.valve_util import btos


class FaucetBgp(object):

    def __init__(self, logger, send_flow_msgs):
        self._bgp_speakers = {}
        self._metrics = None
        self._valves = None
        self.logger = logger
        self._send_flow_msgs = send_flow_msgs
        self._routers = {}

    def _bgp_route_handler(self, path_change, router_id):
        """Handle a BGP change event.

        Args:
            path_change (ryu.services.protocols.bgp.bgpspeaker.EventPrefix): path change
        """
        prefix = ipaddress.ip_network(btos(path_change.prefix))
        nexthop = ipaddress.ip_address(btos(path_change.nexthop))
        withdraw = path_change.is_withdraw
        flowmods = []
        for dp_id, valve in list(self._valves.items()):
            router = valve.dp.routers[router_id]
            if router.is_faucet_vip(nexthop):
                self.logger.error(
                    'BGP nexthop %s for prefix %s cannot be us',
                    nexthop, prefix)
                return
            if not router.ip_in_vip_subnet(nexthop):
                self.logger.error(
                    'BGP nexthop %s for prefix %s is not a connected network',
                    nexthop, prefix)
                return

            if withdraw:
                self.logger.info(
                    'BGP withdraw %s nexthop %s', prefix, nexthop)
                flowmods = valve.del_route(router, prefix)
            else:
                self.logger.info(
                    'BGP add %s nexthop %s', prefix, nexthop)
                flowmods = valve.add_route(router, nexthop, prefix)
            if flowmods:
                self._send_flow_msgs(dp_id, flowmods)

    def _create_bgp_speaker_for_router(self, router):
        """Set up a global BGP speaker for Faucet.

        Args:
        Returns:
            ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker: BGP speaker.
        """
        handler = lambda x: self._bgp_route_handler(x, router.router_id)
        bgp_speaker = BGPSpeaker(
            as_number=router.bgp_as,
            router_id=router.bgp_routerid,
            bgp_server_port=router.bgp_port,
            best_path_change_handler=handler)
        for ipv in router.ipvs():
            for vip in router.faucet_vips_by_ipv(ipv):
                bgp_speaker.prefix_add(
                    prefix=str(vip.network), next_hop=str(vip.ip))
            routes = router.routes_by_ipv(ipv)
            for ip_dst, ip_gw in list(routes.items()):
                bgp_speaker.prefix_add(
                    prefix=str(ip_dst), next_hop=str(ip_gw))
        for bgp_neighbor_address in router.bgp_neighbor_addresses:
            bgp_speaker.neighbor_add(
                address=bgp_neighbor_address,
                remote_as=router.bgp_neighbor_as,
                local_address=router.bgp_local_address,
                enable_ipv4=True,
                enable_ipv6=True)
        return bgp_speaker

    def reset(self, valves, metrics):
        """Set up a BGP speaker for every VLAN that requires it."""
        self._valves = valves
        self._metrics = metrics
        # TODO: port status changes should cause us to withdraw a route.

        valves = list(self._valves.values())
        self._routers = valves[0].dp.routers
        for rid, router in list(self._routers.items()):
            if rid in self._bgp_speakers:
                self._bgp_speakers[rid].shutdown()
            if not router.bgp_as:
                continue
            self._bgp_speakers[rid] = self._create_bgp_speaker_for_router(router)

    def update_metrics(self):
        """Update BGP metrics."""
        for routerid, bgp_speaker in list(self._bgp_speakers.items()):
            router = self._routers[routerid]
            if bgp_speaker:
                neighbor_states = list(json.loads(
                    bgp_speaker.neighbor_state_get()).items())
                for neighbor, neighbor_state in neighbor_states:
                    # pylint: disable=no-member
                    self._metrics.bgp_neighbor_uptime_seconds.labels(
                        router=routerid, neighbor=neighbor).set(
                            neighbor_state['info']['uptime'])
                    for ipv in router.ipvs():
                        #pylint: disable=no-member
                        self._metrics.bgp_neighbor_routes.labels(
                            router=routerid, neighbor=neighbor, ipv=ipv).set(
                                len(router.routes_by_ipv(ipv)))
