"""Interface to the route server."""
import traceback
import json, collections
import ipaddress
import eventlet
eventlet.monkey_patch()

from ryu.lib.hub import StreamClient

Peer = collections.namedtuple('Peer',
        ['peer_ip', 'peer_as', 'local_ip', 'bgp_speaker_key', 'vlan', 'state'])
Nexthop = collections.namedtuple('Nexthop', ['nexthop', 'dp', 'port', 'vlan', 'state', 'pathid'])

class RouteServer(object):
    """Provide APIs to communication with the route server."""

    pathid = 0
    offset = 100

    def __init__(self, logger, valves, send_flow_msgs, server_addr=('127.0.0.1', 9999)):
        self.logger = logger
        self.server_addr = server_addr
        self.running = False
        self.socket = None
        self.send_q = eventlet.queue.Queue(128)
        self.recv_q = eventlet.queue.Queue(128)
        self.valves = valves
        self.send_flow_msgs = send_flow_msgs
        self.peers = {}
        self.router_to_peers = {}
        self.routes = {}
        self.nexthops = {}
        self.intra_ins = {}
        self.intra_outs = {}
        self.connected = False

        self.routers = self._routers(valves)
        for routerid, router in self.routers.items():
            self.register_router(routerid, router)

    @staticmethod
    def _routers(valves):
        """Return a dict of bgp routers, keyed by bgp_routerid that are configured in all Valves."""
        routers = {}
        if valves:
            for valve in list(valves.values()):
                routers.update([
                        (router.router_id, router)
                        for router in valve.dp.routers.values() if router.router_id])
        return routers

    def _send_loop(self):
        while self.running:
            if self.socket:
                msg = self.send_q.get()
                try:
                    self.socket.sendall(msg)
                except:
                    pass
            else:
                eventlet.sleep(1)

    def _recv_loop(self):
        while self.running:
            msg = self.recv_q.get()
            try:
                event = json.loads(msg)
                self.handle(event)
            except:
                print(msg)
                traceback.print_exc()

    def run(self):
        self.running = True
        client = StreamClient(self.server_addr)
        eventlet.spawn(self._recv_loop)
        eventlet.spawn(self._send_loop)
        while self.running:
            print('connecting to route server')
            self.socket = client.connect()
            if self.socket:
                self.logger.info('connected to route server at %s: %s' % self.server_addr)
                print('connected to route server')
                self.server_connected()
                while True:
                    try:
                        data = self.socket.recv(1024)
                        if data:
                            if type(data) == bytes:
                                data = data.decode('utf-8')
                            self.recv_q.put_nowait(data)
                        else:
                            self.socket.close()
                            break
                    except:
                        self.logger.error('connection to route server is lost')
                        self.connected = False
                        self.socket.close()
                        traceback.print_exc()
                        break
            eventlet.sleep(5)

    def stop(self):
        self.running = False
        if self.socket:
            self.deregister()
            self.socket.close()

    def send(self, event):
        msg = json.dumps(event) + '\n'
        if self.send_q.full():
            self.send_q.get()
        self.send_q.put_nowait(msg.encode('utf-8'))

    def handle(self, event):
        if event.get('msg_type') == 'mapping':
            self.mapping_handler(event)

    def server_connected(self):
        self.connected = True
        for router_id in self.routers.keys():
            self.router_up(router_id)
        for peer in self.peers.values():
            if peer.state == 'up':
                self.peer_up(peer.peer_ip)
            else:
                self.peer_down(peer.peer_ip)
        for nexthop, nh_obj in self.nexthops.items():
            self.nexthop_up(nexthop, nh_obj.dp, nh_obj.port, nh_obj.vlan, nh_obj.pathid)

    def register_router(self, router_id, router):
        """Register a router to the route server."""
        self.routers[router_id] = router
        self.router_to_peers[router_id] = set()

    def register_peer(self, peer_ip, peer_as, vlan, bgp_speaker_key):
        """Register a peer to the route server."""
        router = [rt for rt in self.routers.values() if vlan in rt.vlans]
        if len(router) == 0:
            return
        router = router[0]
        local_ip = router.router_id
        if peer_ip not in self.peers:
            self.peers[peer_ip] = Peer(
                    peer_ip=peer_ip, peer_as=peer_as, local_ip=local_ip,
                    bgp_speaker_key=bgp_speaker_key, vlan=vlan, state='down')
            self.router_to_peers[local_ip].add(peer_ip)
            self.routes[peer_ip] = collections.defaultdict(set)

    def mapping_handler(self, mapping):
        """A mapping informs about a route and how it can be used
        Visual description of a path and mapping (remote)

        (Peer1)--->(Border1)--[vlan1]-->(Border2)--[path1]-->(Peer2)--[nexthop1]-->(Prefix1)

        mapping = {
            'src': {'id': 'Peer1', 'type': 'BorderRouter'},
            'dst': {'id': 'Prefix1', 'type': 'Prefix'},
            'path': {
                'ingress': 'Border1',
                'egress': 'Border2',
                'neighbor': 'Peer2',
                'nexthop': 'nexthop1',
                'pathid': 'path1',
                'intralink': {'vlan': 'vlan1'}
            }
        }

        (local)

        (Peer1)--->(Border1)--[path1]-->(Peer2)--[nexthop1]-->(Prefix1)

        mapping = {
            'src': {'id': 'Peer1', 'type': 'BorderRouter'},
            'dst': {'id': 'Prefix1', 'type': 'Prefix'},
            'path': {
                'ingress': 'Border1',
                'egress': 'Border1',
                'neighbor': 'Peer2',
                'nexthop': 'nexthop1',
            }
        }
        """
        print(mapping)
        path = mapping['path']
        ingress = path['ingress']
        egress = path['egress']

        prefix = mapping['dst']['id']
        nexthop = path['nexthop']
        pathid = path['pathid']
        peer_ip = path['neighbor']
        local = ingress == egress # path is local
        if ingress in self.routers:
            nexthop = path['nexthop']
            if local:
                peer = self.peers[peer_ip]
                attachment = peer.attachment
                valve = self.valves[attachment.dp_id]
                vlan = valve.dp.vlans[attachment.vlan_vid]
            else:
                vlan, nexthop = self.intra_outs[egress]
            if mapping['src']['type'] == 'BorderRouter':
                pathid = None # add to the default fib table
            self._add_route(vlan, prefix, nexthop, pathid, local)
        elif egress in self.routers:
            if ingress in self.intra_ins:
                # we need to add a tunnel rule
                in_vlan, in_port = self.intra_ins[ingress]
                self._add_tunnel(in_vlan, in_port, pathid)
                # add a fib rule
                fib_vlan = self.peer_to_vlan[peer_ip]
                self._add_route(fib_vlan, prefix, nexthop, pathid, local=True)
        else:
            self.logger.error('the received mapping is not for me')
            return

        # now advertise to peer if required
        peer_ip = mapping['src']['id']
        if mapping['src']['type'] == 'PeerRouter' and peer_ip in self.peers:
            peer = self.peers[peer_ip]
            valve = self.valves[peer.attachment.dp_id]
            vlan = valve.dp.vlans[peer.attachment.vlan_vid]
            attributes = path.get('attributes', {})
            pathid = path['pathid']
            if not local:
                pathid = self.offset + pathid
            self._advertise(vlan, peer_ip, prefix, pathid, attributes)

    def _add_route(self, vlan, prefix, nexthop, pathid, local):
        """
        if local is true, the nexthop is an external host, otherwise it is another faucet.
        """
        valve = self.valves[vlan.dp_id]
        if not local or pathid is not None:
            print('non-local path and/or multipath is not supported')
            return
        print('adding new route', prefix, nexthop, pathid, local)
        prefix = ipaddress.ip_network(prefix)
        nexthop = ipaddress.ip_address(nexthop)
        flowmods = valve.add_route(vlan, nexthop, prefix)
        if flowmods:
            self.send_flow_msgs(valve, flowmods)

    def _add_tunnel(self, vlan, port, pathid):
        """
        a tunnel matches packets on MPLS label, marks them and forward through the pipeline
        a tunnel rule is added to the port_acl_table which matches on MPLS label
        """
        valve = self.valves[vlan.dp_id]
        flowmods = valve.add_tunnel(vlan, port, pathid)
        if flowmods:
            self.send_flow_msgs(valve, flowmods)

    def _advertise(self, vlan, peer_ip, prefix, pathid, attributes):
        """Advertise a route to this peer."""
        print('advertse a path to peer')
        #ip_gw = vlan.vip_for_host(ipaddress.ip_address(peer_ip), pathid)
        # TODO: send an announcement to peer

    def router_up(self, router_id):
        router = self.routers[router_id]
        event = dict(
                msg_type='router_up',
                routerid=router_id,
                name=router._id)
        self.send(event)

    def router_down(self, router_id):
        self.send(dict(msg_type='router_down', routerid=router_id))

    def peer_up(self, peer_ip):
        if peer_ip not in self.peers:
            return
        peer = self.peers[peer_ip]
        self.peers[peer_ip] = peer._replace(state = 'up')
        self.send(dict(
                msg_type='peer_up',
                peer_ip=peer.peer_ip,
                peer_as=peer.peer_as,
                local_ip=peer.local_ip))

    def peer_down(self, peer_ip):
        if peer_ip not in self.peers:
            return
        peer = self.peers[peer_ip]
        self.peers[peer_ip] = peer._replace(state = 'down')
        self.send(dict(msg_type='peer_down', peer_ip=peer_ip))
        for prefix, nexthops in self.routes[peer_ip].items():
            for nexthop in nexthops:
                self.route_down(peer_ip, nexthop, prefix)
        self.routes[peer_ip] = collections.defaultdict(set)

    def route_up(self, peer_ip, nexthop, prefix, as_path, origin):
        self.send(dict(msg_type='route_up', peer_ip=peer_ip, prefix=prefix,
                       next_hop=nexthop, as_path=as_path, origin=origin))

    def route_down(self, peer_ip, nexthop, prefix):
        self.send(dict(msg_type='route_down', peer_ip=peer_ip, prefix=prefix, next_hop=nexthop))

    def notify_route_change(self, path_change):
        peer_ip = path_change.neighbor
        prefix = path_change.prefix
        if not (peer_ip and prefix):
            return
        peer_ip = str(peer_ip)
        prefix = str(prefix)
        if path_change.is_withdraw:
            nexthop = path_change.next_hop
            nexthops = []
            if nexthop:
                nexthops.append(str(nexthop))
            else:
                nexthops.extend(self.routes[peer_ip][prefix])
            for nexthop in nexthops:
                self.routes[peer_ip][prefix].discard(nexthop)
                self.route_down(peer_ip, nexthop, prefix)
        else:
            nexthop = str(path_change.next_hop)
            self.routes[peer_ip][prefix].add(nexthop)
            self.route_up(peer_ip, nexthop, prefix, path_change.as_path, path_change.origin)

    def notify_link_up(self, router1, router2, dp_name=None, port_name=None, vlan_vid=None):
        """ Link between two Faucets is up """
        self.send({'msg_type': 'link_up', 'src': router1, 'dst': router2,
                   'attributes': {'dp': dp_name, 'port': port_name, 'vlan': vlan_vid}})

    def notify_link_down(self, router1, router2):
        self.send({'msg_type': 'link_down', 'src': router1, 'dst': router2})

    def nexthop_up(self, nexthop, dp_name, port_name, vlan_vid, pathid):
        for router in self.routers.values():
            for vlan in router.vlans:
                if vlan.vid == vlan_vid:
                    self.send(dict(msg_type='nexthop_up', routerid=router.router_id, pathid=pathid,
                              nexthop=nexthop, dp=dp_name, port=port_name, vlan=vlan_vid))
                    return

    def notify_nexthop_connected(self, nexthop, dp_name, port_name, vlan_vid):
        nexthop = str(nexthop)
        if nexthop not in self.nexthops:
            self.pathid += 1
            pathid = self.pathid
            self.nexthops[nexthop] = Nexthop(nexthop=nexthop, dp=dp_name, port=port_name,
                                             vlan=vlan_vid, state='up', pathid=self.pathid)
        else:
            nexthop_ = self.nexthops[nexthop]
            if (nexthop_.dp == dp_name
                    and nexthop_.port == port_name
                    and nexthop_.vlan == vlan_vid):
                return
            for key, value in [('dp', dp_name), ('port', port_name), ('vlan', vlan_vid), ('state', 'up')]:
                nexthop_ = nexthop_._replace(**{key: value})
            self.nexthops[nexthop] = nexthop_
            pathid = nexthop_.pathid
        self.nexthop_up(nexthop, dp_name, port_name, vlan_vid, pathid)


