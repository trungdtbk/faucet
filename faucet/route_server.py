"""Interface to the route server."""
import traceback
import json, collections
import ipaddress
import eventlet
eventlet.monkey_patch()

from ryu.lib.hub import StreamClient

Peer = collections.namedtuple('Peer',
            ['peer_ip', 'peer_as', 'local_ip', 'pathid', 'attachment', 'state'])

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
        self.routers = {}
        self.peers = {}
        self.peer_state = {}
        self.router_to_peers = {}
        self.intra_ins = {}
        self.intra_outs = {}

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
        for router_id in self.routers.keys():
            self.router_up(router_id)
        for peer in self.peers.values():
            self.register_peer(
                peer.peer_ip, peer.peer_as, peer.local_ip, peer.attachment)

    def register_router(self, router_id, router):
        """Register a router to the route server."""
        self.routers[router_id] = router
        self.router_to_peers[router_id] = set()

    def register_peer(self, peer_ip, peer_as, local_ip, attachment):
        """Register a peer to the route server."""
        if peer_ip not in self.peers:
            self.pathid += 1
            pathid = self.pathid
            self.peers[peer_ip] = Peer(peer_ip, peer_as, local_ip, pathid, attachment, 'down')
            self.router_to_peers[local_ip].add(peer_ip)
        self.send(dict(
                msg_type='peer_up',
                peer_ip=peer_ip,
                peer_as=peer_as,
                local_ip=local_ip))

    def notify_peer_state(self, peer_ip, state):
        peer = self.peers[peer_ip]
        self.peers[peer_ip] = peer._replace(state = state)
        self.notify_peer_link_state(peer_ip, state)

    def notify_route_change(self, path_change):
        peer_ip = str(path_change.neighbor)
        if peer_ip is None:
            return
        prefix = str(path_change.prefix)
        if path_change.is_withdraw:
            self.send(dict(msg_type='route_down', peer_ip=peer_ip, prefix=prefix))
        else:
            self.send(event=dict(
                msg_type='route_up',
                peer_ip=peer_ip,
                prefix=prefix,
                next_hop=str(path_change.next_hop),
                as_path=path_change.as_path,
                origin=path_change.origin,
                ))

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
        assert local, 'non-local path is not supported'
        print('adding new route', prefix, nexthop, pathid, local)
        prefix = ipaddress.ip_network(prefix)
        nexthop = ipaddress.ip_address(nexthop)
        flowmods = valve.add_route(vlan, nexthop, prefix, pathid)
        print('flowmods', len(flowmods))
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
        ip_gw = vlan.vip_for_host(ipaddress.ip_address(peer_ip), pathid)
        print('get ip_gw', ip_gw)
        # TODO: send an announcement to peer

    def router_up(self, router_id):
        router = self.routers[router_id]
        event = dict(
                msg_type='router_up',
                router_id=router_id,
                name=router._id)
        self.send(event)

    def router_down(self, router_id):
        self.send(dict(msg_type='router_down', router_id=router_id))

    def peer_connected(self, peer_ip, dp_name, dp_id, port_no, vlan_vid):
        #self.peers[peer_ip] = (dp_name, dp_id, port_no, vlan_vid)
        self.peer_link_state_change(peer_ip, 'up')

    def peer_up(self, peer_ip):
        peer = self.peers[peer_ip]
        event = dict(
                msg_type='peer_up',
                peer_ip=peer.peer_ip,
                peer_as=peer.peer_as,
                local_ip=peer.local_ip)
        self.send(event)
        self.peer_link_state_change(peer_ip, 'up')

    def peer_down(self, peer_ip):
        event = dict(msg_type='peer_down', peer_ip=peer_ip)
        self.send(event)
        self.peer_link_state_change(peer_ip, 'down')

    def route_update(self, path_change):
        peer_ip = str(path_change.neighbor)
        if peer_ip is None:
            return
        prefix = str(path_change.prefix)
        if path_change.is_withdraw:
            self.send(dict(msg_type='route_down', peer_ip=peer_ip, prefix=prefix))
        else:
            self.send(event=dict(
                msg_type='route_up',
                peer_ip=peer_ip,
                prefix=prefix,
                next_hop=str(path_change.next_hop),
                as_path=path_change.as_path,
                origin=path_change.origin,
                ))

    def link_up(self, faucet1, faucet2):
        """ Link between two Faucets is up """
        self.link_state_change(src=dict(router_id=faucet1), dst=dict(router_id=faucet2), state='up')

    def link_down(self, fauct1, facuet2):
        self.link_state_change(src=dict(router_id=faucet1), dst=dict(router_id=faucet2), state='down')

    def notify_link_change(self, src, dst, change):
        self.send(dict(msg_type='link_state_change', src=src, dst=dst, attributes=change))

    def notify_peer_link_state(self, peer_ip, state):
        peer = self.peers[peer_ip]
        for src, dst in [
                ({'router_id': peer.local_ip}, {'peer_ip': peer_ip}),
                ({'peer_ip': peer_ip}, {'router_id': peer.local_ip})]:
            self.notify_link_change(src, dst, {'pathid': peer.pathid, 'state': state})


