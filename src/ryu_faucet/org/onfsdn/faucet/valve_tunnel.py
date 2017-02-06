import valve_of
from ryu.ofproto import ether
import ipaddr

class Tunnel(object):
    """Represent a tunnel (e.g. GRE or MPLS) """

    def __init__(self, id_, rem_ip, rem_id, loc_ip=None, loc_id=None):
        """
        rem_ip (ipaddr.IPAddress)   : IP of the remote end
        rem_id (int)                : ID of the remote end (i.e. MPLS label)
        loc_ip (ipaddr.IPAddress)   : IP of the local end
        loc_id (int)                : ID of the local end
        """
        self.id = id_
        self.rem_ip = rem_ip
        self.rem_id = rem_id
        self.loc_ip = loc_ip
        self.loc_id = loc_id

class TunnelManager(object):

    def __init__(self, logger, valve_in_match, valve_flowmod,
                 port_acl_table, eth_src_table, vlan_table,
                 tunnel_table, eth_dst_table, priority, vlans):

        self.logger = logger
        self.valve_in_match = valve_in_match
        self.valve_flowmod = valve_flowmod
        self.port_acl_table = port_acl_table
        self.eth_src_table = eth_src_table
        self.vlan_table = vlan_table
        self.tunnel_table = tunnel_table
        self.eth_dst_table = eth_dst_table
        self.priority = priority

        self.tunnels = {}
        for vlan in vlans.values():
            self.tunnels[vlan.vid] = {}
            for tun_id, tun_conf in vlan.tunnels.iteritems():
                rem_ip = ipaddr.IPAddress(tun_conf['rem_ip'])
                rem_id = tun_conf['rem_id']
                loc_ip = None
                if tun_conf.get('loc_ip', None):
                    loc_ip = ipaddr.IPAddress(tun_conf['loc_ip'])
                self.tunnels[vlan.vid][tun_id] = Tunnel(
                        id_=tun_id,
                        rem_ip=rem_ip,
                        rem_id=tun_conf['rem_id'],
                        loc_ip=loc_ip,
                        loc_id=tun_conf.get('loc_id',None))

    def get_tunnel(self, vlan, rem_ip):
        for tun in self.tunnels[vlan.vid].itervalues():
            if tun.rem_ip == rem_ip:
                return tun
        return None

    def add_tunnel_flows(self, vlan):
        ofmsgs = []
        for tun in self.tunnels[vlan.vid].itervalues():
            in_match = self.valve_in_match(
                    self.tunnel_table, vlan=vlan,
                    metadata=tun.id)
            inst = [
                    valve_of.apply_actions(
                        [valve_of.pop_vlan()] +
                        valve_of.push_mpls_act(tun.rem_id) +
                        valve_of.push_vlan_act(vlan.vid)),
                        valve_of.goto_table(self.eth_dst_table)]
            ofmsgs.append(self.valve_flowmod(
                self.tunnel_table,
                in_match,
                priority=self.priority,
                inst=inst))

            if tun.loc_id:
                in_match = self.valve_in_match(
                        self.port_acl_table,
                        eth_type=ether.ETH_TYPE_MPLS,
                        mpls_label=tun.loc_id)
                inst = [valve_of.apply_actions(
                    [valve_of.pop_mpls_act(
                        eth_type=ether.ETH_TYPE_MPLS)]),
                    valve_of.goto_table(self.eth_src_table)]
                ofmsgs.append(self.valve_flowmod(
                    self.port_acl_table,
                    in_match,
                    priority=self.priority + 1,
                    inst=inst))

        return ofmsgs
