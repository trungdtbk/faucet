#
import collections
import logging
import math
import networkx as nx
import ipaddress
from anytree import Node, RenderTree

INGRESS = 0
EGRESS = 1
TRANSIT = 2

IPV4 = 4
IPV6 = 6

MAX_PREFIXLEN = 6

def bgp_alloc_factory(logger, valves, vlan):
    graph = None
    switches = {}
    for valve in list(valves.values()):
        dp = valve.dp
        if vlan.vid in dp.vlans:
            switches[dp.name] = Switch(
                logger, dp.name, dp.switch_type, valve, dp.max_ipv4_fib, dp.max_ipv6_fib)
            if graph is None and dp.stack is not None:
                graph = dp.stack['graph']

    bgp_route_alloc = BGPRouteAllocator(logger, vlan.vid, graph, switches)
    return bgp_route_alloc

class Switch(object):
    """Represent a datapath """
    def __init__(self, logger, name, type_, valve=None, ipv4_cap=0, ipv6_cap=0):
        """
        Args:
            name (string): must be unique
            type (int): can be either INGRESS, EGRESS or TRANSIT
            valve (faucet.Valve): Valve that controls the corresponding datapath
            capacity (int): number of FIB entries it can hold
        """
        self.logger = logger
        self.name = name
        self.type = type_
        self.valve = valve
        self.dp_id = valve.dp.dp_id
        self.capacity = {}
        self.capacity[IPV4] = ipv4_cap
        self.capacity[IPV6] = ipv6_cap
        self.remain_cap = {}
        self.remain_cap[IPV4] = ipv4_cap
        self.remain_cap[IPV6] = ipv6_cap
        self.egress_dps = set() #List of egress sw transiting this switch
        self.fibs = collections.defaultdict(dict)

    def add_fib(self, vid, prefix, nexthop=None, next_dp=None):
        ofmsgs = []
        if self.remain_cap[prefix.version] > 0:
            via = nexthop if next_dp is None else next_dp
            self.logger.info(
                'Add fib to %s via %s to DP %s', prefix, via, self.name)
            self.fibs[prefix.version][prefix] = nexthop
            self.remain_cap[prefix.version] -= 1
            if self.valve is not None:
                vlan = self.valve.dp.vlans[vid]
                ofmsgs.extend(self.valve.add_route(
                    vlan=vlan, ip_dst=prefix, ip_gw=nexthop, next_dp=next_dp))
            else:
                self.logger.info(
                    'DP %s has no associated valve running', self.name)
            return ofmsgs
        else:
            self.logger.warn('DP %s has no space left', self.name)
            return ofmsgs

    def del_fib(self, vid, prefix):
        ofmsgs = []
        if prefix in self.fibs[prefix.version]:
            del self.fibs[prefix.version][prefix]
            if self.valve is not None:
                vlan = self.valve.dp.vlans[vid]
                ofmsgs.extend(self.valve.del_route(vlan=vlan, ip_dst=prefix))
            self.remain_cap[prefix.version] += 1
            self.logger.info('Del fib to %s from DP %s', prefix, self.name)
        return ofmsgs

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        return hash(self) == hash(other)

class BGPRouteAllocator(object):

    def __init__(self, logger, vid, graph, switches):
        """
        Args:
            graph (networkx.Graph): network topology
            switches (list): list of Switch instances
        """
        self.logger = logger
        self.vid = vid
        self.graph = graph
        self.switches = switches
        self.egress_switches = [
            name for name, switch in list(self.switches.items())
            if switch.type == 'egress']
        self.egress_trees = {}
        self.agg_prefixes = []
        self.agg_to_egress = {}
        self.max_prefixlen = MAX_PREFIXLEN

    def initialize(self):
        self._build_egress_trees()
        if len(self.egress_trees) > 0:
            num_prefixes = len(self.egress_trees)*2
            self._generate_agg_prefixes(num_prefixes, self.max_prefixlen)
        dp_ofmsgs = self._assign_agg_prefix_to_egress()
        return dp_ofmsgs

    def _assign_agg_prefix_to_egress(self):
        def install_fib(dp_ofmsgs, vid, node, prefix):
            for child in node.children:
                switch = child.switch
                dp_ofmsgs[switch.dp_id].extend(switch.add_fib(
                    vid, prefix, next_dp=node.switch.name))
                install_fib(dp_ofmsgs, vid, child, prefix)

        num_tree = len(self.egress_trees)
        next_egress_idx = {}
        for idx, egress in enumerate(self.egress_trees.keys()):
            next_egress_idx[idx] = egress
        dp_ofmsgs = collections.defaultdict(list)
        for idx, prefix in enumerate(self.agg_prefixes):
            egress = next_egress_idx[idx % (len(next_egress_idx) - 1)]
            self.agg_to_egress[prefix] = self.switches[egress]
            # install default routes to switches
            tree = self.egress_trees[egress]
            install_fib(dp_ofmsgs, self.vid, tree, prefix)
        return dp_ofmsgs

    def _generate_agg_prefixes(self, num_prefixes, max_prefixlen):
        largest = ipaddress.ip_network('0.0.0.0/0')
        self.agg_prefixes.append(largest)
        while(len(self.agg_prefixes) < num_prefixes):
            self.agg_prefixes.sort(key=lambda x:x.prefixlen)
            assert(self.agg_prefixes[-1].prefixlen <= max_prefixlen)
            largest = self.agg_prefixes.pop(0)
            for prefix in largest.subnets(prefixlen_diff=1):
                self.agg_prefixes.append(prefix)

    def _build_egress_trees(self):
        def prunning(node):
            """Remove unwanted node i.e. non-ingress leaves"""
            if node is None:
                return
            if node.is_leaf:
                if node.switch.type != 'ingress':
                    parent = node.parent
                    node.parent = None
                    prunning(parent)
            for child in node.children:
                prunning(child)

        def get_best_transit(switches, betweenness_centrality, neighbors):
            betweenness_centrality_copy = {}
            for neigh in neighbors:
                betweenness_centrality_copy[neigh] =  betweenness_centrality[neigh]
            usage_count = (1<<64, None)
            while True:
                best_transit = max(
                    betweenness_centrality_copy, key=lambda x : x[1])
                switch = switches[best_transit]
                if len(switch.egress_dps) == 0:
                    return best_transit
                else:
                    usage, neigh = usage_count
                    if len(switch.egress_dps) < usage:
                        usage_count = (len(switch.egress_dps), best_transit)
                    del betweenness_centrality_copy[best_transit]
                    if not betweenness_centrality_copy:
                        usage, neigh = usage_count
                        return neigh
            return None

        def build_spanning_tree(switches, graph, betweenness_centrality,
                                visited, parent):
            """Build non-overlap spanning tree rooted at an egress switch. We try to
            minimize the number of tree utilizing the same switch"""
            neighbors = graph.neighbors(parent.name)
            remain_nodes = set(neighbors).difference(visited)
            tobe_added = set()
            if not remain_nodes:
                return
            for node in list(remain_nodes):
                switch = switches[node]
                if switch.type != 'transit':
                    remain_nodes.remove(node)
                if switch.type == 'ingress':
                    tobe_added.add(node)
            if remain_nodes:
                best_transit = get_best_transit(
                    switches, betweenness_centrality, remain_nodes)
                tobe_added.add(best_transit)
            visited.update(neighbors)
            for node in tobe_added:
                switch = switches[node]
                child = Node(node, switch=switch,
                             parent=parent, egress=parent.egress)
                switch.egress_dps.add(parent.egress)
                build_spanning_tree(
                    switches, graph, betweenness_centrality, visited, child)

        for switch in list(self.switches.values()):
            if switch.type == 'egress':
                visited = set()
                tree = Node(switch.name, switch=switch, egress=switch.name)
                visited.add(switch.name)
                betweenness_centrality = nx.betweenness_centrality_source(
                    self.graph, sources=[switch.name])
                build_spanning_tree(
                    self.switches, self.graph, betweenness_centrality, visited, tree)
                prunning(tree)
                self.egress_trees[switch.name] = tree

    def _get_agg_prefix(self, prefix):
        """Return aggregate prefix which contains the prefix"""
        for agg_prefix in self.agg_prefixes:
            if agg_prefix.overlaps(prefix) and agg_prefix.prefixlen < prefix.prefixlen:
                return agg_prefix
        return None

    def add_route(self, prefix, nexthop, actual_egress):
        """
        Args:
            prefix (ipaddress.ip_network): IP prefix
            nexthop (ipaddress.ip_address): IP nexthop
            egress_sw (Switch): switch that the nexthop attached to
        """
        def install_fib(dp_ofmsgs, vid, tree, prefix, nexthop):
            switch = tree.switch
            if switch.remain_cap[prefix.version] > 0:
                dp_ofmsgs[switch.dp_id].extend(
                    switch.add_fib(vid, prefix, nexthop))
                return
            for child in tree.children:
                install_fib(dp_ofmsgs, vid, child, prefix, nexthop)
            return
        dp_ofmsgs = collections.defaultdict(list)
        agg_prefix = self._get_agg_prefix(prefix)
        should_be_egress_sw = self.agg_to_egress.get(agg_prefix, None)
        if actual_egress not in self.egress_switches or should_be_egress_sw is None:
            for switch in list(self.switches.values()):
                dp_ofmsgs[switch.dp_id].extend(switch.add_fib(self.vid, prefix, nexthop))
            return dp_ofmsgs
        if actual_egress == should_be_egress_sw.name:
            # prefix belongs to agg which is mapped to right egress sw
            # thus the route can be place anywhere along the path
            egress_tree = self.egress_trees[should_be_egress_sw.name]
            install_fib(dp_ofmsgs, self.vid,
                        self.egress_trees[should_be_egress_sw.name],
                        prefix, nexthop)
        else:
            # prefix belongs to a different tree
            # it must be installed on switch(es) that belong
            actual_egress_tree = self.egress_trees[actual_egress]
            should_be_egress_tree = self.egress_trees[should_be_egress_sw.name]
            all_my_switches = set(
                [node.switch for node in actual_egress_tree.descendants])
            all_other_switches = set(
                [node.switch for node in should_be_egress_tree.descendants])
            shared_switches = all_my_switches.intersection(all_other_switches)
            # try transit switch first
            for switch in shared_switches:
                if switch.type == 'transit' and switch.remain_cap[prefix.version] > 0:
                    dp_ofmsgs[switch.dp_id].extend(
                        switch.add_fib(self.vid, prefix, nexthop))
                    return dp_ofmsgs
            for switch in shared_switches:
                if switch.type == 'ingress':
                    dp_ofmsgs[switch.dp_id].extend(
                        switch.add_fib(self.vid, prefix, nexthop))
        return dp_ofmsgs

    def del_route(self, prefix):
        dp_ofmsgs = collections.defaultdict(list)
        agg_prefix = self._get_agg_prefix(prefix)
        for switch in list(self.switches.values()):
            dp_ofmsgs[switch.dp_id].extend(switch.del_fib(self.vid, prefix))
        return dp_ofmsgs
