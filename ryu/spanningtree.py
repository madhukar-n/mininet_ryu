from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls, DEAD_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event
from ryu.topology.api import get_switch, get_link , get_all_switch , get_all_link
import copy
from ryu.controller import dpset
from ryu.lib import dpid as dpid_lib
from collections import deque
from threading import Lock

UP = 1
DOWN = 0
start = 1
class SimpleSwitchSpanningTree(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topo_shape = TopoStructure()
        self.spanning_tree = {}
        self.switches = []
        self.links = []
        self.host_ports = {}
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        dp = ev.msg.datapath
        self.logger.error("SWITCH CONNECTED: %s", ev.msg.datapath.id)


        ofp = dp.ofproto
        parser = dp.ofproto_parser

        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        dp.send_msg(
            parser.OFPFlowMod(
                datapath=dp,
                priority=0,
                match=match,
                instructions=inst
            )
        )



    def _compute_host_ports(self):
        link_ports = {}

        for u, v in self.links:
            link_ports.setdefault(u[0], set()).add(u[1])
            link_ports.setdefault(v[0], set()).add(v[1])
        for switch in self.switches:
            dpid = switch.dp.id
            ports = set(p.port_no for p in switch.ports)
            used_ports = link_ports.get(dpid, set())
            self.host_ports[dpid] = ports - used_ports

        self.logger.info("Host ports : %s", self.host_ports)

                

    
    def _build_spanning_tree(self, start):
        self.spanning_tree = {}
        visited = {start}
        queue = deque([start])
        self.logger.info("Root bridge : %s" , start)
        adj = {}
        for u, v in self.links:
            adj.setdefault(u[0], set()).add(v[0])
            adj.setdefault(v[0], set()).add(u[0])
        self.logger.info("Adjacency list : %s",adj)
        while queue:
            u = queue.popleft()
            for v in adj.get(u, []):
                if v not in visited:
                    visited.add(v)
                    queue.append(v)
                    self.spanning_tree.setdefault(u, set()).add(v)
                    self.spanning_tree.setdefault(v, set()).add(u)

        self.logger.info("Spanning Tree : %s" , self.spanning_tree)

    def get_topology_data(self):
        # Call get_switch() to get the list of objects Switch.
        self.topo_shape.topo_raw_switches = copy.copy(get_all_switch(self))
        # Call get_link() to get the list of objects Link.
        self.topo_shape.topo_raw_links = copy.copy(get_all_link(self))
        self.topo_shape.print_links("get_topology_data")
        self.topo_shape.print_switches("get_topology_data")
        self.topo_shape.convert_raw_links_to_list()
        self.topo_shape.convert_raw_switch_to_list()
        self.switches = copy.copy(self.topo_shape.topo_raw_switches)
        self.links = copy.copy(self.topo_shape.topo_links)
        self._compute_host_ports()
        self._build_spanning_tree(start)
        # print(f"Links and switches : {self.topo_shape.topo_links} , {self.topo_shape.topo_switches}")

    
    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        self.logger.info("Not tracking Switches, switch leaved.")
    

    @set_ev_cls(event.EventSwitchEnter)
    def on_switch_enter(self, ev):

        self.get_topology_data()
        # self.topo_shape.topo_raw_switches = copy.copy(get_switch(self, None))
        # self.topo_shape.topo_raw_links = copy.copy(get_link(self, None))

        # self.topo_shape.print_links("EventSwitchEnter")
        # self.topo_shape.print_switches("EventSwitchEnter")
        # self.topo_shape.convert_raw_links_to_list()
        # self.topo_shape.convert_raw_switch_to_list()
        # self._compute_host_ports()

    

    @set_ev_cls(dpset.EventPortModify, MAIN_DISPATCHER)
    def port_modify_handler(self, ev):
        self.topo_shape.lock.acquire()
        dp = ev.dp
        port_attr = ev.port
        dp_str = dpid_lib.dpid_to_str(dp.id)
        self.logger.info("\t ***switch dpid=%s"
                         "\n \t port_no=%d hw_addr=%s name=%s config=0x%08x "
                         "\n \t state=0x%08x curr=0x%08x advertised=0x%08x "
                         "\n \t supported=0x%08x peer=0x%08x curr_speed=%d max_speed=%d" %
                         (dp_str, port_attr.port_no, port_attr.hw_addr,
                          port_attr.name, port_attr.config,
                          port_attr.state, port_attr.curr, port_attr.advertised,
                          port_attr.supported, port_attr.peer, port_attr.curr_speed,
                          port_attr.max_speed))
        if port_attr.state == 1:
            tmp_list = []
            removed_link = self.topo_shape.link_with_src_port(port_attr.port_no, dp.id)
            for i, link in enumerate(self.topo_shape.topo_raw_links):
                if link.src.dpid == dp.id and link.src.port_no == port_attr.port_no:
                    print ("\t Removing link " + str(link) + " with index " + str(i))
                    # del self.topo_shape.topo_raw_links[i]
                elif link.dst.dpid == dp.id and link.dst.port_no == port_attr.port_no:
                    print ("\t Removing link " + str(link) + " with index " + str(i))
                    # del self.topo_shape.topo_raw_links[i]
                else:
                    tmp_list.append(link)

            self.topo_shape.topo_raw_links = copy.copy(tmp_list)

            self.topo_shape.print_links("Link Down")

            print ("\t Considering the removed Link " + str(removed_link))
            
            # if removed_link is not None:
            #     shortest_path_hubs, shortest_path_node = self.topo_shape.find_shortest_path(removed_link.src.dpid)
            #     print("\t\tNew shortest_path_hubs: {0}\n\t\tNew shortest_path_node: {1}".format(shortest_path_hubs, shortest_path_node))
        elif port_attr.state == 0:
            self.topo_shape.print_links("Link Up")
        self.get_topology_data()
        self.topo_shape.lock.release()
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        parser = dp.ofproto_parser
        ofp = dp.ofproto

        
        if dst in self.mac_to_port[dpid]:
            out_ports = {self.mac_to_port[dpid][dst]}
        else:
            out_ports = set()
            for nbr in self.spanning_tree.get(dpid, []):
                for u, v in self.links:
                    if u[0] == dpid and v[0] == nbr:
                        out_ports.add(u[1])
            #Add Host ports 
            out_ports |= self.host_ports.get(dpid, set())

            out_ports.discard(in_port)

        valid_ports = {p.port_no for p in dp.ports.values()}
        out_ports &= valid_ports

        actions = [parser.OFPActionOutput(p) for p in out_ports]

        match = parser.OFPMatch(in_port=in_port,
                                eth_src=src,
                                eth_dst=dst)

        if msg.buffer_id != ofp.OFP_NO_BUFFER:
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp,
                buffer_id=msg.buffer_id,
                priority=1,
                match=match,
                instructions=[
                    parser.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS, actions
                    )
                ]
            ))
            return

        dp.send_msg(parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        ))



class TopoStructure():
    def __init__(self, *args, **kwargs):
        self.topo_raw_switches = []
        self.topo_raw_links = []
        self.topo_links = []
        self.lock = Lock()
    
    def print_links(self, func_str=None):
        # Convert the raw link to list so that it is printed easily
        print(" \t" + str(func_str) + ": Current Links:")
        for l in self.topo_raw_links:
            print (" \t\t" + str(l))

    def print_switches(self, func_str=None):
        print(" \t" + str(func_str) + ": Current Switches:")
        for s in self.topo_raw_switches:
            print (" \t\t" + str(s))

    def switches_count(self):
        return len(self.topo_raw_switches)

    def convert_raw_links_to_list(self):
        # Build a  list with all the links [((srcNode,port), (dstNode, port))].
        # The list is easier for printing.
        self.topo_links = [((link.src.dpid, link.src.port_no),
                            (link.dst.dpid, link.dst.port_no))
                           for link in self.topo_raw_links]
        print(f"Links : {self.topo_links}")

    def convert_raw_switch_to_list(self):
        # Build a list with all the switches ([switches])
        self.topo_switches = [(switch.dp.id, UP) for switch in self.topo_raw_switches]
        print(f"switches : {self.topo_switches}")
    
    def link_with_src_port(self, in_port, in_dpid):
        for l in self.topo_raw_links:
            if (l.src.dpid == in_dpid and l.src.port_no == in_port) or (l.dst.dpid == in_dpid and l.src.port_no == in_port):
                return l
        return None
