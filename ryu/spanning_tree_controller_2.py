import json
import heapq
import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet , lldp
from ryu.lib.packet.lldp  import ChassisID
from ryu.lib.packet import ether_types
from ryu.lib.packet.packet import Packet



class SpanningTreeSwitch2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SpanningTreeSwitch2, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.switch_ports = {}
        self.adjacency_list = {}
        self.spanning_tree = {}
        self.host_ports = {}
        self.time_elapsed = 0
    def send_lldp(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for port in datapath.ports.values():
            # Skip LOCAL port
            if port.port_no == ofproto.OFPP_LOCAL:
                continue

            pkt = packet.Packet()

            # Ethernet header
            pkt.add_protocol(
                ethernet.ethernet(
                    dst=lldp.LLDP_MAC_NEAREST_BRIDGE,
                    src=port.hw_addr,
                    ethertype=ether_types.ETH_TYPE_LLDP
                )
            )

            # LLDP payload
            pkt.add_protocol(
                lldp.lldp([
                    lldp.ChassisID(
                        subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
                        chassis_id=str(datapath.id).encode()
                    ),
                    lldp.PortID(
                        subtype=lldp.PortID.SUB_PORT_COMPONENT,
                        port_id=str(port.port_no).encode()
                    ),
                    lldp.TTL(ttl=120),
                    lldp.End()
                ])
            )

            pkt.serialize()

            actions = [parser.OFPActionOutput(port.port_no)]

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=pkt.data
            )

            datapath.send_msg(out)

        # self.add_flow(datapath,0)
    
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        port = msg.desc
        self.logger.info("[PORT CHANGE] %s %s" , dp.id , port)
        if msg.reason == dp.ofproto.OFPPR_ADD:
            self.switch_ports.setdefault(dp.id, {})
            self.switch_ports[dp.id][port.port_no] = {'neighbour': 'host'}
            self.host_ports[dp.id].add(port.port_no)
            self.send_lldp(dp)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.switch_ports[datapath.id] = dict()
        self.adjacency_list[datapath.id] = dict()
        self.host_ports[datapath.id]= set()
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("[SWITCH ENTER] %s - Fetch Switch Features into this : \n %s" ,datapath.id , self.switch_ports)
        port_info_request = parser.OFPPortDescStatsRequest(datapath,0)
        datapath.send_msg(port_info_request)

    def build_adjacency_list(self):
        adjacency = {}
        for dpid, ports in self.switch_ports.items():
            adjacency.setdefault(dpid, [])

            for local_port, info in ports.items():
                if info.get('neighbour') != 'switch':
                    continue

                remote_dpid = info.get('dpid')
                if remote_dpid is None:
                    continue

                adjacency[dpid].append(
                    (remote_dpid, local_port)
                )
        # self.logger.info("[ADJACENCY LIST] %s" , adjacency)
        return adjacency

    def _build_spanning_tree(self, root = 1):
        # Distance to each node
        dist = {node: float('inf') for node in self.adjacency_list}
        dist[root] = 0

        # Parent info:
        # node -> (parent_node, local_port_on_parent)
        parent = {}

        pq = [(0, root)]  # (distance, node)

        while pq:
            cur_dist, u = heapq.heappop(pq)

            if cur_dist > dist[u]:
                continue

            for v, local_port in self.adjacency_list.get(u, []):
                if dist[v] > cur_dist + 1:
                    dist[v] = cur_dist + 1
                    parent[v] = (u, local_port)
                    heapq.heappush(pq, (dist[v], v))

        spanning_tree = {node: [] for node in self.adjacency_list}

        for child, (parent_node, parent_port) in parent.items():
            spanning_tree[parent_node].append((child, parent_port))
            for nbr, port in self.adjacency_list[child]:
                if nbr == parent_node:
                    spanning_tree[child].append((parent_node, port))
                    break

        return spanning_tree
        


        


    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply , CONFIG_DISPATCHER)
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply,MAIN_DISPATCHER)
    def handle_port_info(self,ev):

        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        self.logger.info("handle_port_info:\n[DPID] %s [PORTS]" , datapath.id)
        for port in ev.msg.body:
            self.logger.info("%s " , port)
            if port.port_no == (ofp.OFPP_CONTROLLER + 1) or port.port_no == ofp.OFPP_CONTROLLER:
                continue
            self.switch_ports[datapath.id][port.port_no] = {"neighbour" : "host" , "dpid" : None}
            self.host_ports[datapath.id].add(port.port_no)
        
        # self.logger.info("[UPDATED SWITCH FEATURES] %s" , self.switch_ports)

        self.send_lldp(datapath)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def handle_lldp_packet(self,datapath , packet, in_port):

        eth = packet.get_protocols(ethernet.ethernet)[0]
        lldp_pkt = packet.get_protocol(lldp.lldp)
        
        src = datapath.id
        chassis_id =  int(lldp_pkt.tlvs[0].chassis_id.decode())
        port_id = int(lldp_pkt.tlvs[1].port_id.decode())
        if self.switch_ports[datapath.id][in_port]['neighbour'] == 'host':
            self.logger.info("[LLDP PACKET] %s" , lldp_pkt)
        self.switch_ports[datapath.id][in_port]['neighbour'] = "switch"
        self.switch_ports[chassis_id][port_id]['neighbour'] = 'switch' 
        self.switch_ports[datapath.id][in_port]['dpid'] = chassis_id
        self.switch_ports[chassis_id][port_id]['dpid'] = datapath.id
        self.host_ports[chassis_id].discard(port_id)
        self.host_ports[src].discard(in_port)
        self.logger.info("[AFTER LLDP HANDLE] %s [HOST PORTS] %s" , json.dumps(self.switch_ports) , self.host_ports)
        self.adjacency_list = self.build_adjacency_list()
        #Compute the time elapsed to construct the spanning tree
        self.logger.info("[ADJACENCY LIST] %s" , self.adjacency_list)
        start = time.perf_counter()
        self.spanning_tree = self._build_spanning_tree()
        end = time.perf_counter()
        self.time_elapsed = end - start
        self.logger.info("[SPANNING TREE] %s" , self.spanning_tree)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        # self.logger.info("Datapath : %s" , datapath)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dpid = datapath.id
        dst = eth.dst
        src = eth.src
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # handle the lldp packet
            self.logger.info("packet in %s %s %s %s %s", dpid, src, dst, in_port , hex(eth.ethertype))
            # self.logger.info("[LLDP PACKET] %s" , pkt)
            self.handle_lldp_packet(datapath , pkt , in_port)
            return
        
        self.mac_to_port.setdefault(dpid, {})
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_ports = {self.mac_to_port[dpid][dst]}
        else:
            out_ports = set()
            for neighbour in self.spanning_tree.get(dpid, []):
                self.logger.info(neighbour)
                out_ports.add(neighbour[1])
            out_ports |= self.host_ports.get(dpid, set())

            out_ports.discard(in_port)
        # self.logger.info("[OUTPUT PORTS %s]" , out_ports)
        valid_ports = {p.port_no for p in datapath.ports.values()}
        out_ports &= valid_ports
        # self.logger.info("Flooding through following ports : %s" , out_ports)
        actions = [parser.OFPActionOutput(p) for p in out_ports]

        match = parser.OFPMatch(in_port=in_port,
                                eth_src=src,
                                eth_dst=dst)

        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                priority=1,
                match=match,
                instructions=[
                    parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions
                    )
                ]
            ))
            return

        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        ))
