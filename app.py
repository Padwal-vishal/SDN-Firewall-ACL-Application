from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.ofproto import ofproto_v1_3
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
import json

from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
import json

fname  = "rules.json"

#Priorities
ARP_PRIORITY = 100 
ACLRULE_PRIORITY = 11
DENY_PRIORITY = 10
TRAFFIC_PRIORITY = 50


# ACL & ACL Manager

class AccessControlList(object):
    '''
    Maintains the ACL rule in the dictionary
    '''
    def __init__(self):
        self.aclrules = {}
        with open(fname) as f:
            self.aclrules = json.load(f)

        #creating reverse acl rule for all rules
        r_flows = []
        for rule in self.aclrules:
            r_flows.append(self.get_reverse_flow(rule))
        self.aclrules.extend(r_flows)
        #print(self.aclrules)

    def list_acl(self):
        return self.aclrules

    def get_reverse_flow(self, rule):
        if "ipv4_src" in rule and "ipv4_dst" in rule and "protocol" in rule and "src_port" in rule and "dst_port" in rule:
            rrule = {  "ipv4_src": rule["ipv4_dst"], "ipv4_dst": rule["ipv4_src"], "protocol": rule["protocol"],"src_port": rule["dst_port"],"dst_port": rule["src_port"]}   
            return rrule

        if "ipv4_src" in rule and "ipv4_dst" in rule and "protocol" in rule :
            rrule = {  "ipv4_src": rule["ipv4_dst"], "ipv4_dst": rule["ipv4_src"], "protocol": rule["protocol"]}   
            return rrule        

        if "ipv4_src" in rule and "ipv4_dst" in rule:
            rrule = {  "ipv4_src": rule["ipv4_dst"], "ipv4_dst": rule["ipv4_src"]}   
            return rrule    

ACLManager = AccessControlList()


class AclApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AclApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #add ARP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]        
        self.add_flow(datapath, ARP_PRIORITY, match, actions)        


        #add default deny
        match = parser.OFPMatch()
        actions = []
        self.add_flow(datapath, DENY_PRIORITY, match, actions)


        #add acl rules to the new switch
        aclrules = ACLManager.list_acl()
        print(aclrules)
        for rule in aclrules:
            self.install_acl_rule(datapath, rule)


    def install_acl_rule(self, datapath, rule):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = self.create_acl_match(rule, parser)
        print(match)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, ACLRULE_PRIORITY, match, actions)


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



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)

                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port,)

                #  If UDP Protocol
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port,)            

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, TRAFFIC_PRIORITY, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, TRAFFIC_PRIORITY, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    def create_acl_match(self, rule, parser):
        match = None
        if "ipv4_src" in rule and "ipv4_dst" in rule and "protocol" in rule:
            #Checking ICMP Protocol
            if rule["protocol"] == "icmp":
                protocol = in_proto.IPPROTO_ICMP
            elif rule["protocol"] == "tcp":
                protocol = in_proto.IPPROTO_TCP                
            elif rule["protocol"] == "udp":
                protocol = in_proto.IPPROTO_UDP

            if  protocol == in_proto.IPPROTO_ICMP :
                if rule["ipv4_src"] == "any" and rule["ipv4_dst"] == "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol)
                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] != "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=rule["ipv4_dst"], ip_proto=protocol)
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] == "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=rule["ipv4_src"], ip_proto=protocol)
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] != "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=rule["ipv4_src"], ipv4_dst=rule["ipv4_dst"], ip_proto=protocol)
                return match
            elif protocol == in_proto.IPPROTO_TCP:
                if rule["ipv4_src"] == "any" and rule["ipv4_dst"] == "any" and rule["src_port"] =="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol)
                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] == "any" and rule["src_port"] =="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, tcp_dst= int(rule["dst_port"]))
                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] == "any" and rule["src_port"] !="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, tcp_src= int(rule["src_port"]))
                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] == "any" and rule["src_port"] !="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, tcp_src= int(rule["src_port"]), tcp_dst= int(rule["dst_port"]))


                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] == "any" and rule["src_port"] =="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=rule["ipv4_src"], ip_proto=protocol)
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] == "any" and rule["src_port"] =="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=rule["ipv4_src"], ip_proto=protocol, tcp_dst= int(rule["dst_port"]))
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] == "any" and rule["src_port"] !="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=rule["ipv4_src"], ip_proto=protocol, tcp_src= int(rule["src_port"]))
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] == "any" and rule["src_port"] !="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=rule["ipv4_src"], ip_proto=protocol, tcp_src= int(rule["src_port"]), tcp_dst= int(rule["dst_port"]))



                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] != "any" and rule["src_port"] =="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst=rule["ipv4_dst"], ip_proto=protocol)
                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] != "any" and rule["src_port"] =="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=rule["ipv4_dst"], ip_proto=protocol, tcp_dst= int(rule["dst_port"]))
                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] != "any" and rule["src_port"] !="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=rule["ipv4_dst"], ip_proto=protocol, tcp_src= int(rule["src_port"]))
                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] != "any" and rule["src_port"] !="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=rule["ipv4_dst"], ip_proto=protocol, tcp_src= int(rule["src_port"]), tcp_dst= int(rule["dst_port"]))



                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] != "any" and rule["src_port"] =="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=rule["ipv4_src"], ipv4_dst=rule["ipv4_dst"], ip_proto=protocol)
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] != "any" and rule["src_port"] =="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=rule["ipv4_src"], ipv4_dst=rule["ipv4_dst"], ip_proto=protocol, tcp_dst= int(rule["dst_port"]))
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] != "any" and rule["src_port"] !="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=rule["ipv4_src"], ipv4_dst=rule["ipv4_dst"], ip_proto=protocol, tcp_src= int(rule["src_port"]))
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] != "any" and rule["src_port"] !="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=rule["ipv4_src"], ipv4_dst=rule["ipv4_dst"], ip_proto=protocol, tcp_src= int(rule["src_port"]), tcp_dst= int(rule["dst_port"]))

                return match

            elif protocol == in_proto.IPPROTO_UDP:
                if rule["ipv4_src"] == "any" and rule["ipv4_dst"] == "any" and rule["src_port"] =="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol)
                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] == "any" and rule["src_port"] =="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, udp_dst= rule["dst_port"])
                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] == "any" and rule["src_port"] !="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, udp_src= rule["src_port"])
                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] == "any" and rule["src_port"] !="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, udp_src= rule["src_port"], udp_dst= int(rule["dst_port"]))


                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] == "any" and rule["src_port"] =="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=rule["ipv4_src"], ip_proto=protocol)
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] == "any" and rule["src_port"] =="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=rule["ipv4_src"], ip_proto=protocol, udp_dst= int(rule["dst_port"]))
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] == "any" and rule["src_port"] !="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=rule["ipv4_src"], ip_proto=protocol, udp_src= int(rule["src_port"]))
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] == "any" and rule["src_port"] !="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=rule["ipv4_src"], ip_proto=protocol, udp_src= int(rule["src_port"]), udp_dst= int(rule["dst_port"]))



                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] != "any" and rule["src_port"] =="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst=rule["ipv4_dst"], ip_proto=protocol)
                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] != "any" and rule["src_port"] =="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=rule["ipv4_dst"], ip_proto=protocol, udp_dst= int(rule["dst_port"]))
                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] != "any" and rule["src_port"] !="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=rule["ipv4_dst"], ip_proto=protocol, udp_src= int(rule["src_port"]))
                elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] != "any" and rule["src_port"] !="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=rule["ipv4_dst"], ip_proto=protocol, udp_src= int(rule["src_port"]), udp_dst= int(rule["dst_port"]))



                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] != "any" and rule["src_port"] =="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=rule["ipv4_src"], ipv4_dst=rule["ipv4_dst"], ip_proto=protocol)
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] != "any" and rule["src_port"] =="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=rule["ipv4_src"], ipv4_dst=rule["ipv4_dst"], ip_proto=protocol, udp_dst= int(rule["dst_port"]))
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] != "any" and rule["src_port"] !="any" and  rule["dst_port"]== "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=rule["ipv4_src"], ipv4_dst=rule["ipv4_dst"], ip_proto=protocol, udp_src= int(rule["src_port"]))
                elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] != "any" and rule["src_port"] !="any" and  rule["dst_port"]!= "any" :
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=rule["ipv4_src"], ipv4_dst=rule["ipv4_dst"], ip_proto=protocol, udp_src= int(rule["src_port"]), udp_dst= int(rule["dst_port"]))

                return match

        elif "ipv4_src" in rule and "ipv4_dst" in rule :
            if rule["ipv4_src"] == "any" and rule["ipv4_dst"] == "any" :
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
            elif rule["ipv4_src"] == "any" and rule["ipv4_dst"] != "any" :
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=rule["ipv4_dst"])
            elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] == "any" :
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=rule["ipv4_src"])
            elif rule["ipv4_src"] != "any" and rule["ipv4_dst"] != "any" :
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=rule["ipv4_src"], ipv4_dst=rule["ipv4_dst"])
            return match
