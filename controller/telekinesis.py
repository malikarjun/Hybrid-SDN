# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.ofproto import ofproto_v1_3,ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.lib.packet import icmp
from ryu.lib.packet import udp
import pdb

def pack(byte_sequence):
    """Convert list of bytes to byte string."""
    return b"".join(map(chr, byte_sequence))

def _arp_reply(_eth_src, _eth_dst, _ip_src, _ip_dst):
    # Formulate a ARP
    # https://en.wikipedia.org/wiki/EtherType

    print _eth_src, _eth_dst, _ip_src, _ip_dst

    if _ip_src.split('.')[2] == _ip_dst.split('.')[2]:
        return -1

    print "Doing pout"

    eth_src = [int('0x'+byte, 16) for byte in _eth_src.split(':')]
    eth_dst = [int('0x'+byte, 16) for byte in _eth_dst.split(':')]
    eth_type = [0x08, 0x06]
    arp_type = [0x00, 0x01, 0x08, 0x00, 0x06, 0x04]
    arp_reply = [0x00, 0x02]
    arp_req = [0x00, 0x01]
    ip_src = [int(byte) for byte in _ip_src.split('.')]
    ip_dst = [int(byte) for byte in _ip_dst.split('.')]
    vlan_type = [0x81,0x00]
    vlan = [0x00,0x05]

    # arpframe
        ## ETHERNET
        # destination MAC addr
        # source MAC addr
        # vlan_type
        ##  VLAN
        # vlan
        # ETHERNET_PROTOCOL_TYPE_ARP,
        ## ARP
        # ARP_PROTOCOL_TYPE_ETHERNET_IP,
        # operation type request/reply
        # sender MAC addr
        # sender IP addr
        # target hardware addr
        # target IP addr

    arp_frame = eth_dst+eth_src+vlan_type+vlan+eth_type+arp_type+arp_reply+eth_src+ip_src+eth_dst+ip_dst

    # Construct Ethernet packet with an IPv4 ICMP PING request as payload
    r = pack(arp_frame)
    return r

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.dpset = kwargs['dpset']
        self.logger.info("packet in dpid src dst in_port")

    def send_packet_out(self, datapath, buffer_id, in_port, data):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_IN_PORT)]
        req = ofp_parser.OFPPacketOut(datapath, buffer_id,
                                      in_port, actions, data)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        self.mac_to_port = {}

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("packet in dpid src dst in_port %s",datapath.id)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # sample install flow
        # match = parser.OFPMatch(eth_dst='10:00:00:00:00:01')
        # actions = [parser.OFPActionSetField(eth_src='00:00:00:00:00:01'),parser.OFPActionOutput(1)]
        # self.add_flow(datapath, 1, match, actions)

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
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
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

        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        pkt_type = ""
        if pkt_arp:
            pkt_type = "arp"
        if pkt_icmp:
            pkt_type = "icmp"
        if pkt_tcp:
            pkt_type = "tcp"
        if pkt_udp:
            pkt_type = "udp"

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        if ("33" not in [dst[:2], src[:2]]) and ("ff" not in [dst[:2], src[:2]]): #supress random flood packets
            self.logger.info("packet in %s %s %s %s %s %s", dpid, src, dst, in_port, out_port, pkt_type)

        eth_VLAN = ether.ETH_TYPE_8021Q
        s_vid = 1
        try:
            s_vid = pkt.get_protocols(vlan.vlan)[0].vid
        except:
            s_vid = 1
            if pkt_arp:
                s_vid = int(pkt_arp.dst_ip.split('.')[2])
        f = parser.OFPMatchField.make( ofproto.OXM_OF_VLAN_VID, s_vid)
        vlan_action = [parser.OFPActionPushVlan(eth_VLAN),
                parser.OFPActionSetField(f)]
        actions = [parser.OFPActionOutput(out_port)]

        if pkt_arp:
            if in_port!=5:
                actions=vlan_action+actions
            else:
                actions=[parser.OFPActionPopVlan()]+actions

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
