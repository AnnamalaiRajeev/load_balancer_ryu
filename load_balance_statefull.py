from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types, ethernet, ipv4, tcp, icmp, arp
from ryu.lib.mac import haddr_to_bin


class L2Switch(app_manager.RyuApp):
    mac_of_server = {'server_1': ('00:00:00:00:00:01', 1, '10.0.0.1'), 'server_2': ('00:00:00:00:00:02', 2, '10.0.0.2'), 'server_3': ('00:00:00:00:00:03', 3, '10.0.0.3')}
    server_list = ['server_1', 'server_2', 'server_3']
    client_ip_mac_database = {}
    ip_of_server = '10.0.0.100'
    i = 3
    n = i % 3
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)

    def make_arp_reply(self, srcmac, dstmac, packetethertype, arpdata_srcip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=packetethertype,
                                           dst=srcmac,
                                           src=self.mac_of_server[self.server_list[self.n]][0]))

        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=self.mac_of_server[self.server_list[self.n]][0],
                                 src_ip=self.ip_of_server,
                                 dst_mac=srcmac,
                                 dst_ip=arpdata_srcip))
        return pkt

    def make_arp_reply_server(self, srcmac, dstmac, packetethertype, arpdata_srcip, client_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=packetethertype,
                                           dst=srcmac,
                                           src=self.mac_of_server[self.server_list[self.n]][0]))

        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=self.client_ip_mac_database[client_ip],
                                 src_ip=client_ip,
                                 dst_mac=srcmac,
                                 dst_ip=arpdata_srcip))
        return pkt

    def ipv4_to_int(self, string):
        ip = string.split('.')
        assert len(ip) == 4
        i = 0
        for b in ip:
            print(b)
            b = int(b)
            i = (i << 8) | b
            i = i % 3
        return i

    def add_flow(self, datapath, in_port, dst, src, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            dl_type=0x0800,
            dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=20, hard_timeout=0,
            priority=22222,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
        print("flow entry added:\n{}".format(mod))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        print('Packet_In:\n',msg)
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        packet_in_packet_instance = packet.Packet(data=msg.data)
        ethernet_header = packet_in_packet_instance.get_protocols(ethernet.ethernet)[0]
        dest_mac = ethernet_header.dst
        src_mac = ethernet_header.src
        if ethernet_header.ethertype == 2054:  # Arp packet
            arp_header = packet_in_packet_instance.get_protocols(arp.arp)[0]
            op_code = arp_header.opcode
            arp_data_dst_ip = arp_header.dst_ip
            arp_data_src_ip = arp_header.src_ip
            self.n = self.ipv4_to_int(arp_data_src_ip)
            if op_code == 1 and arp_data_dst_ip == '10.0.0.100':  # make arp reply and send it to client
                arp_reply_packet = self.make_arp_reply(src_mac, dest_mac, ethernet_header.ethertype, arp_data_src_ip)
                assert isinstance(arp_reply_packet, packet.Packet)
                arp_reply_packet.serialize()
                reply_data = arp_reply_packet.data
                actions = [ofp_parser.OFPActionOutput(port=msg.in_port)]
                out = ofp_parser.OFPPacketOut(
                    datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions,
                    data=reply_data)
                print("Arp reply sent to client {}\n{}".format(arp_data_src_ip, out))
                true_factor = dp.send_msg(out)
                assert true_factor is True
                print(self.mac_of_server[self.server_list[self.n]][2])
                actions = [dp.ofproto_parser.OFPActionSetNwDst(self.mac_of_server[self.server_list[self.n]][2]),
                           dp.ofproto_parser.OFPActionOutput(self.mac_of_server[self.server_list[self.n]][1])]
                self.add_flow(dp, msg.in_port, self.mac_of_server[self.server_list[self.n]][0], src_mac, actions) # forward flow
                actions = [dp.ofproto_parser.OFPActionSetNwSrc(self.ip_of_server),
                           dp.ofproto_parser.OFPActionOutput(msg.in_port)]
                self.add_flow(dp, self.mac_of_server[self.server_list[self.n]][1],
                              src_mac, self.mac_of_server[self.server_list[self.n]][0], actions)
                arp_data_client_ip = arp_header.src_ip
                self.client_ip_mac_database[arp_data_client_ip] = src_mac
                print('server alloted: {}, ip: {}'.format(self.server_list[self.n], self.mac_of_server[self.server_list[self.n]][2]))
                # self.i += 1
                # self.n = self.i % 3
                print('server Next in Que {} , ip: {}'.format(self.server_list[self.n],self.mac_of_server[self.server_list[self.n]][2]))

            elif op_code == 1 and arp_data_dst_ip in self.client_ip_mac_database.keys():
                arp_reply_packet = self.make_arp_reply_server(src_mac, self.client_ip_mac_database[arp_data_dst_ip],
                                                              ethernet_header.ethertype, arp_data_src_ip, 
                                                              arp_data_dst_ip)
                #print("*****************************\n\n", arp_reply_packet)
                assert isinstance(arp_reply_packet, packet.Packet)
                arp_reply_packet.serialize()
                reply_data = arp_reply_packet.data
                actions = [ofp_parser.OFPActionOutput(port=msg.in_port)]
                out = ofp_parser.OFPPacketOut(
                    datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions,
                    data=reply_data)
                true_factor = dp.send_msg(out)
                print("Arp reply[Packet_Out] sent to server {}:\n{}".format(arp_data_src_ip, out))
                print("arp_reply[Packet_Out] success status:", true_factor)

