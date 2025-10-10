from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp, udp, icmp, arp, ether_types
import time
from collections import defaultdict

class ControllerAPI(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ControllerAPI, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.flow_stats = defaultdict(lambda: {
            'first_seen': 0.0, 'last_seen': 0.0,
            'packet_count': 0, 'byte_count': 0, 'datapath_id': None
        })
        self.logger.info("Controller iniciado - monitor L3 com NORMAL + espelhamento")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if dp.id not in self.datapaths:
            self.logger.info('Datapath conectado: %016x', dp.id)
            self.datapaths[dp.id] = dp

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        p = dp.ofproto_parser

        # (A) Flow base (priority 0): tudo → NORMAL (faz switch L2/ARP ok no próprio OVS)
        match_all = p.OFPMatch()
        actions_norm = [p.OFPActionOutput(ofp.OFPP_NORMAL)]
        inst_norm = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_norm)]
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=0, match=match_all, instructions=inst_norm))

        # (B) Espelhar IPv4 para o controlador (priority 10), sem parar o tráfego
        match_ip = p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
        actions_mirror_ip = [
            p.OFPActionOutput(ofp.OFPP_NORMAL),
            p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
        ]
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=10, match=match_ip,
                                 instructions=[p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_mirror_ip)]))

        # (opcional) Espelhar ARP também (útil para contar/depurar ARP)
        match_arp = p.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions_mirror_arp = [
            p.OFPActionOutput(ofp.OFPP_NORMAL),
            p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
        ]
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=10, match=match_arp,
                                 instructions=[p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_mirror_arp)]))

        self.logger.info("DPID %s: instalado NORMAL + espelhamento IP/ARP.", dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Chega aqui só a CÓPIA (mirror). NÃO faça PacketOut.
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return  # estamos interessados em IPv4 (ARP já foi espelhado só pra debug)

        ip_src, ip_dst, ip_proto = ip_pkt.src, ip_pkt.dst, ip_pkt.proto

        tp_src = tp_dst = 0
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if tcp_pkt:
            tp_src, tp_dst = tcp_pkt.src_port, tcp_pkt.dst_port
        elif udp_pkt:
            tp_src, tp_dst = udp_pkt.src_port, udp_pkt.dst_port
        elif icmp_pkt:
            tp_src, tp_dst = icmp_pkt.type, icmp_pkt.code

        key = (ip_src, ip_dst, ip_proto, tp_src, tp_dst)
        st = self.flow_stats[key]
        now = time.time()
        if st['first_seen'] == 0.0:
            st['first_seen'] = now
            st['datapath_id'] = dp.id
        st['last_seen'] = now
        st['packet_count'] += 1
        st['byte_count'] += len(msg.data)

        if st['packet_count'] % 100 == 0:
            self.logger.info("Flow %s:%s -> %s:%s proto=%s pkts=%d",
                             ip_src, tp_src, ip_dst, tp_dst, ip_proto, st['packet_count'])
