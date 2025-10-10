from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types, ipv4, tcp, udp, icmp, arp
from ryu.lib import hub

import time
from collections import defaultdict

class ControllerAPI(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ControllerAPI, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.flow_stats = defaultdict(lambda: {
            'first_seen': 0.0,
            'last_seen': 0.0,
            'packet_count': 0,
            'byte_count': 0,
            'datapath_id': None
        })
        self.report_interval = 10  
        self.idle_forget = 60      
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("Controller iniciado (OF1.3): NORMAL + espelho IP/ARP + coleta L3/L4")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER and dp.id not in self.datapaths:
            self.datapaths[dp.id] = dp
            self.logger.info("Datapath conectado: %016x", dp.id)
        elif ev.state == DEAD_DISPATCHER and dp.id in self.datapaths:
            del self.datapaths[dp.id]
            self.logger.info("Datapath desconectado: %016x", dp.id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        p = dp.ofproto_parser

        match_all = p.OFPMatch()
        actions_norm = [p.OFPActionOutput(ofp.OFPP_NORMAL)]
        inst_norm = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_norm)]
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=0, match=match_all, instructions=inst_norm))

        match_ip = p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)  # 0x0800
        actions_mirror_ip = [
            p.OFPActionOutput(ofp.OFPP_NORMAL),
            p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
        ]
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=10, match=match_ip,
                                 instructions=[p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_mirror_ip)]))

        match_arp = p.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions_mirror_arp = [
            p.OFPActionOutput(ofp.OFPP_NORMAL),
            p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
        ]
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=10, match=match_arp,
                                 instructions=[p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_mirror_arp)]))

        self.logger.info("DPID %s: instalado NORMAL + espelho IP/ARP.", dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match.get('in_port')  # Usando o in_port no match

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # Ignora pacotes LLDP

        eth_src = eth.src
        eth_dst = eth.dst

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst
            ip_proto = ip_pkt.proto  

            tp_src = tp_dst = 0
            t = pkt.get_protocol(tcp.tcp)
            u = pkt.get_protocol(udp.udp)
            ic = pkt.get_protocol(icmp.icmp)
            if t:
                tp_src, tp_dst = t.src_port, t.dst_port
            elif u:
                tp_src, tp_dst = u.src_port, u.dst_port
            elif ic:
                tp_src, tp_dst = ic.type, ic.code  # ICMP Type e Code

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
                self.logger.info("Flow %s:%s -> %s:%s proto=%s | pkts=%d (in_port=%s mac %s→%s) ",
                                 ip_src, tp_src, ip_dst, tp_dst, ip_proto,
                                 st['packet_count'], in_port, eth_src, eth_dst)

    def _monitor(self):
        """Thread que realiza o monitoramento e relatórios periódicos"""
        while True:
            hub.sleep(self.report_interval)
            self._report_and_cleanup()

    def _report_and_cleanup(self):
        """Relatório de fluxos e limpeza dos fluxos inativos"""
        if not self.flow_stats:
            self.logger.debug("Sem fluxos no momento.")
            return

        now = time.time()
        items = []
        for k, v in self.flow_stats.items():
            dur = max(v['last_seen'] - v['first_seen'], 1e-6)
            pps = v['packet_count'] / dur
            bps = v['byte_count'] / dur
            items.append((k, v['packet_count'], v['byte_count'], pps, bps, v['datapath_id'], v['last_seen']))

        items.sort(key=lambda x: x[2], reverse=True)  # Ordena pelos bytes
        top = items[:10]

        self.logger.info("=== TOP FLOWS (últimos ~%ds) ===", self.report_interval)
        for (k, pkts, bytes_, pps, bps, dpid, last_seen) in top:
            ip_src, ip_dst, proto, tp_src, tp_dst = k
            self.logger.info("DP=%s %s:%s -> %s:%s proto=%s | pkts=%d bytes=%d | pps=%.2f bps=%.2f",
                             dpid, ip_src, tp_src, ip_dst, tp_dst, proto, pkts, bytes_, pps, bps)

        removed = 0
        for k in list(self.flow_stats.keys()):
            if now - self.flow_stats[k]['last_seen'] > self.idle_forget:
                del self.flow_stats[k]
                removed += 1
        if removed:
            self.logger.debug("Removidos %d fluxos inativos (> %ds).", removed, self.idle_forget)
