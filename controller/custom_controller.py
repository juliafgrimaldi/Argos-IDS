from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types, ipv4, tcp, udp, icmp

import time
from collections import defaultdict

class L3MonitorMinimal(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3MonitorMinimal, self).__init__(*args, **kwargs)
        self.datapaths = {}
        # flow_key = (ip_src, ip_dst, ip_proto, tp_src, tp_dst)
        self.flow_stats = defaultdict(lambda: {
            'first_seen': 0.0,
            'last_seen': 0.0,
            'packet_count': 0,
            'byte_count': 0,
            'datapath_id': None
        })
        self.report_interval = 10  # segundos
        self.idle_forget = 60      # esquece flows inativos há X s

        # thread periódica de monitoramento/log
        self.monitor_thread = hub.spawn(self._monitor)

        self.logger.info("Controller iniciado (minimal L3 monitor)")

    # ---- Registro dos datapaths (útil p/ monitor) ----
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.datapaths:
                self.logger.info("Datapath conectado: %016x", dp.id)
                self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                self.logger.info("Datapath desconectado: %016x", dp.id)
                del self.datapaths[dp.id]

    # ---- Instala table-miss: tudo vai ao controller ----
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
        dp.send_msg(mod)

        self.logger.info("DPID %s configurado: table-miss -> CONTROLLER", dp.id)

    # ---- PacketIn: extrai L3/L4 + encaminha ----
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # ignora LLDP e pacotes não-IP se quiser
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst
            ip_proto = ip_pkt.proto

            # portas L4 (ou ICMP type/code)
            tp_src = 0
            tp_dst = 0
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

            if tcp_pkt:
                tp_src = tcp_pkt.src_port
                tp_dst = tcp_pkt.dst_port
            elif udp_pkt:
                tp_src = udp_pkt.src_port
                tp_dst = udp_pkt.dst_port
            elif icmp_pkt:
                # opcional: usar type/code no lugar de portas
                tp_src = icmp_pkt.type   # apenas para chavear
                tp_dst = icmp_pkt.code

            flow_key = (ip_src, ip_dst, ip_proto, tp_src, tp_dst)
            st = self.flow_stats[flow_key]
            now = time.time()
            if st['first_seen'] == 0.0:
                st['first_seen'] = now
                st['datapath_id'] = dp.id
            st['last_seen'] = now
            st['packet_count'] += 1
            st['byte_count'] += len(msg.data)

            # log leve a cada 100 pacotes deste flow
            if st['packet_count'] % 100 == 0:
                self.logger.info("Flow %s -> %s proto=%s pkts=%d",
                                 ip_src, ip_dst, ip_proto, st['packet_count'])

        # Encaminhamento: NORMAL (OVS pipeline) — altere para FLOOD se preferir
        actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=dp,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        dp.send_msg(out)

    # ---- Monitor periódico: imprime top-N e limpa flows inativos ----
    def _monitor(self):
        while True:
            hub.sleep(self.report_interval)
            self._report_and_cleanup()

    def _report_and_cleanup(self):
        if not self.flow_stats:
            self.logger.debug("Sem flows no momento.")
            return

        now = time.time()
        # Top 10 por bytes no intervalo todo
        items = []
        for k, v in self.flow_stats.items():
            dur = max(v['last_seen'] - v['first_seen'], 1e-6)
            pps = v['packet_count'] / dur
            bps = v['byte_count'] / dur
            items.append((k, v['packet_count'], v['byte_count'], pps, bps, v['datapath_id'], v['last_seen']))

        items.sort(key=lambda x: x[2], reverse=True)
        top = items[:10]

        self.logger.info("=== TOP FLOWS (últimos ~%ds) ===", self.report_interval)
        for (k, pkts, bytes_, pps, bps, dpid, last_seen) in top:
            ip_src, ip_dst, proto, tp_src, tp_dst = k
            self.logger.info(
                "DP=%s %s:%s -> %s:%s proto=%s | pkts=%d bytes=%d | pps=%.2f bps=%.2f",
                dpid, ip_src, tp_src, ip_dst, tp_dst, proto, pkts, bytes_, pps, bps
            )

        # Limpeza de flows ociosos
        removed = 0
        for k in list(self.flow_stats.keys()):
            if now - self.flow_stats[k]['last_seen'] > self.idle_forget:
                del self.flow_stats[k]
                removed += 1
        if removed:
            self.logger.debug("Removidos %d flows inativos (> %ds).", removed, self.idle_forget)
