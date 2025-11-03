"""
Simple Switch 13 modificado para capturar dados Layer 3 e 4
Compatível com pingall e iperf
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types, ipv4, tcp, udp, icmp, arp
from ryu.lib import hub
import time
from collections import defaultdict


class SimpleSwitch13L3(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13L3, self).__init__(*args, **kwargs)

        # === Configurações gerais ===
        self.mac_to_port = {}
        self.flow_match_type = 'L4'  # L2 / L3 / L4
        self.PRIO_L2 = 1
        self.PRIO_ARP = 5
        self.PRIO_L3 = 10
        self.PRIO_L4 = 20
        self.IDLE_TIMEOUT = 30
        self.HARD_TIMEOUT = 0

        # Estatísticas
        self.flow_stats = defaultdict(lambda: {
            'first_seen': 0.0,
            'last_seen': 0.0,
            'packet_count': 0,
            'byte_count': 0,
            'datapath_id': None,
            'ip_src': '',
            'ip_dst': '',
            'tp_src': 0,
            'tp_dst': 0,
            'ip_proto': 0
        })

        # Thread opcional de relatório
        self.report_interval = 30
        self.monitor_thread = hub.spawn(self._monitor)

        self.logger.info("✅ SimpleSwitch13L3 iniciado (match_type=%s)", self.flow_match_type)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY
        )
        datapath.send_msg(mod)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        fm = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(fm)

        self.logger.info("✅ Table-miss reinstalada para DPID %s", datapath.id)


    def add_flow(self, datapath, priority, match, actions,
                 buffer_id=None, idle_timeout=30, hard_timeout=0):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id,
                priority=priority, match=match, instructions=inst,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority,
                match=match, instructions=inst,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofp.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]
            match_arp = parser.OFPMatch(
                eth_type=0x0806,
                arp_spa=arp_pkt.src_ip,
                arp_tpa=arp_pkt.dst_ip
            )

            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                self.add_flow(datapath, self.PRIO_ARP, match_arp, actions,
                              msg.buffer_id, idle_timeout=self.IDLE_TIMEOUT)
                return
            else:
                self.add_flow(datapath, self.PRIO_ARP, match_arp, actions,
                              idle_timeout=self.IDLE_TIMEOUT)

            data = None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=actions,
                                      data=data)
            datapath.send_msg(out)
            return

        # ------------------------------------------------------------------
        # 🔹 2) Learning-switch básico L2
        # ------------------------------------------------------------------
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # ------------------------------------------------------------------
        # 🔹 3) Match e instalação de flows L3/L4
        # ------------------------------------------------------------------
        ip_pkt_temp = pkt.get_protocol(ipv4.ipv4)
        match = None

        if ip_pkt_temp:
            match_fields = {
                'in_port': in_port,
                'eth_type': ether_types.ETH_TYPE_IP,
                'ipv4_src': ip_pkt_temp.src,
                'ipv4_dst': ip_pkt_temp.dst
            }
            prio = self.PRIO_L4 if self.flow_match_type == 'L4' else self.PRIO_L3

            if self.flow_match_type == 'L4':
                tcp_pkt_temp = pkt.get_protocol(tcp.tcp)
                udp_pkt_temp = pkt.get_protocol(udp.udp)
                if tcp_pkt_temp:
                    match_fields['ip_proto'] = 6
                    match_fields['tcp_src'] = tcp_pkt_temp.src_port
                    match_fields['tcp_dst'] = tcp_pkt_temp.dst_port
                elif udp_pkt_temp:
                    match_fields['ip_proto'] = 17
                    match_fields['udp_src'] = udp_pkt_temp.src_port
                    match_fields['udp_dst'] = udp_pkt_temp.dst_port
                else:
                    prio = self.PRIO_L3

            match = parser.OFPMatch(**match_fields)
        else:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            prio = self.PRIO_L2

        # Instala flow
        if msg.buffer_id != ofp.OFP_NO_BUFFER:
            self.add_flow(datapath, prio, match, actions,
                          msg.buffer_id, idle_timeout=self.IDLE_TIMEOUT)
            return
        else:
            self.add_flow(datapath, prio, match, actions,
                          idle_timeout=self.IDLE_TIMEOUT)

        # ------------------------------------------------------------------
        # 🔹 4) Atualiza estatísticas (captura L3)
        # ------------------------------------------------------------------
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst
            ip_proto = ip_pkt.proto
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
                st.update({
                    'first_seen': now,
                    'datapath_id': datapath.id,
                    'ip_src': ip_src,
                    'ip_dst': ip_dst,
                    'tp_src': tp_src,
                    'tp_dst': tp_dst,
                    'ip_proto': ip_proto
                })
                proto = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(ip_proto, str(ip_proto))
                self.logger.info(f"Novo flow: {ip_src}:{tp_src} -> {ip_dst}:{tp_dst} [{proto}]")
            st['last_seen'] = now
            st['packet_count'] += 1
            st['byte_count'] += len(msg.data)

        # ------------------------------------------------------------------
        # 🔹 5) PacketOut (envia o pacote atual)
        # ------------------------------------------------------------------
        data = None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # ----------------------------------------------------------------------

    def _monitor(self):
        while True:
            hub.sleep(self.report_interval)
            self._print_report()

    def _print_report(self):
        if not self.flow_stats:
            return
        flows = []
        for _, st in self.flow_stats.items():
            dur = max(st['last_seen'] - st['first_seen'], 1e-6)
            pps = st['packet_count'] / dur
            bps = st['byte_count'] / dur
            flows.append((st['ip_src'], st['tp_src'], st['ip_dst'], st['tp_dst'],
                          st['ip_proto'], st['packet_count'], st['byte_count'], pps, bps, dur))
        flows.sort(key=lambda x: x[6], reverse=True)
        self.logger.info("=" * 70)
        self.logger.info("FLOWS LAYER 3 - TOP 10")
        self.logger.info("=" * 70)
        for i, f in enumerate(flows[:10], 1):
            proto = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(f[4], str(f[4]))
            self.logger.info(f"#{i}: {f[0]}:{f[1]} -> {f[2]}:{f[3]} [{proto}] "
                             f"| {f[5]} pkts {f[6]} bytes ({f[7]:.2f} pps)")
        self.logger.info("Total de flows: %d", len(self.flow_stats))

    
    def get_flow_stats_dict(self):
        result = {}
        now = time.time()
        
        for key, st in self.flow_stats.items():
            duration = max(st['last_seen'] - st['first_seen'], 1e-6)
            flow_id = f"{st['ip_src']}_{st['tp_src']}_{st['ip_dst']}_{st['tp_dst']}_{st['ip_proto']}"
            
            result[flow_id] = {
                'timestamp': st['first_seen'],
                'datapath_id': st['datapath_id'],
                'ip_src': st['ip_src'],
                'ip_dst': st['ip_dst'],
                'tp_src': st['tp_src'],
                'tp_dst': st['tp_dst'],
                'ip_proto': st['ip_proto'],
                'packet_count': st['packet_count'],
                'byte_count': st['byte_count'],
                'flow_duration_sec': int(duration),
                'packet_count_per_second': st['packet_count'] / duration,
                'byte_count_per_second': st['byte_count'] / duration,
            }
        
        return result