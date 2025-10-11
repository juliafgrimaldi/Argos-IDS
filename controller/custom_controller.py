from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import ipv4, tcp, udp, icmp
from ryu.lib import hub
import time
from collections import defaultdict


class SimpleSwitch13L3(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13L3, self).__init__(*args, **kwargs)
        
        # Tabela MAC (igual ao simple_switch_13 original)
        self.mac_to_port = {}
        
        # NOVO: Estatísticas Layer 3
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
        
        # Thread para relatórios (opcional)
        self.report_interval = 30  # Relatório a cada 30s
        self.monitor_thread = hub.spawn(self._monitor)
        
        self.logger.info("Simple Switch 13 L3 iniciado")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handler padrão do simple_switch_13"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Instalar table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """Adiciona flow (igual ao simple_switch_13 original)"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
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
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        
        # ========== NOVO: CAPTURA LAYER 3 ==========
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if ip_pkt:
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst
            ip_proto = ip_pkt.proto
            
            tp_src = 0
            tp_dst = 0
            
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            
            if tcp_pkt:
                tp_src = tcp_pkt.src_port
                tp_dst = tcp_pkt.dst_port
            elif udp_pkt:
                tp_src = udp_pkt.src_port
                tp_dst = udp_pkt.dst_port
            elif icmp_pkt:
                tp_src = icmp_pkt.type
                tp_dst = icmp_pkt.code
            
            # Criar chave do flow
            flow_key = (ip_src, ip_dst, ip_proto, tp_src, tp_dst)
            
            # Atualizar estatísticas
            st = self.flow_stats[flow_key]
            now = time.time()
            
            if st['first_seen'] == 0.0:
                st['first_seen'] = now
                st['datapath_id'] = datapath.id
                st['ip_src'] = ip_src
                st['ip_dst'] = ip_dst
                st['tp_src'] = tp_src
                st['tp_dst'] = tp_dst
                st['ip_proto'] = ip_proto
                
                # Log de novo flow
                proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(ip_proto, str(ip_proto))
                self.logger.info("Novo flow: %s:%d -> %s:%d [%s] in_port=%d",
                               ip_src, tp_src, ip_dst, tp_dst, proto_name, in_port)
            
            st['last_seen'] = now
            st['packet_count'] += 1
            st['byte_count'] += len(msg.data)
            
            # Log periódico
            if st['packet_count'] % 100 == 0:
                proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(ip_proto, str(ip_proto))
                duration = st['last_seen'] - st['first_seen']
                pps = st['packet_count'] / duration if duration > 0 else 0
                
                self.logger.info("Flow stats: %s:%d -> %s:%d [%s] | pkts=%d bytes=%d (%.2f pps)",
                               ip_src, tp_src, ip_dst, tp_dst, proto_name,
                               st['packet_count'], st['byte_count'], pps)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _monitor(self):
        """Thread opcional para relatórios periódicos"""
        while True:
            hub.sleep(self.report_interval)
            self._print_report()

    def _print_report(self):
        """Imprime relatório dos flows Layer 3"""
        if not self.flow_stats:
            return
        
        flows = []
        now = time.time()
        
        for key, st in self.flow_stats.items():
            duration = max(st['last_seen'] - st['first_seen'], 1e-6)
            pps = st['packet_count'] / duration
            bps = st['byte_count'] / duration
            
            flows.append({
                'ip_src': st['ip_src'],
                'ip_dst': st['ip_dst'],
                'tp_src': st['tp_src'],
                'tp_dst': st['tp_dst'],
                'ip_proto': st['ip_proto'],
                'packets': st['packet_count'],
                'bytes': st['byte_count'],
                'pps': pps,
                'bps': bps,
                'duration': duration
            })
        
        flows.sort(key=lambda x: x['bytes'], reverse=True)
        
        self.logger.info("="*70)
        self.logger.info("FLOWS LAYER 3 - TOP 10 (por bytes)")
        self.logger.info("="*70)
        
        for i, f in enumerate(flows[:10], 1):
            proto = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(f['ip_proto'], str(f['ip_proto']))
            self.logger.info("#%d: %s:%d -> %s:%d [%s] | %d pkts, %d bytes (%.2f pps, %.2f bps) %.1fs",
                           i, f['ip_src'], f['tp_src'], f['ip_dst'], f['tp_dst'],
                           proto, f['packets'], f['bytes'], f['pps'], f['bps'], f['duration'])
        
        self.logger.info("="*70)
        self.logger.info("Total de flows: %d", len(self.flow_stats))
    
    def get_flow_stats_dict(self):
        """
        Retorna estatísticas como dicionário (para seu IDS consumir)
        """
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