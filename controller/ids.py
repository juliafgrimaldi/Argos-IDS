import pickle
import os
import time
import requests
import pandas as pd
import math
import sqlite3
from ryu.base import app_manager
from ryu.lib import hub
from ryu.controller import event
from sklearn import set_config
from ML.predict_knn import predict_knn
from ML.predict_svm import predict_svm
from ML.predict_decision_tree import predict_decision_tree
from ML.predict_random_forest import predict_random_forest

set_config(transform_output="pandas")
ryu_instance = None

class ControllerAPI(app_manager.RyuApp):
    _CONTEXTS = {}

    def __init__(self, *args, **kwargs):
        super(ControllerAPI, self).__init__(*args, **kwargs)
        try:
            self.api_url = "http://127.0.0.1:8080/stats/flow/"
            self.block_url = "http://127.0.0.1:8080/stats/flowentry/add"
            self.filename = "./backend/traffic_predict.csv"
            self.numeric_columns = [
                'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout', 
                'hard_timeout', 'flags', 'packet_count', 'byte_count',
                'packet_count_per_second', 'packet_count_per_nsecond',
                'byte_count_per_second', 'byte_count_per_nsecond'
            ]
            self.categorical_columns = [
                'datapath_id', 'flow_id', 'ip_src', 'tp_src', 
                'ip_dst', 'tp_dst', 'ip_proto', 'icmp_code', 'icmp_type'
            ]

            self.models = {}
            global ryu_instance
            ryu_instance = self
            self.blocked_sources = {}  
            self.block_cooldown = 300 
            
            self.start_time = time.time()
            self.last_processed_time = self.start_time
            self.logger.info("IDS iniciado em timestamp: {}".format(self.start_time))

            self.classification_threshold = 0.7
            
            self.accuracies = {
                "decision_tree": 0.97,
                "knn": 0.97,
                "random_forest": 0.97,
                "svm": 0.87,
            }

            self._load_models()
            self._initialize_csv()
            self._initialize_db()
            self.monitor_thread = hub.spawn(self._monitor)
            self.logger.info("ControllerAPI inicializou com sucesso")
        except Exception as e:
            self.logger.error("Erro no __init__: {}".format(e))

    def _initialize_db(self):
        conn = sqlite3.connect("traffic.db")
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            datapath_id INTEGER,
            flow_id TEXT,
            ip_src TEXT,
            tp_src INTEGER,
            ip_dst TEXT,
            tp_dst INTEGER,
            ip_proto INTEGER,
            icmp_code INTEGER,
            icmp_type INTEGER,
            flow_duration_sec INTEGER,
            flow_duration_nsec INTEGER,
            idle_timeout INTEGER,
            hard_timeout INTEGER,
            flags INTEGER,
            packet_count INTEGER,
            byte_count INTEGER,
            packet_count_per_second REAL,
            packet_count_per_nsecond REAL,
            byte_count_per_second REAL,
            byte_count_per_nsecond REAL,
            prediction_score REAL,
            label BOOLEAN
        )
        """)
        conn.commit()
        conn.close()

    def save_flow(self, row, label: bool, prediction_score: float = 0.0):
        try:
            conn = sqlite3.connect("traffic.db")
            cursor = conn.cursor()
            packets = row.get("packets", 0)
            bytes = row.get("bytes", 0)
            duration_sec = row.get("duration_sec", 0)
            packets = int(packets) if packets == packets else 0
            bytes = int(bytes) if bytes == bytes else 0
            duration_sec = int(duration_sec) if duration_sec == duration_sec else 0
            cursor.execute("PRAGMA table_info(flows)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'prediction_score' in columns:
                cursor.execute("""
                INSERT INTO flows (
                    timestamp, datapath_id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                    ip_proto, icmp_code, icmp_type, flow_duration_sec, flow_duration_nsec,
                    idle_timeout, hard_timeout, flags, packet_count, byte_count,
                    packet_count_per_second, packet_count_per_nsecond,
                    byte_count_per_second, byte_count_per_nsecond,
                    prediction_score, label
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    safe_float(row.get("timestamp", time.time())),
                    safe_int(row.get("datapath_id")),
                    str(row.get("flow_id", "")),
                    str(row.get("ip_src", "")),
                    safe_int(row.get("tp_src")),
                    str(row.get("ip_dst", "")),
                    safe_int(row.get("tp_dst")),
                    safe_int(row.get("ip_proto")),
                    safe_int(row.get("icmp_code")),
                    safe_int(row.get("icmp_type")),
                    safe_int(row.get("flow_duration_sec")),
                    safe_int(row.get("flow_duration_nsec")),
                    safe_int(row.get("idle_timeout")),
                    safe_int(row.get("hard_timeout")),
                    safe_int(row.get("flags")),
                    safe_int(row.get("packet_count")),
                    safe_int(row.get("byte_count")),
                    safe_float(row.get("packet_count_per_second")),
                    safe_float(row.get("packet_count_per_nsecond")),
                    safe_float(row.get("byte_count_per_second")),
                    safe_float(row.get("byte_count_per_nsecond")),
                    float(prediction_score),
                    1 if label else 0
            ))
            else:
                cursor.execute("""
                INSERT INTO flows (
                    timestamp, datapath_id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                    ip_proto, icmp_code, icmp_type, flow_duration_sec, flow_duration_nsec,
                    idle_timeout, hard_timeout, flags, packet_count, byte_count,
                    packet_count_per_second, packet_count_per_nsecond,
                    byte_count_per_second, byte_count_per_nsecond, label
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                safe_float(row.get("timestamp", time.time())),
                safe_int(row.get("datapath_id")),
                str(row.get("flow_id", "")),
                str(row.get("ip_src", "")),
                safe_int(row.get("tp_src")),
                str(row.get("ip_dst", "")),
                safe_int(row.get("tp_dst")),
                safe_int(row.get("ip_proto")),
                safe_int(row.get("icmp_code")),
                safe_int(row.get("icmp_type")),
                safe_int(row.get("flow_duration_sec")),
                safe_int(row.get("flow_duration_nsec")),
                safe_int(row.get("idle_timeout")),
                safe_int(row.get("hard_timeout")),
                safe_int(row.get("flags")),
                safe_int(row.get("packet_count")),
                safe_int(row.get("byte_count")),
                safe_float(row.get("packet_count_per_second")),
                safe_float(row.get("packet_count_per_nsecond")),
                safe_float(row.get("byte_count_per_second")),
                safe_float(row.get("byte_count_per_nsecond")),
                1 if label else 0
            ))

            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error("Erro ao salvar fluxo no banco: {}".format(e))

    def get_active_dpids(self):
        try:
            response = requests.get("http://127.0.0.1:8080/stats/switches")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error("Erro ao buscar switches ativos: {}".format(e))
        return []

    def _load_models(self):
        self.logger.info("Loading bundled models from pickle...")
        def load_bundle(name):
            try:
                with open("mdls/{}_model_bundle.pkl".format(name), "rb") as f:
                    return pickle.load(f)
            except Exception as e:
                self.logger.error("Erro ao carregar modelo {}: {}".format(name, e))
                return None

        model_files = {
            'decision_tree': 'dt',
            'knn': 'knn',
            'random_forest': 'randomforest',
            'svm': 'svm'
        }
        
        for model_name, file_name in model_files.items():
            model_path = "mdls/{}_model_bundle.pkl".format(file_name)
            if os.path.exists(model_path):
                model = load_bundle(file_name)
                if model is not None:
                    self.models[model_name] = model
                    self.logger.info("Modelo {} carregado com sucesso".format(model_name))
            else:
                self.logger.warning("Arquivo de modelo não encontrado: {}".format(model_path))

    def _initialize_csv(self):
        df = pd.DataFrame(columns=[
            'timestamp', 'datapath_id', 'flow_id', 'ip_src', 'tp_src', 
            'ip_dst', 'tp_dst', 'ip_proto', 'icmp_code', 'icmp_type',
            'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout',
            'hard_timeout', 'flags', 'packet_count', 'byte_count',
            'packet_count_per_second', 'packet_count_per_nsecond',
            'byte_count_per_second', 'byte_count_per_nsecond'
        ])
        df.to_csv(self.filename, index=False)

    def _monitor(self):
        while True:
            self.logger.info("Monitor thread active")
            dpids = self.get_active_dpids()
            self.logger.info(f"DPIDs ativos: {dpids}")
            for dpid in dpids:
                self.collect_and_store_stats(dpid)
            self.predict_traffic()
            hub.sleep(10)

    def collect_and_store_stats(self, dpid):
        try:
            self.logger.info("Coletando stats do DPID {}".format(dpid))
            response = requests.get("{}{}".format(self.api_url, dpid), timeout=10)
            response.raise_for_status()
            flow_stats = response.json().get(str(dpid), [])
            rows = []
            current_time = time.time()

            for stat in flow_stats:
                match = stat.get('match', {})
                ip_src = match.get('ipv4_src', match.get('nw_src', '0.0.0.0'))
                ip_dst = match.get('ipv4_dst', match.get('nw_dst', '0.0.0.0'))
                tp_src = match.get('tcp_src', match.get('udp_src', match.get('tp_src', 0)))
                tp_dst = match.get('tcp_dst', match.get('udp_dst', match.get('tp_dst', 0)))
                ip_proto = match.get('ip_proto', match.get('nw_proto', 0))
                icmp_code = match.get('icmpv4_code', match.get('icmp_code', 0))
                icmp_type = match.get('icmpv4_type', match.get('icmp_type', 0))
                in_port = match.get('in_port', 0)

                packet_count = stat.get('packet_count', 0)
                byte_count = stat.get('byte_count', 0)
                duration_sec = stat.get('duration_sec', 0)
                duration_nsec = stat.get('duration_nsec', 0)
                idle_timeout = stat.get('idle_timeout', 0)
                hard_timeout = stat.get('hard_timeout', 0)
                flags = stat.get('flags', 0)
                priority = stat.get('priority', 0)

                if packet_count <= 10 and byte_count <= 1000:
                    self.logger.debug("Ignorando tráfego de controle")
                    continue

                if packet_count == 0 or byte_count == 0:
                    continue

                if duration_sec < 1:
                    self.logger.debug("Ignorando fluxo efêmero (duration < 1s)")
                    continue

                total_duration_sec = duration_sec + (duration_nsec / 1e9)

                if total_duration_sec > 0:
                    packet_count_per_second = packet_count / total_duration_sec
                    byte_count_per_second = byte_count / total_duration_sec
                else:
                    packet_count_per_second = 0
                    byte_count_per_second = 0
                
                total_duration_nsec = (duration_sec * 1e9) + duration_nsec
                if total_duration_nsec > 0:
                    packet_count_per_nsecond = packet_count / total_duration_nsec
                    byte_count_per_nsecond = byte_count / total_duration_nsec
                else:
                    packet_count_per_nsecond = 0
                    byte_count_per_nsecond = 0

                # Detecção volumétrica imediata
                if packet_count_per_second > 10000:
                    self.logger.warning("ATAQUE VOLUMÉTRICO DETECTADO: {} pps".format(packet_count_per_second))
                    # Bloquear imediatamente
                    continue
                
                flow_id = "{}{}{}{}{}".format(ip_src, tp_src, ip_dst, tp_dst, ip_proto)

                if packet_count >= 10 and packet_count <= 1000:
                    self.logger.info("Flow sample: packets={}, bytes={}, duration_sec={}, ip_src={}, ip_dst={}".format(
                        packet_count, byte_count, duration_sec, ip_src, ip_dst
                    ))

                rows.append({
                    'timestamp': current_time,
                    'datapath_id': dpid,
                    'flow_id': flow_id,
                    'ip_src': ip_src,
                    'tp_src': tp_src,
                    'ip_dst': ip_dst,
                    'tp_dst': tp_dst,
                    'ip_proto': ip_proto,
                    'icmp_code': icmp_code,
                    'icmp_type': icmp_type,
                    'flow_duration_sec': duration_sec,
                    'flow_duration_nsec': duration_nsec,
                    'idle_timeout': idle_timeout,
                    'hard_timeout': hard_timeout,
                    'flags': flags,
                    'packet_count': packet_count,
                    'byte_count': byte_count,
                    'packet_count_per_second': packet_count_per_second,
                    'packet_count_per_nsecond': packet_count_per_nsecond,
                    'byte_count_per_second': byte_count_per_second,
                    'byte_count_per_nsecond': byte_count_per_nsecond
                })

            if rows:
                file_exists = os.path.exists(self.filename)
                pd.DataFrame(rows).to_csv(self.filename, mode='a', index=False, header=not file_exists)
                self.logger.info("Coletados {} fluxos".format(len(rows)))

        except Exception as e:
            self.logger.error("Failed to collect stats for dpid {}: {}".format(dpid, e))

    def predict_traffic(self):
        try:
            if not os.path.exists(self.filename):
                self.logger.warning("CSV file doesn't exist yet")
                return
                
            df = pd.read_csv(self.filename)
            if df.empty:
                self.logger.info("No data for prediction")
                return

            df_unprocessed = df[df['time'] > self.last_processed_time].copy()
            if df_unprocessed.empty:
                self.logger.info("Nenhum tráfego novo desde a inicialização")
                return
            
            processing_start_time = time.time()

            temp_filename = "./backend/temp_predict.csv"
            df_unprocessed.to_csv(temp_filename, index=False)

            self.logger.info("Iniciando predições para {} fluxos usando {} modelos".format(len(df_unprocessed), len(self.models)))
            predictions = {}

            for name, bundle in self.models.items():
                try:
                    self.logger.info("Executando predição com modelo: {}".format(name))
                    
                    if name == 'knn':
                        pred, _ = predict_knn(bundle, temp_filename)
                    elif name == 'svm':
                        pred, _ = predict_svm(bundle, temp_filename)
                    elif name == 'decision_tree':
                        pred, _ = predict_decision_tree(bundle, temp_filename)
                    elif name == 'random_forest':
                        pred, _ = predict_random_forest(bundle, temp_filename)
                    else:
                        continue
                    
                    if pred is not None and len(pred) > 0:
                        predictions[name] = pred
                        
                        malicious_count = sum(pred)
                        benign_count = len(pred) - malicious_count
                        self.logger.info("Modelo {}: {} maliciosos, {} benignos ({:.1f}% maliciosos)".format(
                            name, malicious_count, benign_count, 
                            (malicious_count/len(pred))*100 if len(pred) > 0 else 0
                        ))
                    else:
                        self.logger.warning("Modelo {} retornou predições inválidas".format(name))
                        
                except Exception as e:
                    self.logger.error("Erro na predição do modelo {}: {}".format(name, e))
                    import traceback
                    self.logger.error("Traceback: {}".format(traceback.format_exc()))

            if os.path.exists(temp_filename):
                os.remove(temp_filename)

            if not predictions:
                self.logger.error("Nenhuma predição válida foi obtida!")
                return

            if len(predictions) > 1:
                self.logger.info("Usando votação ponderada com {} modelos".format(len(predictions)))
                final_predictions = self.weighted_vote(predictions)
            else:
                model_name = list(predictions.keys())[0]
                final_predictions = predictions[model_name]
                self.logger.info("Usando apenas modelo: {}".format(model_name))


            total_malicious = sum(final_predictions)
            total_flows = len(final_predictions)
            percentage_malicious = (total_malicious/total_flows)*100 if total_flows > 0 else 0
            self.logger.info("RESULTADO FINAL: {} fluxos maliciosos de {} total ({:.1f}%)".format(
                total_malicious, total_flows, (total_malicious/total_flows)*100 if total_flows > 0 else 0
            ))

            if percentage_malicious > 80 and total_flows > 10:
                self.logger.error("ALERTA: Taxa de detecção suspeita ({:.1f}%)! Possível problema nos modelos ou dados.".format(
                    percentage_malicious
                ))
                self.logger.error("Recomendação: Verifique se os modelos foram treinados corretamente.")

            blocked_count = 0
            for i, pred in enumerate(final_predictions):
                if i >= len(df):
                    break
                    
                row = df_unprocessed.iloc[i].to_dict()
                confidence_score = self._calculate_confidence_score(predictions, i) if len(predictions) > 1 else float(pred)

                self.save_flow(row, bool(pred), confidence_score)
                
                if pred == 1:
                    blocked_count += 1
                    self.logger.warning("FLUXO MALICIOSO DETECTADO (confiança: {:.3f}): dpid={}, src={}, dst={}, packets={}, bytes={}".format(
                        confidence_score, row['datapath_id'], row['ip_src'], row['ip_dst'], row['packet_count'], row['bytes']
                    ))
                    self.block_traffic(row['datapath_id'], row['ip_src'], row['ip_dst'], row.get('in_port', 0))
                else:
                    self.logger.debug("Fluxo benigno: packets={}, bytes={}".format(row['packet_count'], row['byte_count']))

            self.last_processed_time = processing_start_time

            if blocked_count > 0:
                self.logger.warning("BLOQUEIOS NESTE CICLO: {} (apenas novos fluxos)".format(blocked_count))
            else:
                self.logger.info("Nenhum bloqueio - todos os {} novos fluxos são benignos".format(total_flows))

        except Exception as e:
            self.logger.error("Prediction error: {}".format(e))
            import traceback
            self.logger.error("Traceback: {}".format(traceback.format_exc()))

    def _calculate_confidence_score(self, predictions, index):
        if not predictions or index >= len(list(predictions.values())[0]):
            return 0.0
            
        votes = []
        total_weight = 0
        weighted_sum = 0
        
        for model_name, pred_list in predictions.items():
            if index < len(pred_list):
                weight = self.accuracies.get(model_name, 1.0)
                votes.append(pred_list[index])
                weighted_sum += pred_list[index] * weight
                total_weight += weight
        
        if total_weight > 0:
            return weighted_sum / total_weight
        else:
            return 0.0

    def weighted_vote(self, predictions):
        if not predictions:
            return []
            
        num_samples = len(list(predictions.values())[0])
        
        for model_name, pred_list in predictions.items():
            if len(pred_list) != num_samples:
                self.logger.warning("Modelo {} tem {} predições, esperado {}".format(
                    model_name, len(pred_list), num_samples
                ))
        
        final_predictions = []
        
        for i in range(num_samples):
            weighted_sum = 0.0
            total_weight = 0.0
            
            for model_name, pred_list in predictions.items():
                if i < len(pred_list):
                    weight = self.accuracies.get(model_name, 1.0)
                    weighted_sum += pred_list[i] * weight
                    total_weight += weight
            
            if total_weight > 0:
                avg_vote = weighted_sum / total_weight
                final_prediction = 1 if avg_vote > self.classification_threshold else 0
            else:
                final_prediction = 0
                
            final_predictions.append(final_prediction)
        
        return final_predictions
    
    def block_traffic(self, dpid, eth_src, eth_dst, in_port):
        if eth_src in self.blocked_sources:
            last_block = self.blocked_sources[eth_src]
            if time.time() - last_block < self.block_cooldown:
                self.logger.debug("Origem {} já bloqueada recentemente".format(eth_src))
                return 

        flow_rule = {
            "dpid": dpid,
            "priority": 100,
            "match": {
                "in_port": in_port,
                "eth_src": eth_src,
                "eth_dst": eth_dst
            },
            "actions": []
        }
        try:
            response = requests.post(self.block_url, json=flow_rule)
            if response.status_code == 200:
                self.logger.info("Successfully blocked traffic from {} to {}".format(eth_src, eth_dst))
            else:
                self.logger.error("Failed to block traffic: {} {}".format(response.status_code, response.text))
        except Exception as e:
            self.logger.error("Error sending block rule: {}".format(e))