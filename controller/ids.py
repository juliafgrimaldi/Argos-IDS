import pickle
import os
import time
import requests
import pandas as pd
import math
import sqlite3
from ryu.base import app_manager
from ryu.lib import hub
from sklearn import set_config
from ML.predict_knn import predict_knn
from ML.predict_svm import predict_svm
from ML.predict_decision_tree import predict_decision_tree
from ML.predict_naive_bayes import predict_naive_bayes
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
            self.numeric_columns = ['packets', 'bytes', 'duration_sec']
            self.categorical_columns = ['dpid', 'in_port', 'eth_src', 'eth_dst']
            self.models = {}
            global ryu_instance
            ryu_instance = self
            
            self.start_time = time.time()
            self.logger.info("IDS iniciado em timestamp: {}".format(self.start_time))

            self.classification_threshold = 0.5
            
            self.accuracies = {
                "decision_tree": 0.97,
                "knn": 0.97,
                "naive_bayes": 0.70,
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
            time REAL,
            dpid INTEGER,
            in_port INTEGER,
            eth_src TEXT,
            eth_dst TEXT,
            packets INTEGER,
            bytes INTEGER,
            duration_sec INTEGER,
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
                    time, dpid, in_port, eth_src, eth_dst, packets, bytes, duration_sec, prediction_score, label
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row.get("time", time.time()),
                    int(row["dpid"]),
                    int(row["in_port"]),
                    row["eth_src"],
                    row["eth_dst"],
                    packets,
                    bytes,
                    duration_sec,
                    float(prediction_score),
                    1 if label else 0
            ))
            else:
                cursor.execute("""
                INSERT INTO flows (
                    time, dpid, in_port, eth_src, eth_dst, packets, bytes, duration_sec, label
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row.get("time", time.time()),
                    int(row["dpid"]),
                    int(row["in_port"]),
                    row["eth_src"],
                    row["eth_dst"],
                    packets,
                    bytes,
                    duration_sec,
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
                with open("models/{}_model_bundle.pkl".format(name), "rb") as f:
                    return pickle.load(f)
            except Exception as e:
                self.logger.error("Erro ao carregar modelo {}: {}".format(name, e))
                return None

        model_files = {
            'decision_tree': 'dt',
            'knn': 'knn',
            'naive_bayes': 'nb',
            'random_forest': 'randomforest',
            'svm': 'svm'
        }
        
        for model_name, file_name in model_files.items():
            model_path = "models/{}_model_bundle.pkl".format(file_name)
            if os.path.exists(model_path):
                model = load_bundle(file_name)
                if model is not None:
                    self.models[model_name] = model
                    self.logger.info("Modelo {} carregado com sucesso".format(model_name))
            else:
                self.logger.warning("Arquivo de modelo não encontrado: {}".format(model_path))

    def _initialize_csv(self):
        df = pd.DataFrame(columns=[
            'time', 'dpid', 'in_port', 'eth_src', 'eth_dst',
            'packets', 'bytes', 'duration_sec'
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

            for stat in flow_stats:
                match = stat.get('match', {})
                eth_src = match.get('dl_src', 'NULL')
                eth_dst = match.get('dl_dst', 'NULL')
                in_port = match.get('in_port', 'NULL')
                packets = stat.get('packet_count', 0)
                bytes_count = stat.get('byte_count', 0)
                duration_sec = stat.get('duration_sec', 0)
                timestamp = time.time()

                if len(rows) < 3:
                    self.logger.info("Flow sample: packets={}, bytes={}, duration={}, eth_src={}, eth_dst={}".format(
                        packets, bytes_count, duration_sec, eth_src, eth_dst
                    ))

                rows.append({
                    'time': timestamp,
                    'dpid': dpid,
                    'in_port': in_port,
                    'eth_src': eth_src,
                    'eth_dst': eth_dst,
                    'packets': packets,
                    'bytes': bytes_count,
                    'duration_sec': duration_sec
                })

            if rows:
                pd.DataFrame(rows).to_csv(self.filename, mode='a', index=False, header=not os.path.exists(self.filename))
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

            df_new = df[df['time'] >= self.start_time].copy()
            if df_new.empty:
                self.logger.info("Nenhum tráfego novo desde a inicialização")
                return
            
            temp_filename = "./backend/temp_predict.csv"
            df_new.to_csv(temp_filename, index=False)

            self.logger.info("Iniciando predições para {} fluxos usando {} modelos".format(len(df), len(self.models)))
            predictions = {}
            valid_predictions = 0

            for name, bundle in self.models.items():
                try:
                    self.logger.info("Executando predição com modelo: {}".format(name))
                    
                    if name == 'knn':
                        pred, _ = predict_knn(bundle, temp_filename)
                    elif name == 'svm':
                        pred, _ = predict_svm(bundle, temp_filename)
                    elif name == 'decision_tree':
                        pred, _ = predict_decision_tree(bundle, temp_filename)
                    elif name == 'naive_bayes':
                        pred, _ = predict_naive_bayes(bundle, temp_filename)
                    elif name == 'random_forest':
                        pred, _ = predict_random_forest(bundle, temp_filename)
                    else:
                        continue
                    
                    if pred is not None and len(pred) > 0:
                        predictions[name] = pred
                        valid_predictions += 1
                        
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
            self.logger.info("RESULTADO FINAL: {} fluxos maliciosos de {} total ({:.1f}%)".format(
                total_malicious, total_flows, (total_malicious/total_flows)*100 if total_flows > 0 else 0
            ))

            for i, pred in enumerate(final_predictions):
                if i >= len(df):
                    break
                    
                row = df.iloc[i].copy()

                row["packets"] = int(row["packets"]) if pd.notna(row["packets"]) else 0
                row["bytes"] = int(row["bytes"]) if pd.notna(row["bytes"]) else 0
                row["duration_sec"] = int(row["duration_sec"]) if pd.notna(row["duration_sec"]) else 0
                row["dpid"] = int(row["dpid"]) if pd.notna(row["dpid"]) else 0
                row["in_port"] = int(row["in_port"]) if pd.notna(row["in_port"]) else 0
                row["eth_src"] = row["eth_src"] if pd.notna(row["eth_src"]) else "UNKNOWN"
                row["eth_dst"] = row["eth_dst"] if pd.notna(row["eth_dst"]) else "UNKNOWN"
                row["time"] = float(row["time"]) if pd.notna(row["time"]) else time.time()

                confidence_score = self._calculate_confidence_score(predictions, i) if len(predictions) > 1 else float(pred)
                
                self.save_flow(row, bool(pred), confidence_score)
                
                if pred == 1 and row["eth_src"] != "UNKNOWN" and row["eth_dst"] != "UNKNOWN":
                    self.logger.warning("FLUXO MALICIOSO DETECTADO (confiança: {:.3f}): dpid={}, src={}, dst={}, packets={}, bytes={}".format(
                        confidence_score, row['dpid'], row['eth_src'], row['eth_dst'], row['packets'], row['bytes']
                    ))
                    self.block_traffic(row['dpid'], row['eth_src'], row['eth_dst'], row['in_port'])
                else:
                    self.logger.debug("Fluxo benigno: packets={}, bytes={}".format(row['packets'], row['bytes']))

            df_remaining = df[df['time'] < self.start_time].copy()
            df_remaining.to_csv(self.filename, index=False)

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