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
            label BOOLEAN
        )
        """)
        conn.commit()
        conn.close()


    def save_flow(self, row, label: bool):
        try:
            conn = sqlite3.connect("traffic.db")
            cursor = conn.cursor()
            packets = row.get("packets", 0)
            bytes = row.get("bytes", 0)
            duration_sec = row.get("duration_sec", 0)
            packets = int(packets) if packets == packets else 0
            bytes = int(bytes) if bytes == bytes else 0
            duration_sec = int(duration_sec) if duration_sec == duration_sec else 0
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
            return response.json()  # Lista de dpids
        except Exception as e:
            self.logger.error("Erro ao buscar switches ativos: {}".format(e))
        return []

    def _load_models(self):
        self.logger.info("Loading bundled models from pickle...")
        def load_bundle(name):
            with open("models/{}_model_bundle.pkl".format(name), "rb") as f:
                return pickle.load(f)

        self.models['decision_tree'] = load_bundle('dt')
        self.models['knn'] = load_bundle('knn')
        self.models['naive_bayes'] = load_bundle('nb')
        self.models['random_forest'] = load_bundle('randomforest')
        self.models['svm'] = load_bundle('svm')

    def _initialize_csv(self):
        if not os.path.exists(self.filename):
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

        except Exception as e:
            self.logger.error("Failed to collect stats for dpid {}: {}".format(dpid, e))

    def predict_traffic(self):
        try:
            df = pd.read_csv(self.filename)
            predictions = {}

            for name, bundle in self.models.items():

                if name == 'knn':
                    pred, _ = predict_knn(bundle, self.filename)
                elif name == 'svm':
                    pred, _ = predict_svm(bundle, self.filename)
                elif name == 'decision_tree':
                    pred, _ = predict_decision_tree(bundle, self.filename)
                elif name == 'naive_bayes':
                    pred, _ = predict_naive_bayes(bundle, self.filename)
                elif name == 'random_forest':
                    pred, _ = predict_random_forest(bundle, self.filename)

                predictions[name] = pred

            final_predictions = self.weighted_vote(predictions)
            for i, pred in enumerate(final_predictions):
                row = df.iloc[i]

                row["packets"] = int(row["packets"]) if pd.notna(row["packets"]) else 0
                row["bytes"] = int(row["bytes"]) if pd.notna(row["bytes"]) else 0
                row["duration_sec"] = int(row["duration_sec"]) if pd.notna(row["duration_sec"]) else 0
                row["dpid"] = int(row["dpid"]) if pd.notna(row["dpid"]) else 0
                row["in_port"] = int(row["in_port"]) if pd.notna(row["in_port"]) else 0
                row["eth_src"] = row["eth_src"] if pd.notna(row["eth_src"]) else "UNKNOWN"
                row["eth_dst"] = row["eth_dst"] if pd.notna(row["eth_dst"]) else "UNKNOWN"
                row["time"] = float(row["time"]) if pd.notna(row["time"]) else time.time()

                self.save_flow(row, bool(pred))
                if pred == 1:
                    self.block_traffic(row['dpid'], row['eth_src'], row['eth_dst'], row['in_port'])
                    self.logger.warning("Blocked malicious flow: {}".format(row.to_dict()))
                else:
                    self.logger.info("Benign flow: {}".format(row.to_dict()))

        except Exception as e:
            self.logger.error("Prediction error: {}".format(e))

    def weighted_vote(self, predictions):
        votes = {}
        weights = {}
        for model_name, pred_list in predictions.items():
            weight = self.accuracies.get(model_name, 1.0)
            for i, pred in enumerate(pred_list):
                votes.setdefault(i, 0.0)
                weights.setdefault(i, 0.0)
                votes[i] += pred * weight
                weights[i] += weight

        final_predictions = []
        for i in range(len(votes)):
            if weights[i] > 0:
                avg_vote = votes[i] / weights[i]
            else:
                avg_vote = 0
            final_predictions.append(1 if avg_vote > 0.5 else 0)

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

