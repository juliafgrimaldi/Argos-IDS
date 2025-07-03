import pickle
import os
import time
import requests
import pandas as pd
from ryu.base import app_manager
from ryu.lib import hub
from ML.predict_knn import predict_knn
from ML.predict_svm import predict_svm
from ML.predict_decision_tree import predict_decision_tree
from ML.predict_naive_bayes import predict_naive_bayes
from ML.predict_random_forest import predict_random_forest

class ControllerAPI(app_manager.RyuApp):
    _CONTEXTS = {}

    def __init__(self, *args, **kwargs):
        super(ControllerAPI, self).__init__(*args, **kwargs)
        self.api_url = "http://127.0.0.1:8080/stats/flow/"
        self.block_url = "http://127.0.0.1:8080/stats/flowentry/add"
        self.filename = "traffic_predict.csv"
        self.numeric_columns = ['packets', 'bytes', 'duration_sec']
        self.categorical_columns = ['dpid', 'in_port', 'eth_src', 'eth_dst']
        self.models = {}
        self.accuracies = {
            "decision_tree": 0.97,
            "knn": 0.97,
            "naive_bayes": 0.70,
            "random_forest": 0.97,
            "svm": 0.87,
        }

        self._load_models()
        self._initialize_csv()
        self.monitor_thread = hub.spawn(self._monitor)

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
            with open("models/{}_bundle.pkl".format(name), "rb") as f:
                return pickle.load(f)

        self.models['decision_tree'] = load_bundle('decision_tree')
        self.models['knn'] = load_bundle('knn')
        self.models['naive_bayes'] = load_bundle('naive_bayes')
        self.models['random_forest'] = load_bundle('random_forest')
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
            dpids = self.get_active_dpids()
            for dpid in dpids:
                self.collect_and_store_stats(dpid)
            self.predict_traffic()
            hub.sleep(10)

    def collect_and_store_stats(self, dpid):
        try:
            response = requests.get(f"{self.api_url}{dpid}")
            response.raise_for_status()
            flow_stats = response.json().get(str(dpid), [])
            rows = []

            for stat in flow_stats:
                match = stat.get('match', {})
                eth_src = match.get('eth_src', 'NULL')
                eth_dst = match.get('eth_dst', 'NULL')
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
                model = bundle['model']
                selector = bundle['selector']
                encoder = bundle['encoder']
                imputer = bundle['imputer']
                scaler = bundle['scaler']

                if name == 'knn':
                    pred, _ = predict_knn(model, selector, encoder, imputer, scaler, self.filename, self.numeric_columns, self.categorical_columns)
                elif name == 'svm':
                    pred, _ = predict_svm(model, selector, encoder, imputer, scaler, self.filename, self.numeric_columns, self.categorical_columns)
                elif name == 'decision_tree':
                    pred, _ = predict_decision_tree(model, selector, encoder, imputer, scaler, self.filename, self.numeric_columns, self.categorical_columns)
                elif name == 'naive_bayes':
                    pred, _ = predict_naive_bayes(model, selector, encoder, imputer, scaler, self.filename, self.numeric_columns, self.categorical_columns)
                elif name == 'random_forest':
                    pred, _ = predict_random_forest(model, selector, encoder, imputer, scaler, self.filename, self.numeric_columns, self.categorical_columns)

                predictions[name] = pred

            final_predictions = self.weighted_vote(predictions)
            for i, pred in enumerate(final_predictions):
                if pred == 1:
                    row = df.iloc[i]
                    self.block_traffic(int(row['dpid']), row['eth_src'], row['eth_dst'], int(row['in_port']))
                    self.logger.warning("Blocked malicious flow: {}".format(row.to_dict()))

        except Exception as e:
            self.logger.error("Prediction error: {}".format(e))

    def weighted_vote(self, predictions):
        votes = {}
        for model_name, pred_list in predictions.items():
            weight = self.accuracies.get(model_name, 1.0)
            for i, pred in enumerate(pred_list):
                votes.setdefault(i, 0)
                votes[i] += pred * weight
        return [1 if v > 2.5 else 0 for v in votes.values()]

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
