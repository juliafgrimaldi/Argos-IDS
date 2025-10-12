
from sklearn.metrics import accuracy_score
import pandas as pd
import numpy as np
import pickle
import os
from ryu.base import app_manager

class ControllerAPI(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(ControllerAPI, self).__init__(*args, **kwargs)
        self.models = {}
        self.accuracies = {
            "decision_tree": 0.97,
            "knn": 0.97,
            "random_forest": 0.97,
            "svm": 0.87,
        }
        self._load_models()
        self._initialize_csv()

    def evaluate_model(self, model_name, model, X_test, y_test):
        try:
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            self.logger.info("Modelo {} avaliado com precisao: {}".format(model_name, accuracy:.3f))
            self.accuracies[model_name] = accuracy
        except Exception as e:
            self.logger.error("Erro na avaliacao do modelo {}: {}".format(model_name, e))

    def evaluate_all_models(self, test_data):
        X_test = test_data.drop(columns=['label'])
        y_test = test_data['label']
        
        for model_name, model in self.models.items():
            self.evaluate_model(model_name, model, X_test, y_test)

    def update_model_accuracies(self, test_data):
        self.logger.info("Atualizando acuracia dos modelos...")
        self.evaluate_all_models(test_data)

    def _load_models(self):
        model_files = {
            'decision_tree': 'dt',
            'knn': 'knn',
            'random_forest': 'randomforest',
            'svm': 'svm'
        }
        
        for model_name, file_name in model_files.items():
            model_path = "mdls/{}_model_bundle.pkl".format(file_name)
            if os.path.exists(model_path):
                with open(model_path, "rb") as f:
                    model = pickle.load(f)
                    self.models[model_name] = model
                    self.logger.info("Modelo {} carregado com sucesso".format(model_name))
            else:
                self.logger.warning("Arquivo de modelo nao encontrado: {}".format(model_path))

    def _initialize_csv(self):
        columns = [
            'timestamp', 'datapath_id', 'flow_id', 'ip_src', 'tp_src', 
            'ip_dst', 'tp_dst', 'ip_proto', 'icmp_code', 'icmp_type',
            'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout',
            'hard_timeout', 'flags', 'packet_count', 'byte_count',
            'packet_count_per_second', 'packet_count_per_nsecond',
            'byte_count_per_second', 'byte_count_per_nsecond'
        ]
        
        if os.path.exists(self.filename):
            try:
                existing_df = pd.read_csv(self.filename)
                if 'time' in existing_df.columns and 'timestamp' not in existing_df.columns:
                    existing_df.rename(columns={'time': 'timestamp'}, inplace=True)
                    existing_df.to_csv(self.filename, index=False)
                    self.logger.info("Coluna 'time' renomeada para 'timestamp'")
                return
            except:
                pass
        
        df = pd.DataFrame(columns=columns)
        df.to_csv(self.filename, index=False)
