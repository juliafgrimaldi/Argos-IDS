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
        # Load models here
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
