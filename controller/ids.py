import pickle
import os
import time
import hashlib
import requests
import pandas as pd
import numpy as np
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
            
            self.last_processed_time = 0.0
            try:
                if os.path.exists(self.filename):
                    df = pd.read_csv(self.filename)
                    col = 'timestamp' if 'timestamp' in df.columns else 'time'
                    if col and not df.empty:
                        self.last_processed_time = float(df[col].max())
                        self.logger.info(f"Último timestamp processado: {self.last_processed_time}")
            except Exception as e:
                self.logger.warning(f"Não foi possível carregar last_processed_time: {e}")
            
            self.total_flows_processed = 0
            self.flow_last_seen = {}

            self.classification_threshold = 0.5
            
            self.accuracies = {
                "decision_tree": 1.0,
                "knn": 0.99,
                "random_forest": 0.97,
                "svm": 0.97,
            }

            self._load_models()
            self._initialize_csv()
            self._initialize_last_processed_time()
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
            label BOOLEAN,
            processed BOOLEAN,
            flow_hash TEXT           
        )
        """)
        conn.commit()
        conn.close()

    def _initialize_last_processed_time(self):
        self.last_processed_time = 0.0
        try:
            if os.path.exists(self.filename):
                df = pd.read_csv(self.filename)
                col = 'timestamp' if 'timestamp' in df.columns else ('time' if 'time' in df.columns else None)
                if col and not df.empty:
                    self.last_processed_time = float(pd.to_numeric(df[col], errors='coerce').max())
        except Exception as e:
            self.logger.warning(f"Não foi possivel inicializar last_processed_time: {e}")


    def _safe_int(self, val, default=0):
        try:
            return int(val) if pd.notna(val) and val == val else default
        except:
            return default
    
    def _safe_float(self, val, default=0.0):
        try:
            return float(val) if pd.notna(val) and val == val else default
        except:
            return default

    def save_flow(self, row, label: bool, prediction_score: float = 0.0):
        try:
            conn = sqlite3.connect("traffic.db")
            cursor = conn.cursor()

            flow_hash = row.get('flow_hash', self.generate_flow_hash(
                row['ip_src'], row['ip_dst'], row['tp_src'], row['tp_dst'], row['ip_proto']
            ))
            
            cursor.execute("""
            INSERT INTO flows (
                timestamp, datapath_id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                ip_proto, icmp_code, icmp_type, flow_duration_sec, flow_duration_nsec,
                idle_timeout, hard_timeout, flags, packet_count, byte_count,
                packet_count_per_second, packet_count_per_nsecond,
                byte_count_per_second, byte_count_per_nsecond,
                prediction_score, label, processed, flow_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self._safe_float(row.get("timestamp", time.time())),
                self._safe_int(row.get("datapath_id")),
                str(row.get("flow_id", "")),
                str(row.get("ip_src", "")),
                self._safe_int(row.get("tp_src")),
                str(row.get("ip_dst", "")),
                self._safe_int(row.get("tp_dst")),
                self._safe_int(row.get("ip_proto")),
                self._safe_int(row.get("icmp_code")),
                self._safe_int(row.get("icmp_type")),
                self._safe_int(row.get("flow_duration_sec")),
                self._safe_int(row.get("flow_duration_nsec")),
                self._safe_int(row.get("idle_timeout")),
                self._safe_int(row.get("hard_timeout")),
                self._safe_int(row.get("flags")),
                self._safe_int(row.get("packet_count")),
                self._safe_int(row.get("byte_count")),
                self._safe_float(row.get("packet_count_per_second")),
                self._safe_float(row.get("packet_count_per_nsecond")),
                self._safe_float(row.get("byte_count_per_second")),
                self._safe_float(row.get("byte_count_per_nsecond")),
                float(prediction_score),
                1 if label else 0,  
                1,
                str(flow_hash)
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
                    bundle = pickle.load(f)
                    
                # VALIDAR se o modelo está treinado
                if isinstance(bundle, dict):
                    model = bundle.get('model')
                    if model is not None:
                        # Verificar se tem o atributo que indica treinamento
                        if hasattr(model, 'classes_') or hasattr(model, 'n_features_in_'):
                            self.logger.info("Modelo {} validado - está treinado".format(name))
                            return bundle
                        else:
                            self.logger.error("Modelo {} NÃO ESTÁ TREINADO!".format(name))
                            return None
                    else:
                        self.logger.error("Bundle {} não contém 'model'".format(name))
                        return None
                else:
                    # Se não for dict, pode ser modelo direto
                    if hasattr(bundle, 'classes_') or hasattr(bundle, 'n_features_in_'):
                        self.logger.info("Modelo {} (formato direto) validado".format(name))
                        return {'model': bundle}
                    else:
                        self.logger.error("Modelo {} não está no formato correto".format(name))
                        return None
                        
            except Exception as e:
                self.logger.error("Erro ao carregar modelo {}: {}".format(name, e))
                import traceback
                self.logger.error("Traceback: {}".format(traceback.format_exc()))
                return None

        model_files = {
            'decision_tree': 'dt',
            'knn': 'knn',
            'random_forest': 'randomforest',
            'svm': 'svm'
        }
        
        loaded_count = 0
        for model_name, file_name in model_files.items():
            model_path = "mdls/{}_model_bundle.pkl".format(file_name)
            if os.path.exists(model_path):
                self.logger.info("Carregando: {}".format(model_path))
                model = load_bundle(file_name)
                if model is not None:
                    self.models[model_name] = model
                    loaded_count += 1
                    self.logger.info("✓ Modelo {} carregado e validado".format(model_name))
                else:
                    self.logger.error("✗ Modelo {} FALHOU na validação".format(model_name))
            else:
                self.logger.warning("Arquivo não encontrado: {}".format(model_path))
        
        if loaded_count == 0:
            self.logger.error("CRÍTICO: NENHUM MODELO VÁLIDO CARREGADO!")
        else:
            self.logger.info("Total de modelos válidos carregados: {}".format(loaded_count))

    def _initialize_csv(self):
        columns = [
            'timestamp', 'datapath_id', 'flow_id', 'flow_hash', 'ip_src', 'tp_src', 
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

    def _monitor(self):
        while True:
            try:
                try:
                    resp = requests.get("http://127.0.0.1:8000/api/config/mode", timeout=2)
                    if resp.status_code == 200:
                        self.mitigation_mode = resp.json().get("mode", "block")
                except Exception as e:
                    self.logger.warning(f"Falha ao sincronizar modo com painel: {e}")

                self.logger.info(f"[Modo atual de mitigação: {self.mitigation_mode.upper()}]")
                dpids = self.get_active_dpids()
                self.logger.info(f"DPIDs ativos: {dpids}")
                for dpid in dpids:
                    self.collect_and_store_stats(dpid)
                self.predict_traffic()
                hub.sleep(10)
            except Exception as e:
                self.logger.error(f"Erro no monitoramento: {e}")

    def generate_flow_hash(self, ip_src, ip_dst, tp_src, tp_dst, ip_proto):
        flow_string = f"{ip_src}-{ip_dst}-{tp_src}-{tp_dst}-{ip_proto}"
        return hashlib.sha256(flow_string.encode()).hexdigest()

    def is_flow_updated(self, flow_hash, packet_count, byte_count):
        if flow_hash not in self.flow_last_seen:
            return True
    
        last_state = self.flow_last_seen[flow_hash]
    
        if (packet_count > last_state['packet_count'] or 
            byte_count > last_state['byte_count']):
            return True
    
        return False
        
    def update_flow_state(self, flow_hash, packet_count, byte_count, timestamp):
        self.flow_last_seen[flow_hash] = {
            'packet_count': packet_count,
            'byte_count': byte_count,
            'timestamp': timestamp
        }

    def collect_and_store_stats(self, dpid):
        try:
            self.logger.info("Coletando stats do DPID {}".format(dpid))
            response = requests.get("{}{}".format(self.api_url, dpid), timeout=10)
            response.raise_for_status()
            flow_stats = response.json().get(str(dpid), [])
            
            self.logger.info("=== API RETORNOU {} FLUXOS BRUTOS ===".format(len(flow_stats)))
            
            rows = []
            current_time = time.time()
            flows_with_ip = 0
            flows_filtered_empty = 0
            flows_filtered_volumetric = 0
            flows_skipped_no_update = 0

            for stat in flow_stats:
                match = stat.get('match', {})
                
                ip_src = match.get('ipv4_src', match.get('nw_src', '0.0.0.0'))
                ip_dst = match.get('ipv4_dst', match.get('nw_dst', '0.0.0.0'))
                if ip_src != '0.0.0.0' and ip_dst != '0.0.0.0':
                    flows_with_ip += 1
                tp_src = match.get('tcp_src', match.get('tcp_src', match.get('tp_src', 0)))
                tp_dst = match.get('tcp_dst', match.get('tcp_dst', match.get('tp_dst', 0)))
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

                flow_hash = self.generate_flow_hash(ip_src, ip_dst, tp_src, tp_dst, ip_proto)

                #if not self.is_flow_updated(flow_hash, packet_count, byte_count):
                #    flows_skipped_no_update += 1
                #    self.logger.debug("Fluxo {} não teve mudanças (packets={}, bytes={})".format(
                #        flow_hash[:16], packet_count, byte_count
                #    ))
                #    continue

                total_duration_sec = duration_sec + (duration_nsec / 1e9)
                
                if total_duration_sec < 0.001:
                    total_duration_sec = 0.001
                
                packet_count_per_second = packet_count / total_duration_sec
                byte_count_per_second = byte_count / total_duration_sec
                
                total_duration_nsec = (duration_sec * 1e9) + duration_nsec
                if total_duration_nsec < 1000:
                    total_duration_nsec = 1000
                    
                packet_count_per_nsecond = packet_count / total_duration_nsec
                byte_count_per_nsecond = byte_count / total_duration_nsec

                if packet_count_per_second > 10000:
                    self.logger.warning("Bloqueio heurístico - ATAQUE VOLUMÉTRICO DETECTADO: {} pps".format(packet_count_per_second))
                    self.block_traffic(dpid, ip_src, ip_dst, in_port)
                    flows_filtered_volumetric += 1
                    continue

                flow_id = "{}{}{}{}{}".format(ip_src, tp_src, ip_dst, tp_dst, ip_proto)

                self.update_flow_state(flow_hash, packet_count, byte_count, current_time)

                rows.append({
                    'timestamp': current_time,
                    'datapath_id': dpid,
                    'flow_id': flow_id,
                    'flow_hash': flow_hash,
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
                df_to_save = pd.DataFrame(rows)
                self.logger.info("=== RESUMO DA COLETA ===")
                self.logger.info("API retornou: {} fluxos".format(len(flow_stats)))
                self.logger.info("Filtrados (vazios): {}".format(flows_filtered_empty))
                self.logger.info("Filtrados (volumétricos): {}".format(flows_filtered_volumetric))
                self.logger.info("Flows com IPs válidos: {}".format(flows_with_ip))
                self.logger.info("✓ SALVOS NO CSV: {} flows - Timestamp: {:.2f}".format(
                    len(rows), current_time
                ))
                self.logger.info("========================")
                
                file_exists = os.path.exists(self.filename)
                
                if file_exists:
                    try:
                        existing_df = pd.read_csv(self.filename, nrows=0)
                        if 'time' in existing_df.columns and 'timestamp' not in existing_df.columns:
                            existing_df = pd.read_csv(self.filename)
                            existing_df.rename(columns={'time': 'timestamp'}, inplace=True)
                            existing_df.to_csv(self.filename, index=False)
                            self.logger.info("CSV atualizado: 'time' -> 'timestamp'")
                    except Exception as ex:
                        self.logger.warning("Erro ao verificar CSV: {}".format(ex))
                
                df_to_save.to_csv(self.filename, mode='a', index=False, header=not file_exists)
            else:
                self.logger.warning("=== NENHUM FLUXO VÁLIDO PARA SALVAR ===")
                self.logger.warning("API retornou: {} fluxos".format(len(flow_stats)))
                self.logger.warning("Todos foram filtrados: vazios={}, volumétricos={}".format(
                    flows_filtered_empty, flows_filtered_volumetric
                ))

        except Exception as e:
            self.logger.error("Failed to collect stats for dpid {}: {}".format(dpid, e))
            import traceback
            self.logger.error("Traceback: {}".format(traceback.format_exc()))

    def predict_traffic(self):
        try:
            if not os.path.exists(self.filename):
                self.logger.warning("CSV file doesn't exist yet")
                return
                
            df = pd.read_csv(self.filename)
            if df.empty:
                self.logger.info("No data for prediction")
                return

            time_column = 'timestamp' if 'timestamp' in df.columns else 'time'
            df[time_column] = pd.to_numeric(df[time_column], errors='coerce')

            cur_min = float(df[time_column].min())
            cur_max = float(df[time_column].max())
            self.logger.info(f"[DEBUG] last_processed_time={self.last_processed_time:.2f} | csv.min={cur_min:.2f} csv.max={cur_max:.2f}")

            df_unprocessed = df[df[time_column] > float(self.last_processed_time)].copy()
            self.logger.info(f"[DEBUG] novos={len(df_unprocessed)}")
            
            cols_to_drop = ['flow_hash']
            df_unprocessed.drop(columns=[c for c in cols_to_drop if c in df_unprocessed.columns], inplace=True)

            if df_unprocessed.empty:
                self.logger.info("Nenhum tráfego novo para predição")
                return
            
            self.logger.info("PROCESSANDO {} NOVOS FLUXOS (timestamps: {:.2f} a {:.2f})".format(
                len(df_unprocessed),
                df_unprocessed[time_column].min(),
                df_unprocessed[time_column].max()
            ))

            temp_filename = "./backend/temp_predict.csv"
            df_unprocessed.to_csv(temp_filename, index=False)

            self.logger.info("Iniciando predições para {} fluxos usando {} modelos".format(
                len(df_unprocessed), len(self.models)
            ))
            predictions = {}

            for name, bundle in self.models.items():
                try:
                    self.logger.info("Executando predição com modelo: {}".format(name))
                    
                    # Verificar se modelo está carregado corretamente
                    if bundle is None:
                        self.logger.error("Bundle do modelo {} está None!".format(name))
                        continue
                    
                    if name == 'knn':
                        pred, _ = predict_knn(bundle, temp_filename)
                        print("\nDistribuição das predições:", pd.Series(pred).value_counts())
                        print("Exemplo das primeiras 5 linhas:")
                        print(_[['prediction']].head())
                    #elif name == 'svm':
                    #    pred, _ = predict_svm(bundle, temp_filename)
                    #elif name == 'decision_tree':
                    #    pred, _ = predict_decision_tree(bundle, temp_filename)
                    #elif name == 'random_forest':
                    #    pred, _ = predict_random_forest(bundle, temp_filename)
                    else:
                        self.logger.warning("Modelo desconhecido: {}".format(name))
                        continue
                    
                    if pred is not None and len(pred) > 0:
                        predictions[name] = pred
                        
                        malicious_count = np.count_nonzero(pred==0)
                        benign_count = np.count_nonzero(pred == 1)
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

            arr = np.array(final_predictions)
            num_malicious = np.count_nonzero(arr == 0)
            total_flows = len(arr)
            percentage_malicious = (num_malicious/total_flows)*100 if total_flows > 0 else 0
            self.logger.info(f"RESULTADO FINAL: {num_malicious} fluxos maliciosos de {total_flows} total ({100*num_malicious/total_flows:.1f}%)")
        

            if percentage_malicious > 80 and total_flows > 10:
                self.logger.error("ALERTA: Taxa de detecção suspeita ({:.1f}%)!".format(percentage_malicious))

            blocked_count = 0
            for i, pred in enumerate(final_predictions):
                if i >= len(df_unprocessed):
                    break
                    
                row = df_unprocessed.iloc[i].to_dict()
                is_normal = bool(pred)           
                is_malicious = not is_normal   
                confidence_score = self._calculate_confidence_score(predictions, i) if len(predictions) > 1 else float(pred)
                
                self.save_flow(row, is_normal, confidence_score)
                
                if is_malicious:
                    blocked_count += 1
                    self.logger.warning("FLUXO MALICIOSO DETECTADO (confiança: {:.3f}): dpid={}, src={}, dst={}, packets={}".format(
                        confidence_score, row['datapath_id'], row['ip_src'], row['ip_dst'], row['packet_count']
                    ))
                    self.block_traffic(row['datapath_id'], row['ip_src'], row['ip_dst'], 0)

            self.last_processed_time =  float(df_unprocessed[time_column].max())
            self.total_flows_processed += len(df_unprocessed)
            
            self.logger.info("Timestamp de processamento atualizado para: {:.2f} (total acumulado: {})".format(
                self.last_processed_time, self.total_flows_processed
            ))

            if blocked_count > 0:
                self.logger.warning("BLOQUEIOS NESTE CICLO: {}".format(blocked_count))
            else:
                self.logger.info("Nenhum bloqueio - todos os {} novos fluxos são benignos".format(total_flows))

        except Exception as e:
            self.logger.error("Prediction error: {}".format(e))
            import traceback
            self.logger.error("Traceback: {}".format(traceback.format_exc()))

    def _calculate_confidence_score(self, predictions, index):
        if not predictions or index >= len(list(predictions.values())[0]):
            return 0.0
            
        weighted_sum = 0
        total_weight = 0
        
        for model_name, pred_list in predictions.items():
            if index < len(pred_list):
                weight = self.accuracies.get(model_name, 1.0)
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

    def save_block_in_db(self, dpid, ip_src, ip_dst, reason="Automatic IDS block"):
        try:
            conn = sqlite3.connect("traffic.db")
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS blocked_flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dpid INTEGER NOT NULL,
                    ip_src TEXT NOT NULL,
                    ip_dst TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    reason TEXT DEFAULT 'IDS block',
                    active BOOLEAN DEFAULT 1
                )
            """)

            cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS ux_block
            ON blocked_flows(dpid, ip_src, ip_dst, active)
            """)

            cur.execute(
                "INSERT INTO blocked_flows (dpid, ip_src, ip_dst, timestamp, reason, active) VALUES (?, ?, ?, ?, ?, 1) ON CONFLICT(dpid, ip_src, ip_dst, active) DO UPDATE SET timestamp=excluded.timestamp, reason=excluded.reason", 
                (dpid, ip_src, ip_dst, time.time(), reason, 1)
        )
            conn.commit()
            conn.close()
            self.logger.info(f" Bloqueio salvo no banco: {ip_src} -> {ip_dst}")
        except Exception as e:
            self.logger.error(f"Erro ao salvar bloqueio no banco: {e}")

    
    def block_traffic(self, dpid, ip_src, ip_dst, in_port):
        self.logger.info("="*60)
        self.logger.info("TENTATIVA DE BLOQUEIO")
        self.logger.info("="*60)
        self.logger.info("dpid: {} (tipo: {})".format(dpid, type(dpid)))
        self.logger.info("ip_src: {} (tipo: {})".format(ip_src, type(ip_src)))
        self.logger.info("ip_dst: {} (tipo: {})".format(ip_dst, type(ip_dst)))
        self.logger.info("block_url: {}".format(self.block_url))
        key = (int(dpid), str(ip_src), str(ip_dst))
        if key in self.blocked_sources:
            last_block = self.blocked_sources[ip_src]
            if time.time() - last_block < self.block_cooldown:
                self.logger.debug("Origem {} já bloqueada recentemente".format(ip_src))
                return 

        try:
            dpid = int(dpid)
        except (ValueError, TypeError) as e:
            self.logger.error("ERRO: dpid inválido: {} - {}".format(dpid, e))
            return
        
        ip_invalid = (
            not ip_src or ip_src == '0.0.0.0' or 
            not ip_dst or ip_dst == '0.0.0.0'
        )
        
        if ip_invalid:
            self.logger.error(
            f"ERRO: IPs e MACs inválidos — impossível bloquear: src={ip_src}, dst={ip_dst}"
        )
            return

        else:
            flow_rule = {
                "dpid": dpid,
                "priority": 65535,
                "match": {
                    "eth_type": 2048,
                    "ipv4_src": ip_src,
                    "ipv4_dst": ip_dst
            },
            "actions": []
        }

        self.logger.info("Regra a ser enviada:")
        self.logger.info("  {}".format(flow_rule))


        try:
            self.logger.info("Enviando POST para: {}".format(self.block_url))
            response = requests.post(self.block_url, json=flow_rule, timeout=5)
            
            self.logger.info("Resposta HTTP: {}".format(response.status_code))
            self.logger.info("Corpo da resposta: {}".format(response.text))
            
            if response.status_code == 200:
                self.logger.warning("✅ BLOQUEIO INSTALADO COM SUCESSO!")
                self.logger.warning("   {} -> {} no switch {} (priority=65535)".format(
                    ip_src, ip_dst, dpid
                ))
                self.blocked_sources[key] = time.time()
                self.save_block_in_db(dpid, ip_src, ip_dst, reason="IDS block")
            else:
                self.logger.error("❌ FALHA HTTP {}: {}".format(
                    response.status_code, response.text
                ))
                
        except requests.exceptions.Timeout:
            self.logger.error("❌ TIMEOUT ao conectar em {}".format(self.block_url))
        except requests.exceptions.ConnectionError as e:
            self.logger.error("❌ ERRO DE CONEXÃO: {}".format(e))
            self.logger.error("   Certifique-se que o Ryu REST está ativo")
        except Exception as e:
            self.logger.error("❌ ERRO INESPERADO: {}".format(e))
            import traceback
            self.logger.error(traceback.format_exc())
        
        self.logger.info("="*60)