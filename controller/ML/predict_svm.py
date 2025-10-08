import pandas as pd
import numpy as np

def predict_svm(model_bundle, filename):
    """
    Args:
        model_bundle: Dicionário com modelo e transformadores
        filename: Caminho do arquivo CSV com dados para predição
    
    Returns:
        predictions: Array numpy com predições (0 ou 1)
        df: DataFrame com coluna 'prediction' adicionada
    """
    try:
        df = pd.read_csv(filename)
        
        if df.empty:
            raise ValueError("O arquivo de predição está vazio.")
        
        # Extrair componentes do bundle
        model = model_bundle['model']
        selector = model_bundle['selector']
        encoder = model_bundle['encoder']
        imputer = model_bundle['imputer']
        scaler = model_bundle['scaler']
        numeric_columns = model_bundle['numeric_columns']
        categorical_columns = model_bundle['categorical_columns']
        
        # Substituir inf/-inf por NaN
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        
        # Garantir que todas as colunas necessárias existem
        for col in numeric_columns:
            if col not in df.columns:
                df[col] = 0
                print(f"[SVM] Coluna numérica ausente '{col}' - preenchida com 0")
        
        for col in categorical_columns:
            if col not in df.columns:
                df[col] = "unknown"
                print(f"[SVM] Coluna categórica ausente '{col}' - preenchida com 'unknown'")
        
        # Preencher NaN em categóricas
        df[categorical_columns] = df[categorical_columns].fillna("unknown")
        
        # Processar colunas numéricas
        X_num = imputer.transform(df[numeric_columns])
        X_num_scaled = scaler.transform(X_num)
        
        # Processar colunas categóricas
        X_cat = encoder.transform(df[categorical_columns].astype(str))
        X_cat_df = pd.DataFrame(
            X_cat, 
            columns=encoder.get_feature_names_out(categorical_columns),
            index=df.index
        )
        
        # Combinar features
        X_full = pd.concat([
            pd.DataFrame(X_num_scaled, columns=numeric_columns, index=df.index), 
            X_cat_df
        ], axis=1)
        
        # Selecionar features
        X_selected = selector.transform(X_full)
        
        # Fazer predição
        predictions = model.predict(X_selected)
        
        # Adicionar predições ao DataFrame
        df["prediction"] = predictions
        
        return predictions, df
        
    except Exception as e:
        print(f"[SVM] Erro na predição: {e}")
        import traceback
        traceback.print_exc()
        raise

