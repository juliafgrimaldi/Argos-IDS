import pandas as pd
import numpy as np
import ipaddress
import hashlib

def safe_hash(value):
    """Converte IPs e IDs em inteiros consistentes."""
    if pd.isna(value):
        return 0
    s = str(value)
    try:
        return int(ipaddress.ip_address(s))
    except ValueError:
        return int(hashlib.sha1(s.encode()).hexdigest(), 16) % (10**8)

def predict_knn(model_bundle, filename):
    try:
        df = pd.read_csv(filename)
        if df.empty:
            raise ValueError("O arquivo de predição está vazio.")

        model = model_bundle["model"]
        scaler = model_bundle.get("scaler", None)
        numeric_columns = model_bundle.get("numeric_columns", [])
        categorical_columns = model_bundle.get("categorical_columns", [])

        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        for col in ["flow_id", "ip_src", "ip_dst"]:
            if col in df.columns:
                df[col] = df[col].apply(safe_hash)

        for col in df.select_dtypes(include=["object", "category"]).columns:
            df[col] = df[col].astype(str).astype("category").cat.codes

        df.fillna(0, inplace=True)

        if scaler and len(numeric_columns) > 0:
            cols_comuns = [c for c in numeric_columns if c in df.columns]
            if cols_comuns:
                df[cols_comuns] = scaler.transform(df[cols_comuns])

        predictions = model.predict(df)
        df["prediction"] = predictions

        return predictions, df

    except Exception as e:
        print(f"[KNN] Erro na predição: {e}")
        import traceback
        traceback.print_exc()
        raise
