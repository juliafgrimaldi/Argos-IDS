import pandas as pd
import numpy as np

def predict_random_forest(model, selector, encoder, imputer, scaler, filename, numeric_columns, categorical_columns):
    df = pd.read_csv(filename)
    all_columns = ['time', 'dpid', 'in_port', 'eth_src', 'eth_dst', 'packets', 'bytes', 'duration_sec']
    df_full = df[all_columns]
    print(df_full.dtypes)
    # Pré-processamento
    df_numeric = df_full[numeric_columns]
    df_categorical = df_full[categorical_columns].astype(str)
    print("Numeric columns:", numeric_columns)
    print("Categorical columns:", categorical_columns)
    print("Dtypes in df_full:\n", df_full.dtypes)
    X_num = imputer.transform(df_numeric)
    X_cat = encoder.transform(df_categorical)

    X = np.concatenate([X_num, X_cat], axis=1)
    X_selected = selector.transform(X)
    X_scaled = scaler.transform(X_selected)

    # Predição
    predictions = model.predict(X_scaled)
    return predictions, df
