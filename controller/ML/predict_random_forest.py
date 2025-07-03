import pandas as pd
import numpy as np

def predict_random_forest(model, selector, encoder, imputer, scaler, filename, numeric_columns, categorical_columns):
    df = pd.read_csv(filename)

    # Pré-processamento
    df_numeric = df[numeric_columns]
    df_categorical = df[categorical_columns].astype(str)

    X_num = imputer.transform(df_numeric)
    X_cat = encoder.transform(df_categorical)

    X = np.concatenate([X_num, X_cat], axis=1)
    X_selected = selector.transform(X)
    X_scaled = scaler.transform(X_selected)

    # Predição
    predictions = model.predict(X_scaled)
    return predictions, df
