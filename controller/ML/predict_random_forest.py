import pandas as pd
import numpy as np

def predict_random_forest(model, selector, encoder, imputer, scaler, filename, numeric_columns, categorical_columns):
    df = pd.read_csv(filename)

    if df.empty:
        raise ValueError("O arquivo de predição está vazio.")

    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    for col in numeric_columns:
        if col not in df.columns:
            df[col] = 0
    for col in categorical_columns:
        if col not in df.columns:
            df[col] = "unknown"

    df_numeric = df[numeric_columns].astype(float)
    df_categorical = df[categorical_columns].astype(str)

    print("Numeric columns:", numeric_columns)
    print("Categorical columns:", categorical_columns)
    print("Dtypes in df:\n", df.dtypes)

    X_num = imputer.transform(df_numeric)

    X_cat = encoder.transform(df_categorical)
    if hasattr(X_cat, "toarray"):  
        X_cat = X_cat.toarray()

    X = np.concatenate([X_num, X_cat], axis=1)

    X_scaled = scaler.transform(X)

    X_selected = selector.transform(X_scaled)

    predictions = model.predict(X_selected)

    df["prediction"] = predictions
    return predictions, df
