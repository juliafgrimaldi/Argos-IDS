import pandas as pd
import numpy as np

def predict_svm(model, selector, encoder, imputer, scaler, filename, numeric_columns, categorical_columns):
    df = pd.read_csv(filename)

    if df.empty:
        raise ValueError("O arquivo de predição está vazio.")

    # Substituir inf/-inf por NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Garantir que TODAS as colunas usadas no treino existam
    for col in numeric_columns:
        if col not in df.columns:
            df[col] = 0
    for col in categorical_columns:
        if col not in df.columns:
            df[col] = "unknown"

    # Separar numéricas e categóricas
    df_numeric = df[numeric_columns]
    df_categorical = df[categorical_columns].astype(str)

    print("Numeric columns:", numeric_columns)
    print("Categorical columns:", categorical_columns)
    print("Dtypes in df:\n", df.dtypes)

    X_num = imputer.transform(df_numeric)

    X_cat = encoder.transform(df_categorical)

    if hasattr(X_cat, "toarray"):
        X_cat = X_cat.toarray()

    X = np.hstack([X_num, X_cat])

    X_scaled = scaler.transform(X)

    if selector is not None:
        X_selected = selector.transform(X_scaled)
    else:
        X_selected = X_scaled

    predictions = model.predict(X_selected)

    df["prediction"] = predictions
    return predictions, df
