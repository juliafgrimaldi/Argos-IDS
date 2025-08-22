import pandas as pd
import numpy as np

def predict_random_forest(model, selector, encoder, imputer, scaler, filename, numeric_columns, categorical_columns):
    df = pd.read_csv(filename)

    if df.empty:
        raise ValueError("O arquivo de predição está vazio.")

    # Substituir inf/-inf por NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Garantir que TODAS as colunas do treino existam
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

    # 1. Imputar valores ausentes numéricos
    X_num = imputer.transform(df_numeric)

    # 2. Codificar categóricas
    X_cat = encoder.transform(df_categorical)

    # 3. Concatenar numéricas + categóricas
    X = np.concatenate([X_num, X_cat], axis=1)

    # 4. Escalar (antes da seleção!)
    X_scaled = scaler.transform(X)

    # 5. Seleção de atributos
    X_selected = selector.transform(X_scaled)

    # 6. Predição
    predictions = model.predict(X_selected)

    df["prediction"] = predictions
    return predictions, df
