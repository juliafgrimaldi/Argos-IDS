import pandas as pd
import numpy as np

def predict_decision_tree(model, selector, encoder, imputer, scaler, filename, numeric_columns, categorical_columns):
    df = pd.read_csv(filename)

    if df.empty:
        raise ValueError("O arquivo de predição está vazio.")

    # Substituir inf por NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Garantir que todas as colunas categóricas existam
    for col in categorical_columns:
        if col not in df.columns:
            df[col] = "unknown"

    df[categorical_columns] = df[categorical_columns].fillna("unknown")

    # Garantir que todas as colunas numéricas existam
    for col in numeric_columns:
        if col not in df.columns:
            df[col] = 0

    df_numeric = df[numeric_columns]
    df_categorical = df[categorical_columns].astype(str)

    print("Numeric columns:", numeric_columns)
    print("Categorical columns:", categorical_columns)
    print("Dtypes in df:\n", df.dtypes)

    # 1. Imputação numérica
    X_num = imputer.transform(df_numeric)

    # 2. Codificação categórica
    X_cat = encoder.transform(df_categorical)

    # 3. Combinar numéricas + categóricas
    X = np.concatenate([X_num, X_cat], axis=1)

    # 4. Escalonar
    X_scaled = scaler.transform(X)

    # 5. Seleção de atributos
    X_selected = selector.transform(X_scaled)

    # 6. Predição
    predictions = model.predict(X_selected)

    df["prediction"] = predictions
    return predictions, df
