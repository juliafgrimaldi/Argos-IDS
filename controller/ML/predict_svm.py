import pandas as pd
import numpy as np

def predict_svm(model_bundle, filename):
    df = pd.read_csv(filename)

    if df.empty:
        raise ValueError("O arquivo de predição está vazio.")

    model = model_bundle['model']
    selector = model_bundle['selector']
    encoder = model_bundle['encoder']
    imputer = model_bundle['imputer']
    scaler = model_bundle['scaler']
    numeric_columns = model_bundle['numeric_columns']
    categorical_columns = model_bundle['categorical_columns']

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

    X_num = imputer.transform(df_numeric)
    X_num_scaled = scaler.transform(X_num)

    X_cat = encoder.transform(df_categorical)

    if hasattr(X_cat, "toarray"):
        X_cat = X_cat.toarray()

    X = np.hstack([X_num, X_cat])

    X_scaled = scaler.transform(X)
    X_cat_df = pd.DataFrame(X_cat, columns=encoder.get_feature_names_out(categorical_columns))

    # Concatenar numéricas + categóricas
    X_full = pd.concat([pd.DataFrame(X_num_scaled, columns=numeric_columns), X_cat_df], axis=1)

    X_selected = selector.transform(X_full)


    predictions = model.predict(X_selected)

    df["prediction"] = predictions
    return predictions, df
