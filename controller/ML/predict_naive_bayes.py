import pandas as pd
import numpy as np

def predict_naive_bayes(model_bundle, filename):
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

    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    for col in numeric_columns:
        if col not in df.columns:
            df[col] = 0
    for col in categorical_columns:
        if col not in df.columns:
            df[col] = "unknown"

    X_num = imputer.transform(df[numeric_columns])
    X_num_scaled = scaler.transform(X_num)

    X_cat = encoder.transform(df[categorical_columns].astype(str))
    X_cat_df = pd.DataFrame(X_cat, columns=encoder.get_feature_names_out(categorical_columns))

    X_full = pd.concat([pd.DataFrame(X_num_scaled, columns=numeric_columns), X_cat_df], axis=1)

    X_selected = selector.transform(X_full)

    predictions = model.predict(X_selected)

    df["prediction"] = predictions
    return predictions, df
