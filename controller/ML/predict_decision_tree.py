import pandas as pd
import numpy as np

def predict_decision_tree(model_bundle, filename):
    try:
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
                print(f"[DT] Coluna numérica ausente '{col}' - preenchida com 0")

        for col in categorical_columns:
            if col not in df.columns:
                df[col] = "unknown"
                print(f"[DT] Coluna categórica ausente '{col}' - preenchida com 'unknown'")

        df = df.reindex(columns=numeric_columns + categorical_columns, fill_value=np.nan)

        df[categorical_columns] = df[categorical_columns].fillna("unknown")

        for col_idx, col in enumerate(categorical_columns):
            categorias_treinadas = set(encoder.categories_[col_idx])
            df[col] = np.where(
                df[col].isin(categorias_treinadas),
                df[col],
                'unknown'
            )

        X_num = imputer.transform(df[numeric_columns])
        X_num_scaled = scaler.transform(X_num)

        X_cat = encoder.transform(df[categorical_columns].astype(str))
        X_cat_df = pd.DataFrame(
            X_cat,
            columns=encoder.get_feature_names_out(categorical_columns),
            index=df.index
        )

        X_full = pd.concat([
            pd.DataFrame(X_num_scaled, columns=numeric_columns, index=df.index),
            X_cat_df
        ], axis=1)

        X_selected = selector.transform(X_full)

        predictions = model.predict(X_selected)

        print(f"[DT] Formato após seleção: {X_selected.shape}")
        unique, counts = np.unique(predictions, return_counts=True)
        print(f"[DT] Predições únicas: {dict(zip(unique, counts))}")

        df["prediction"] = predictions
        return predictions, df

    except Exception as e:
        print(f"[Decision Tree] Erro na predição: {e}")
        import traceback
        traceback.print_exc()
        raise
