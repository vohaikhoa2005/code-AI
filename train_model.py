import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix,
    precision_recall_curve, auc, recall_score, precision_score
)
import warnings
warnings.filterwarnings('ignore')


def load_and_preprocess_data(filepath='advanced_siem_dataset_with_labels.csv'):
    print("Loading dataset...")
    df = pd.read_csv(filepath)

    df = df.fillna("unknown")

    numeric_cols = ['duration', 'bytes', 'src_port', 'dst_port']

    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    return df


def validate_label_column(df):
    if "label" not in df.columns:
        raise ValueError("Dataset must include a 'label' column with SAFE/UNSAFE values.")

    if df["label"].dtype == object:
        df["label"] = df["label"].astype(str).str.strip().str.lower()
        df["label"] = df["label"].map({"safe": 0, "unsafe": 1, "0": 0, "1": 1})

    if not pd.api.types.is_integer_dtype(df["label"]):
        df["label"] = pd.to_numeric(df["label"], errors='coerce')

    if df["label"].isna().any():
        raise ValueError("Some labels could not be converted to 0/1; check 'label' column values.")

    unique_labels = set(df["label"].unique())
    if not unique_labels.issubset({0, 1}):
        raise ValueError(f"Unexpected label values found: {unique_labels}. Only 0/1 expected.")

    print(df["label"].value_counts())
    return df


def encode_categorical_features(df):

    categorical_cols = [
        'event_type', 'source', 'user', 'action', 'object',
        'process_id', 'parent_process',
        'device_type', 'device_id', 'firmware_version',
        'src_ip', 'dst_ip', 'signature_id',
        'cloud_service', 'resource_id',
        'protocol', 'method', 'mac_address',
        'data_access_time'  # Treat as categorical
    ]

    encoders_dict = {}

    for col in categorical_cols:
        if col in df.columns:

            df[col] = df[col].astype(str)
            df[col] = df[col].fillna("unknown")

            # ADD UNKNOWN TO TRAINING
            unique_vals = list(df[col].unique())
            if "unknown" not in unique_vals:
                unique_vals.append("unknown")

            encoder = LabelEncoder()
            encoder.fit(unique_vals)

            df[col] = encoder.transform(df[col])

            encoders_dict[col] = encoder

            print(f"{col} encoded ({len(encoder.classes_)})")

    joblib.dump(encoders_dict, "encoders_dict.pkl")

    return df, encoders_dict


def main():

    print("Training SIEM AI Model")

    df = load_and_preprocess_data()

    df = validate_label_column(df)

    df, encoders_dict = encode_categorical_features(df)

    expected_cols = [
        'source', 'user', 'action', 'object',
        'process_id', 'parent_process',
        'device_type', 'device_id',
        'firmware_version',
        'src_ip', 'dst_ip',
        'cloud_service', 'resource_id',
        'protocol', 'method', 'mac_address',
        'duration', 'data_access_time', 'bytes', 'src_port', 'dst_port'
    ]

    for col in expected_cols:
        if col not in df.columns:
            df[col] = 0

    X = df[expected_cols]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    scaler = StandardScaler()

    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    joblib.dump(scaler, "scaler.pkl")

    model = RandomForestClassifier(
        n_estimators=20,
        max_depth=3,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    joblib.dump(model, "siem_model.pkl")

    preds = model.predict(X_test)
    preds_proba = model.predict_proba(X_test)[:, 1]  # Get probability for class 1 (UNSAFE)

    acc = accuracy_score(y_test, preds)

    print("\n" + "="*60)
    print("MODEL EVALUATION")
    print("="*60)
    print("\n1. ACCURACY:")
    print(f"   Accuracy: {acc:.4f}")
    
    print("\n2. CLASSIFICATION REPORT:")
    print(classification_report(y_test, preds, target_names=['SAFE', 'UNSAFE']))
    
    print("\n3. CONFUSION MATRIX:")
    cm = confusion_matrix(y_test, preds)
    print(cm)
    print(f"   TN={cm[0,0]}, FP={cm[0,1]}, FN={cm[1,0]}, TP={cm[1,1]}")
    
    print("\n4. RECALL/PRECISION FOR CLASS 1 (UNSAFE):")
    recall_1 = recall_score(y_test, preds, pos_label=1)
    precision_1 = precision_score(y_test, preds, pos_label=1)
    print(f"   Recall (Sensitivity): {recall_1:.4f}")
    print(f"   Precision (Accuracy): {precision_1:.4f}")
    print(f"   F1-Score: {2*(precision_1*recall_1)/(precision_1+recall_1):.4f}")
    
    print("\n5. ANALYSIS OF THRESHOLDS FROM PREDICT_PROBA:")
    print(f"   {'Threshold':<15} {'Precision':<15} {'Recall':<15} {'F1-Score':<15}")
    print("   " + "-"*55)
    
    thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    for threshold in thresholds:
        preds_threshold = (preds_proba >= threshold).astype(int)
        if preds_threshold.sum() > 0:
            precision_th = precision_score(y_test, preds_threshold, zero_division=0)
            recall_th = recall_score(y_test, preds_threshold, zero_division=0)
            f1_th = 2*(precision_th*recall_th)/(precision_th+recall_th) if (precision_th+recall_th)>0 else 0
            print(f"   {threshold:<15.1f} {precision_th:<15.4f} {recall_th:<15.4f} {f1_th:<15.4f}")
    
    print("\n6. PR-AUC (Precision-Recall Area Under Curve):")
    precision_curve, recall_curve, thresholds_pr = precision_recall_curve(y_test, preds_proba)
    pr_auc = auc(recall_curve, precision_curve)
    print(f"   PR-AUC: {pr_auc:.4f}")
    print("="*60)

    print('Saved:')
    print('siem_model.pkl')
    print('scaler.pkl')
    print('encoders_dict.pkl')
    
    # Save metrics for app display
    f1_score = 2*(precision_1*recall_1)/(precision_1+recall_1) if (precision_1+recall_1) > 0 else 0
    metrics_data = {
        'cm': cm.tolist(),
        'recall': float(recall_1),
        'precision': float(precision_1),
        'f1': float(f1_score),
        'pr_auc': float(pr_auc),
        'accuracy': float(acc),
        'y_test': y_test.tolist(),
        'preds_proba': preds_proba.tolist(),
        'preds': preds.tolist(),
        'precision_curve': [],
        'recall_curve': [],
        'thresholds_pr': []
    }
    
    # Store precision-recall curve data for visualization
    precision_curve, recall_curve, thresholds_pr = precision_recall_curve(y_test, preds_proba)
    metrics_data['precision_curve'] = precision_curve.tolist()
    metrics_data['recall_curve'] = recall_curve.tolist()
    metrics_data['thresholds_pr'] = thresholds_pr.tolist()
    
    joblib.dump(metrics_data, 'model_metrics.pkl')
    print('model_metrics.pkl')


if __name__ == "__main__":
    main()