import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, average_precision_score, recall_score, precision_score


def load_data(filepath='advanced_siem_dataset.csv'):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset not found: {filepath}")

    df = pd.read_csv(filepath)
    return df


def build_proxy_label(df, severity_col='severity'):
    if 'label' in df.columns:
        print('Data already has label column; using existing values.')
        return df

    if severity_col not in df.columns:
        raise ValueError(f"Severity column '{severity_col}' not found, cannot build proxy label")

    # Proxy rules: high/critical/emergency => UNSAFE (1) else SAFE (0)
    df['label'] = df[severity_col].astype(str).str.lower().isin(['high', 'critical', 'emergency']).astype(int)
    return df


def prepare_features(df):
    cols = [
        'source', 'user', 'action', 'object',
        'process_id', 'parent_process',
        'device_type', 'device_id', 'firmware_version',
        'src_ip', 'dst_ip',
        'cloud_service', 'resource_id',
        'protocol', 'method', 'mac_address'
    ]

    for c in cols:
        if c not in df.columns:
            df[c] = 'unknown'

    for c in cols:
        df[c] = df[c].fillna('unknown').astype(str)

    encoders = {}
    for c in cols:
        le = LabelEncoder()
        df[c] = le.fit_transform(df[c])
        encoders[c] = le

    X = df[cols]
    y = df['label']
    return X, y, encoders, cols


def evaluate_configs(X_train, X_test, y_train, y_test, configs):
    rows = []

    for cfg in configs:
        model = RandomForestClassifier(
            n_estimators=cfg['n_estimators'],
            max_depth=cfg['max_depth'],
            class_weight=cfg['class_weight'],
            random_state=42,
            n_jobs=-1,
        )

        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0
        pr_auc = average_precision_score(y_test, y_proba)

        row = {
            'n_estimators': cfg['n_estimators'],
            'max_depth': cfg['max_depth'],
            'class_weight': cfg['class_weight'],
            'accuracy': acc,
            'precision': prec,
            'recall': rec,
            'f1': f1,
            'pr_auc': pr_auc,
        }
        rows.append(row)

        print('Config:', cfg)
        print('  Accuracy: {:.4f} | Precision: {:.4f} | Recall: {:.4f} | F1: {:.4f} | PR-AUC: {:.4f}'.format(
            acc, prec, rec, f1, pr_auc
        ))
        print('  Confusion matrix:\n', confusion_matrix(y_test, y_pred))
        print('  Classification report:\n', classification_report(y_test, y_pred, digits=4))
        print('-' * 80)

    return pd.DataFrame(rows)


def main():
    df = load_data('advanced_siem_dataset.csv')
    df = build_proxy_label(df, severity_col='severity')

    X, y, encoders, cols = prepare_features(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    joblib.dump(scaler, 'debug_scaler.pkl')
    joblib.dump(encoders, 'debug_encoders.pkl')

    config_list = [
        {'n_estimators': 50, 'max_depth': 4, 'class_weight': None},
        {'n_estimators': 100, 'max_depth': 6, 'class_weight': 'balanced'},
        {'n_estimators': 150, 'max_depth': None, 'class_weight': 'balanced_subsample'},
    ]

    results_df = evaluate_configs(X_train, X_test, y_train, y_test, config_list)
    results_df.to_csv('run_results.csv', index=False)

    print('Saved run_results.csv')


if __name__ == '__main__':
    main()
