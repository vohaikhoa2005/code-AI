import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import warnings
warnings.filterwarnings('ignore')


def load_and_preprocess_data(filepath='advanced_siem_dataset.csv'):
    print("Loading dataset...")
    df = pd.read_csv(filepath)

    df = df.fillna("unknown")

    numeric_cols = ['duration', 'bytes', 'src_port', 'dst_port']

    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    return df


def create_labels(df):
    sensitive_ports = [22, 23, 3389, 445]

    unsafe_count = (
        (df["duration"] > 2500).astype(int) +
        (df["bytes"] > 500000).astype(int) +
        (df["event_type"].isin(["network", "process", "access", "login"]).astype(int)) +
        (df["src_port"].isin(sensitive_ports).astype(int)) +
        (df["dst_port"].isin(sensitive_ports).astype(int)) +
        ((df["event_type"] == "login") &
         (df["src_port"].isin(sensitive_ports) | df["dst_port"].isin(sensitive_ports))).astype(int) +
        ((df["duration"] > 2500) & (df["bytes"] > 500000)).astype(int)
    )

    df["label"] = (unsafe_count >= 1).astype(int)

    print(df["label"].value_counts())

    return df


def encode_categorical_features(df):

    categorical_cols = [
        'event_type', 'source', 'user', 'action', 'object',
        'process_id', 'parent_process',
        'device_type', 'device_id', 'firmware_version',
        'src_ip', 'dst_ip', 'signature_id',
        'cloud_service', 'resource_id',
        'protocol', 'method', 'mac_address'
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

    df = create_labels(df)

    df, encoders_dict = encode_categorical_features(df)

    expected_cols = [
        'event_type', 'source', 'user', 'action', 'object',
        'process_id', 'parent_process',
        'device_type', 'device_id', 'firmware_version',
        'src_ip', 'dst_ip', 'signature_id',
        'cloud_service', 'resource_id',
        'src_port', 'dst_port', 'protocol',
        'bytes', 'duration', 'method', 'mac_address'
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
        n_estimators=300,
        max_depth=15,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )

    model.fit(X_train, y_train)

    joblib.dump(model, "siem_model.pkl")

    preds = model.predict(X_test)

    acc = accuracy_score(y_test, preds)

    print("Accuracy:", acc)
    print(classification_report(y_test, preds))

    # Plot accuracy curve for training and validation
    import matplotlib.pyplot as plt

    estimators_list = [50, 100, 150, 200, 250, 300]
    train_scores = []
    test_scores = []

    for n in estimators_list:
        tmp_model = RandomForestClassifier(
            n_estimators=n,
            max_depth=15,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        tmp_model.fit(X_train, y_train)
        train_scores.append(tmp_model.score(X_train, y_train))
        test_scores.append(tmp_model.score(X_test, y_test))

    plt.figure(figsize=(8, 5))
    plt.plot(estimators_list, train_scores, marker='o', label='Train Accuracy')
    plt.plot(estimators_list, test_scores, marker='o', label='Test Accuracy')
    plt.xlabel('n_estimators')
    plt.ylabel('Accuracy')
    plt.title('Random Forest Accuracy Curve')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('accuracy_curve.png')
    plt.close()
    print('Accuracy curve saved as accuracy_curve.png')

    print('Saved:')
    print('siem_model.pkl')
    print('scaler.pkl')
    print('encoders_dict.pkl')


if __name__ == "__main__":
    main()