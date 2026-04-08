import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler

def load_model_and_preprocess():
    # Load model and preprocessors
    model = joblib.load('siem_model.pkl')
    scaler = joblib.load('scaler.pkl')
    encoders = joblib.load('encoders_dict.pkl')

    # Feature columns (same as training)
    expected_cols = [
        'source', 'user', 'action', 'object',
        'process_id', 'parent_process',
        'device_type', 'device_id', 'firmware_version',
        'src_ip', 'dst_ip',
        'cloud_service', 'resource_id',
        'protocol', 'method', 'mac_address'
    ]

    return model, scaler, encoders, expected_cols

def predict_sample(sample_data, model, scaler, encoders, expected_cols):
    # Prepare sample as DataFrame
    df = pd.DataFrame([sample_data])

    # Fill missing columns with 'unknown'
    for col in expected_cols:
        if col not in df.columns:
            df[col] = 'unknown'

    # Encode categorical
    for col in expected_cols:
        if col in encoders:
            df[col] = df[col].fillna('unknown').astype(str)
            # Handle unknown categories
            le = encoders[col]
            df[col] = df[col].apply(lambda x: x if x in le.classes_ else 'unknown')
            df[col] = le.transform(df[col])

    # Scale
    X = scaler.transform(df[expected_cols])

    # Predict
    pred = model.predict(X)[0]
    proba = model.predict_proba(X)[0][1]  # Probability for UNSAFE

    return 'UNSAFE' if pred == 1 else 'SAFE', proba

# Load model
model, scaler, encoders, expected_cols = load_model_and_preprocess()

# Load dataset to get some samples
df = pd.read_csv('advanced_siem_dataset_with_labels.csv')

# Select 3 SAFE and 2 UNSAFE samples
safe_samples = df[df['label'] == 0].sample(3, random_state=42)
unsafe_samples = df[df['label'] == 1].sample(2, random_state=42)
samples = pd.concat([safe_samples, unsafe_samples])

print("Testing Model on 5 Random Samples:")
print("="*80)

for i, (_, row) in enumerate(samples.iterrows(), 1):
    sample_data = row.to_dict()
    true_label = 'UNSAFE' if sample_data['label'] == 1 else 'SAFE'

    # Remove label for prediction
    sample_for_pred = {k: v for k, v in sample_data.items() if k != 'label'}

    pred_label, proba = predict_sample(sample_for_pred, model, scaler, encoders, expected_cols)

    print(f"Sample {i}:")
    print(f"  True Label: {true_label}")
    print(f"  Predicted: {pred_label} (Probability UNSAFE: {proba:.4f})")
    print(f"  Key Features: event_type={sample_data.get('event_type', 'N/A')}, duration={sample_data.get('duration', 'N/A')}, bytes={sample_data.get('bytes', 'N/A')}")
    print("-"*40)

print("Model Test Complete!")