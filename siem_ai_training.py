import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Load the dataset
df = pd.read_csv('advanced_siem_dataset.csv')

# Step 1: Handle Missing Values
df = df.fillna("unknown")

# Convert numeric columns
numeric_cols = ['duration', 'bytes', 'src_port', 'dst_port']
for col in numeric_cols:
    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

# Step 2: Create Label based on rules (adjusted for balance)
# Count unsafe conditions
unsafe_count = (
    (df["severity"].isin(["high", "critical"])).astype(int) +
    (df["alert_type"].notna()).astype(int) +
    (df["duration"] > 5000).astype(int) +
    (df["bytes"] > 1000000).astype(int)
)
# Label as unsafe if at least 2 conditions met
df["label"] = (unsafe_count >= 2).astype(int)

# Step 3: Encode Categorical Features - Save encoders for each column
le_dict = {}
categorical_cols = df.select_dtypes(include=["object", "string"]).columns
for col in categorical_cols:
    df[col] = df[col].astype(str)
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    le_dict[col] = le  # Save the encoder for each column

# Step 4: Feature Scaling
scaler = StandardScaler()
X = df.drop("label", axis=1)
X_scaled = scaler.fit_transform(X)
y = df["label"]

# Step 5: Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Step 6: Train Model
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

# Step 7: Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)
print(classification_report(y_test, y_pred))

# Save model, scaler, and encoders
joblib.dump(model, 'siem_model.pkl')
joblib.dump(scaler, 'scaler.pkl')
joblib.dump(le_dict, 'encoders_dict.pkl')  # Save encoders dict for categorical columns