# Advanced SIEM Dataset – AI Training for Unsafe Session Detection (Zero Trust)

## 1. Overview

This dataset contains **100,000 SIEM security events** designed for training AI models to detect **unsafe user sessions** in a **Zero Trust architecture**.
The data simulates enterprise logs including authentication, network traffic, user behavior, device metadata, and cloud activity.

The dataset can be used for:

* Behaviour-based anomaly detection
* Unsafe session classification
* Zero Trust access monitoring
* User session risk scoring
* Insider threat detection
* AI-based SIEM analytics

---

## 2. Dataset File

```
advanced_siem_dataset.csv
```

Total Records: **100,000**
Total Features: **35 columns**
Format: CSV
Type: Mixed (categorical + numeric + text)

---

## 3. Feature Description

### Core Event Information

| Column     | Description                                  |
| ---------- | -------------------------------------------- |
| event_id   | Unique event identifier                      |
| timestamp  | Event timestamp                              |
| event_type | Type of event (login, access, network, etc.) |
| source     | Log source system                            |
| severity   | Event severity level                         |
| raw_log    | Raw SIEM log data                            |

---

### User Behavior Fields

| Column               | Description               |
| -------------------- | ------------------------- |
| user                 | Username                  |
| action               | User action performed     |
| object               | Resource accessed         |
| behavioral_analytics | Behavior score / analysis |
| description          | Event description         |

These fields are **important for Zero Trust behavior modelling**

---

### Process Activity

| Column          | Description           |
| --------------- | --------------------- |
| process_id      | Process identifier    |
| parent_process  | Parent process        |
| additional_info | Extra process details |
 
Useful for detecting:

* Suspicious process execution
* Privilege escalation
* Malware behavior

---

### Device Information

| Column           | Description      |
| ---------------- | ---------------- |
| device_type      | Device type      |
| device_id        | Device ID        |
| firmware_version | Firmware version |
| mac_address      | MAC address      |

Used for:

* Device trust validation
* Unknown device detection

---

### Network Traffic Features

| Column   | Description           |
| -------- | --------------------- |
| src_ip   | Source IP             |
| dst_ip   | Destination IP        |
| src_port | Source port           |
| dst_port | Destination port      |
| protocol | Network protocol      |
| bytes    | Data size transferred |
| duration | Session duration      |

These are **critical for unsafe session detection**

---

### Security Alert Fields

| Column       | Description      |
| ------------ | ---------------- |
| alert_type   | Alert type       |
| signature_id | IDS signature ID |
| category     | Threat category  |
| severity     | Threat severity  |

---

### Cloud / AI Related Fields

| Column        | Description    |
| ------------- | -------------- |
| cloud_service | Cloud provider |
| resource_id   | Cloud resource |
| model_id      | AI model ID    |
| input_hash    | AI input hash  |
| output_hash   | AI output hash |

Used for:

* AI abuse detection
* Cloud access anomalies

---

## 4. Suggested Target Label (For Training)

You should create a **label column** for AI training:

Example:

```
safe = 0
unsafe = 1
```

You can label based on:

### Rule-based Labeling Example

Unsafe if:

* severity = high or critical
* abnormal duration
* unknown device
* unusual IP
* suspicious behavior score
* alert_type exists
* bytes too large
* rare event_type

Example Python:

```python
df["label"] = (
    (df["severity"].isin(["high","critical"])) |
    (df["alert_type"].notna()) |
    (df["duration"] > 5000) |
    (df["bytes"] > 1000000)
).astype(int)
```

---

## 5. Features Recommended for AI Training

Use these columns:

### Behaviour-based Features

```
user
action
object
behavioral_analytics
event_type
```

### Network Session Features

```
src_ip
dst_ip
src_port
dst_port
protocol
bytes
duration
```

### Device Trust Features

```
device_type
device_id
mac_address
```

### Security Context

```
severity
category
alert_type
```

---

## 6. Data Preprocessing

### Step 1: Handle Missing Values

```python
df = df.fillna("unknown")
```

### Step 2: Encode Categorical Features

```python
from sklearn.preprocessing import LabelEncoder

le = LabelEncoder()

for col in df.select_dtypes(include="object"):
    df[col] = le.fit_transform(df[col])
```

### Step 3: Feature Scaling

```python
from sklearn.preprocessing import StandardScaler

scaler = StandardScaler()
X = scaler.fit_transform(df.drop("label",axis=1))
```

---

## 7. AI Models Recommended

You can train using:

### Traditional ML

* Random Forest
* XGBoost
* LightGBM
* SVM

### Deep Learning

* LSTM (session sequence)
* Autoencoder (anomaly detection)
* Transformer (advanced behavior detection)

### Best Choice for Your Topic

Recommended:

```
Isolation Forest
Random Forest
Autoencoder
```

---

## 8. Example Training Code

```python
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

X = df.drop("label",axis=1)
y = df["label"]

X_train,X_test,y_train,y_test = train_test_split(X,y,test_size=0.2)

model = RandomForestClassifier()
model.fit(X_train,y_train)

accuracy = model.score(X_test,y_test)

print("Accuracy:",accuracy)
```

---

## 9. Use Case for Your Research

This dataset supports:

Detection of Unsafe User Sessions in a Zero Trust Model Based on Access Behaviour Using Artificial Intelligence

The AI system will:

1. Monitor user session behavior
2. Analyze device trust
3. Detect abnormal network access
4. Identify unsafe session
5. Trigger Zero Trust alert

---

## 10. Expected Output

Model predicts:

```
0 → Safe session
1 → Unsafe session
```

Example:

| user  | duration | bytes   | severity | prediction |
| ----- | -------- | ------- | -------- | ---------- |
| user1 | 20       | 500     | low      | safe       |
| user2 | 8000     | 2000000 | high     | unsafe     |

---

## 11. Dataset Usage

This dataset is suitable for:

* Zero Trust AI research
* Cybersecurity machine learning
* SIEM AI detection
* Insider threat detection
* User behavior analytics

---

## 12. Author Usage

Project Title:

Detection of Unsafe User Sessions in a Zero Trust Model Based on Access Behaviour Using Artificial Intelligence

Dataset:

Advanced SIEM Synthetic Dataset (100K Events)

AI Goal:

Detect unsafe user sessions using behavior analytics
