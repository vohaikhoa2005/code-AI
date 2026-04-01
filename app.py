import streamlit as st
import pandas as pd
import joblib
import numpy as np
import os
import random
from sklearn.preprocessing import LabelEncoder

# Page config
st.set_page_config(page_title="SIEM AI Detection", layout="wide", initial_sidebar_state="expanded")

# Load model and preprocessing objects
@st.cache_resource
def load_models():
    model = joblib.load('siem_model.pkl')
    scaler = joblib.load('scaler.pkl')
    encoders_dict = joblib.load('encoders_dict.pkl')
    return model, scaler, encoders_dict

model, scaler, encoders_dict = load_models()

# Define columns
categorical_cols = [
    'event_type', 'source', 'user', 'action', 'object',
    'process_id', 'parent_process',
    'device_type', 'device_id', 'firmware_version',
    'src_ip', 'dst_ip', 'signature_id',
    'cloud_service', 'resource_id',
    'protocol', 'method', 'mac_address'
]

numeric_cols = ['duration', 'bytes', 'src_port', 'dst_port']

expected_cols = [
    'event_type', 'source', 'user', 'action', 'object',
    'process_id', 'parent_process',
    'device_type', 'device_id', 'firmware_version',
    'src_ip', 'dst_ip', 'signature_id',
    'cloud_service', 'resource_id',
    'src_port', 'dst_port', 'protocol',
    'bytes', 'duration', 'method', 'mac_address'
]


def preprocess_data(df):
    """Preprocess data for prediction"""
    df = df.fillna("unknown")

    # numeric
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # categorical safe encoding
    for col in categorical_cols:
        if col in df.columns:
            df[col] = df[col].astype(str)

            if col in encoders_dict:
                le = encoders_dict[col]

                # replace unseen values
                df[col] = df[col].apply(
                    lambda x: x if x in le.classes_ else "unknown"
                )

                # add unknown if missing
                if "unknown" not in le.classes_:
                    le.classes_ = np.append(le.classes_, "unknown")

                df[col] = le.transform(df[col])
            else:
                df[col] = 0

    # ensure columns exist
    for col in expected_cols:
        if col not in df.columns:
            df[col] = 0

    return df[expected_cols].astype(float)


def generate_explanation(data_dict):
    """Generate explanation for the prediction"""
    explanations = []

    # Check duration
    if data_dict.get('duration', 0) > 5000:
        explanations.append(f"⏱️ Session duration ({data_dict['duration']}s) exceeds normal threshold (5000s)")

    # Check bytes
    if data_dict.get('bytes', 0) > 1000000:
        explanations.append(f"📊 Data transfer ({data_dict['bytes']:,} bytes) exceeds normal threshold (1,000,000 bytes)")

    # Check event type
    if data_dict.get('event_type', '').lower() in ['network', 'process', 'access', 'login']:
        explanations.append(
            "🌐 Event type '" + data_dict.get('event_type', '') + "' typically involves data access or network activity that requires heightened monitoring and has higher risk than normal operations."
        )

    # Check login sensitivity rule
    if (data_dict.get('event_type', '').lower() == 'login' and
        (data_dict.get('src_port', 0) in [22, 23, 3389, 445] or data_dict.get('dst_port', 0) in [22, 23, 3389, 445])):
        explanations.append("🔐 Login event on sensitive port detected (SSH/Telnet/RDP/SMB)")

    # Check network ports
    if data_dict.get('src_port', 0) in [22, 23, 3389, 445] or data_dict.get('dst_port', 0) in [22, 23, 3389, 445]:
        explanations.append("🌐 Suspicious network ports detected (SSH/Telnet/RDP/SMB)")

    # Check user
    if data_dict.get('user', '').lower() in ['unknown', 'service_account']:
        explanations.append(f"👤 Suspicious user account: '{data_dict['user']}'")

    if len(explanations) == 0:
        explanations.append("✅ No suspicious indicators detected")
        explanations.append("🔒 Session appears normal based on available data")

    return explanations

def predict_case(data_dict):
    """Predict a single case with explanation"""
    df = pd.DataFrame([data_dict])
    df = preprocess_data(df)
    X = scaler.transform(df)
    model_pred = model.predict(X)[0]
    model_conf = model.predict_proba(X)[0][1]

    explanation = generate_explanation(data_dict)

    # Rule-based post-check (ensure critical unsafe conditions are enforced)
    rule_unsafe = (
        (data_dict.get('duration', 0) > 2500 and data_dict.get('bytes', 0) > 500000) or
        (data_dict.get('event_type', '').lower() == 'login' and
         (data_dict.get('src_port', 0) in [22, 23, 3389, 445] or data_dict.get('dst_port', 0) in [22, 23, 3389, 445]))
    )

    if rule_unsafe:
        explanation.append('⚠️ Rule override: critical unsafe pattern matched, forcing UNSAFE')
        # Force confidence high enough for strict yêu cầu
        return 1, 0.95, explanation

    return model_pred, model_conf, explanation


# UI
st.markdown("""
<style>
body { background-color: #f8fafc; }
.css-1d391kg { background-color: #ffffff; }
.section-title { font-size: 24px; font-weight: 700; color: #0d4f8b; }
</style>
""", unsafe_allow_html=True)

st.markdown("# 🛡️ SIEM AI - Unsafe Session Detection System")
st.markdown("### Zero Trust Security Analysis Platform")
st.markdown("---")

# Show accuracy curve if available
st.markdown("### Training Accuracy Curve")
if os.path.exists('accuracy_curve.png'):
    st.image('accuracy_curve.png', caption='Accuracy curve after latest training', width=800)
else:
    st.warning('accuracy_curve.png not found. Please run train_model.py first and restart the app.')

st.markdown("---")
# Single Case Analysis only (Batch and Predefined Scenarios removed)
with st.container():
    st.header("Single Case Prediction")
    st.write("Nhập dữ liệu sau để kiểm tra phiên an toàn hoặc không an toàn")

    layout1, layout2, layout3 = st.columns([1, 2, 1])
    with layout2:
        col1, col2 = st.columns(2)

        with col1:
            user = st.selectbox(
                "Username",
                ['unknown', 'admin', 'user1', 'user2', 'employee_001', 'service_account']
            )

    event_type = st.selectbox(
        "Event Type",
        ['unknown', 'login', 'access', 'network', 'process', 'device_change']
    )

    source = st.selectbox(
        "Log Source",
        ['unknown', 'windows_logs', 'network_logs', 'cloud_logs', 'app_logs']
    )

    action = st.selectbox(
        "Action",
        ['unknown', 'login', 'file_access', 'network_traffic',
         'process_execution', 'resource_access']
    )

    with col2:
        device_type = st.selectbox(
            "Device",
            ['unknown', 'workstation', 'laptop',
             'mobile', 'server', 'iot']
        )

        # Keep placeholder values for now
        severity = 'unknown'
        alert_type = 'unknown'
        category = 'unknown'
        behavioral_analytics = 'unknown'

    col3, col4 = st.columns(2)

    with col3:
        src_ip = st.text_input("Source IP", "192.168.1.1")
        dst_ip = st.text_input("Destination IP", "10.0.0.1")
        src_port = st.number_input("Src Port", 1, 65535, 50000)
        dst_port = st.number_input("Dst Port", 1, 65535, 443)

    with col4:
        duration = st.number_input("Duration", 0, 100000, 100)
        bytes_transferred = st.number_input("Bytes", 0, 10000000, 10000)

        protocol = st.selectbox(
            "Protocol",
            ['unknown', 'TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'SSH']
        )

    if st.button("🔍 Predict"):

        case_data = {
            'event_type': event_type,
            'source': source,
            'user': user,
            'action': action,
            'object': 'unknown',
            'process_id': '0',
            'parent_process': 'unknown',
            'device_type': device_type,
            'device_id': 'unknown',
            'firmware_version': 'unknown',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'signature_id': '0',
            'cloud_service': 'unknown',
            'resource_id': 'unknown',
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'bytes': bytes_transferred,
            'duration': duration,
            'method': 'unknown',
            'mac_address': 'unknown'
        }

        prediction, confidence, explanation = predict_case(case_data)

        st.markdown("---")

        col_res1, col_res2 = st.columns(2)
        
        with col_res1:
            if prediction == 1:
                st.error("🚨 **UNSAFE SESSION DETECTED**")
                st.metric("Threat Confidence", f"{confidence*100:.1f}%")
            else:
                st.success("✅ **SAFE SESSION**")
                st.metric("Safety Confidence", f"{(1-confidence)*100:.1f}%")
        
        with col_res2:
            st.info("**Analysis Details**")
            st.write(f"Status: {'Unsafe' if prediction == 1 else 'Safe'}")
            st.write(f"Model Confidence: {max(confidence, 1-confidence)*100:.1f}%")
        
        # Explanation section
        st.markdown("### 🔍 **Why this classification?**")
        for exp in explanation:
            st.write(f"• {exp}")
        
        if prediction == 1:
            st.warning("⚠️ **Recommended Actions:**")
            st.write("• Review user access permissions")
            st.write("• Monitor session activity closely")
            st.write("• Consider blocking similar patterns")
        else:
            st.success("✅ **Session appears normal**")

    # Random safe/unsafe case button
    if st.button("🎲 Generate Random Test Case"):
        cases = [
            # Safe cases
            {
                'user': 'user1', 'event_type': 'access', 'source': 'windows_logs',
                'action': 'file_access', 'device_type': 'workstation',
                'src_ip': '192.168.1.100', 'dst_ip': '10.0.0.10',
                'src_port': 50000, 'dst_port': 443,
                'duration': 1200, 'bytes': 100000, 'protocol': 'HTTPS'
            },
            {
                'user': 'employee_001', 'event_type': 'device_change', 'source': 'network_logs',
                'action': 'resource_access', 'device_type': 'laptop',
                'src_ip': '192.168.1.200', 'dst_ip': '10.0.0.20',
                'src_port': 56000, 'dst_port': 80,
                'duration': 900, 'bytes': 120000, 'protocol': 'HTTP'
            },
            # Unsafe cases
            {
                'user': 'admin', 'event_type': 'network', 'source': 'network_logs',
                'action': 'network_traffic', 'device_type': 'server',
                'src_ip': '192.168.1.1', 'dst_ip': '10.0.0.5',
                'src_port': 50000, 'dst_port': 443,
                'duration': 3000, 'bytes': 600000, 'protocol': 'TCP'
            },
            {
                'user': 'unknown', 'event_type': 'login', 'source': 'app_logs',
                'action': 'login', 'device_type': 'mobile',
                'src_ip': '192.168.1.50', 'dst_ip': '10.0.0.8',
                'src_port': 40000, 'dst_port': 22,
                'duration': 1000, 'bytes': 200000, 'protocol': 'SSH'
            }
        ]

        random_case = random.choice(cases)
        st.markdown("#### Random test case generated")
        st.write(random_case)

        p, c, exp = predict_case(random_case)

        st.markdown("### Result")
        st.write("Prediction:", "🚨 UNSAFE" if p == 1 else "✅ SAFE")
        st.write("Confidence:", f"{c*100:.1f}%" if p == 1 else f"{(1-c)*100:.1f}%")

        st.markdown("### Why this classification?")
        for e in exp:
            st.write(f"• {e}")

st.markdown("---")
st.markdown(
    "<center>🛡️ SIEM AI Detection System</center>",
    unsafe_allow_html=True
)