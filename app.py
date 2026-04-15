import streamlit as st
import pandas as pd
import joblib
import numpy as np
import os
import random
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import precision_score, recall_score

# Page config
st.set_page_config(page_title="SIEM AI Detection", layout="wide", initial_sidebar_state="collapsed")

# Load model and preprocessing objects
@st.cache_resource
def load_models():
    model = joblib.load('siem_model.pkl')
    scaler = joblib.load('scaler.pkl')
    encoders_dict = joblib.load('encoders_dict.pkl')
    return model, scaler, encoders_dict

model, scaler, encoders_dict = load_models()

# Define columns
expected_cols = [
    'source', 'user', 'action', 'object',
    'process_id', 'parent_process',
    'device_type', 'device_id', 'firmware_version',
    'src_ip', 'dst_ip',
    'cloud_service', 'resource_id',
    'protocol', 'method', 'mac_address',
    'duration', 'data_access_time', 'bytes', 'src_port', 'dst_port'
]

categorical_cols = [
    'source', 'user', 'action', 'object',
    'process_id', 'parent_process',
    'device_type', 'device_id', 'firmware_version',
    'src_ip', 'dst_ip',
    'cloud_service', 'resource_id',
    'protocol', 'method', 'mac_address',
    'data_access_time'  # Treat as categorical
]

numeric_cols = ['duration', 'bytes', 'src_port', 'dst_port']

# Prepare random examples for demo
@st.cache_resource
def get_demo_cases():
    return [
        {
            'source': 'windows_logs', 'user': 'user1', 'action': 'file_access', 'object': 'document.pdf',
            'process_id': 'unknown', 'parent_process': 'unknown',
            'device_type': 'workstation', 'device_id': 'unknown', 'firmware_version': 'unknown',
            'src_ip': '192.168.1.100', 'dst_ip': '10.0.0.10',
            'cloud_service': 'unknown', 'resource_id': 'unknown',
            'protocol': 'https', 'method': 'unknown', 'mac_address': 'unknown',
            'duration': 163.0, 'data_access_time': 'unknown', 'bytes': 1024, 'src_port': 443, 'dst_port': 443
        },
        {
            'source': 'network_logs', 'user': 'employee_001', 'action': 'resource_access', 'object': 'firmware',
            'process_id': 'unknown', 'parent_process': 'unknown',
            'device_type': 'laptop', 'device_id': 'unknown', 'firmware_version': 'unknown',
            'src_ip': '192.168.1.200', 'dst_ip': '10.0.0.20',
            'cloud_service': 'unknown', 'resource_id': 'unknown',
            'protocol': 'https', 'method': 'unknown', 'mac_address': 'unknown',
            'duration': 900.0, 'data_access_time': 'unknown', 'bytes': 2048, 'src_port': 443, 'dst_port': 443
        },
        {
            'source': 'app_logs', 'user': 'admin', 'action': 'login', 'object': 'dashboard_access',
            'process_id': 'unknown', 'parent_process': 'unknown',
            'device_type': 'workstation', 'device_id': 'unknown', 'firmware_version': 'unknown',
            'src_ip': '192.168.1.150', 'dst_ip': '10.0.0.15',
            'cloud_service': 'unknown', 'resource_id': 'unknown',
            'protocol': 'https', 'method': 'unknown', 'mac_address': 'unknown',
            'duration': 1400.0, 'data_access_time': 'unknown', 'bytes': 1536, 'src_port': 443, 'dst_port': 443
        },
        {
            'source': 'cloud_logs', 'user': 'employee_002', 'action': 'resource_access', 'object': 'api_call',
            'process_id': 'unknown', 'parent_process': 'unknown',
            'device_type': 'laptop', 'device_id': 'unknown', 'firmware_version': 'unknown',
            'src_ip': '192.168.1.175', 'dst_ip': '10.0.0.22',
            'cloud_service': 'unknown', 'resource_id': 'unknown',
            'protocol': 'https', 'method': 'unknown', 'mac_address': 'unknown',
            'duration': 120.0, 'data_access_time': 'unknown', 'bytes': 512, 'src_port': 443, 'dst_port': 443
        },
        {
            'source': 'windows_logs', 'user': 'user3', 'action': 'read', 'object': 'database_query',
            'process_id': 'unknown', 'parent_process': 'unknown',
            'device_type': 'server', 'device_id': 'unknown', 'firmware_version': 'unknown',
            'src_ip': '10.0.0.50', 'dst_ip': '10.0.0.60',
            'cloud_service': 'unknown', 'resource_id': 'unknown',
            'protocol': 'tcp', 'method': 'unknown', 'mac_address': 'unknown',
            'duration': 1768.0, 'data_access_time': 'unknown', 'bytes': 3072, 'src_port': 1433, 'dst_port': 1433
        },
        {
            'source': 'network_logs', 'user': 'employee_003', 'action': 'process_execution', 'object': 'backup_task',
            'process_id': 'unknown', 'parent_process': 'unknown',
            'device_type': 'workstation', 'device_id': 'unknown', 'firmware_version': 'unknown',
            'src_ip': '192.168.1.120', 'dst_ip': '10.0.0.25',
            'cloud_service': 'unknown', 'resource_id': 'unknown',
            'protocol': 'https', 'method': 'unknown', 'mac_address': 'unknown',
            'duration': 2800.0, 'data_access_time': 'unknown', 'bytes': 1048576, 'src_port': 443, 'dst_port': 443
        },
        {
            'source': 'firewall', 'user': 'unknown', 'action': 'block', 'object': 'suspicious_traffic',
            'process_id': 'unknown', 'parent_process': 'unknown',
            'device_type': 'server', 'device_id': 'unknown', 'firmware_version': 'unknown',
            'src_ip': '192.168.1.1', 'dst_ip': '10.0.0.5',
            'cloud_service': 'unknown', 'resource_id': 'unknown',
            'protocol': 'tcp', 'method': 'unknown', 'mac_address': 'unknown',
            'duration': 80.0, 'data_access_time': 'unknown', 'bytes': 64, 'src_port': 22, 'dst_port': 22
        },
        {
            'source': 'ids_alert', 'user': 'unknown', 'action': 'alert', 'object': 'malware_detected',
            'process_id': 'unknown', 'parent_process': 'unknown',
            'device_type': 'workstation', 'device_id': 'unknown', 'firmware_version': 'unknown',
            'src_ip': '192.168.1.50', 'dst_ip': '203.0.113.10',
            'cloud_service': 'unknown', 'resource_id': 'unknown',
            'protocol': 'tcp', 'method': 'unknown', 'mac_address': 'unknown',
            'duration': 20.0, 'data_access_time': 'unknown', 'bytes': 128, 'src_port': 80, 'dst_port': 80
        },
        {
            'source': 'app_logs', 'user': 'service_account', 'action': 'block', 'object': 'suspicious_access',
            'process_id': 'unknown', 'parent_process': 'unknown',
            'device_type': 'server', 'device_id': 'unknown', 'firmware_version': 'unknown',
            'src_ip': '192.168.1.200', 'dst_ip': '10.0.0.8',
            'cloud_service': 'unknown', 'resource_id': 'unknown',
            'protocol': 'tcp', 'method': 'unknown', 'mac_address': 'unknown',
            'duration': 60.0, 'data_access_time': 'unknown', 'bytes': 256, 'src_port': 22, 'dst_port': 22
        },
        {
            'source': 'firewall', 'user': 'service_account', 'action': 'deny', 'object': 'suspicious_port_scan',
            'process_id': 'unknown', 'parent_process': 'unknown',
            'device_type': 'network_device', 'device_id': 'unknown', 'firmware_version': 'unknown',
            'src_ip': '203.0.113.50', 'dst_ip': '10.0.0.0',
            'cloud_service': 'unknown', 'resource_id': 'unknown',
            'protocol': 'tcp', 'method': 'unknown', 'mac_address': 'unknown',
            'duration': 10.0, 'data_access_time': 'unknown', 'bytes': 48, 'src_port': 0, 'dst_port': 0
        },
        {
            'source': 'network_logs', 'user': 'unknown', 'action': 'network_traffic', 'object': 'data_exfiltration',
            'process_id': 'unknown', 'parent_process': 'unknown',
            'device_type': 'server', 'device_id': 'unknown', 'firmware_version': 'unknown',
            'src_ip': '10.0.0.100', 'dst_ip': '203.0.113.99',
            'cloud_service': 'unknown', 'resource_id': 'unknown',
            'protocol': 'tcp', 'method': 'unknown', 'mac_address': 'unknown',
            'duration': 3120.0, 'data_access_time': 'unknown', 'bytes': 5242880, 'src_port': 443, 'dst_port': 443
        },
        {
            'source': 'ids_alert', 'user': 'unknown', 'action': 'alert', 'object': 'sql_injection_attempt',
            'process_id': 'unknown', 'parent_process': 'unknown',
            'device_type': 'server', 'device_id': 'unknown', 'firmware_version': 'unknown',
            'src_ip': '203.0.113.77', 'dst_ip': '10.0.0.30',
            'cloud_service': 'unknown', 'resource_id': 'unknown',
            'protocol': 'tcp', 'method': 'unknown', 'mac_address': 'unknown',
            'duration': 250.0, 'data_access_time': 'unknown', 'bytes': 1024, 'src_port': 80, 'dst_port': 80
        }
    ]


def initialise_session_defaults():
    defaults = {
        'source': 'unknown', 'user': 'unknown', 'action': 'unknown', 'object': 'unknown',
        'process_id': 'unknown', 'parent_process': 'unknown',
        'device_type': 'unknown', 'device_id': 'unknown', 'firmware_version': 'unknown',
        'src_ip': '192.168.1.1', 'dst_ip': '10.0.0.1',
        'cloud_service': 'unknown', 'resource_id': 'unknown',
        'protocol': 'unknown', 'method': 'unknown', 'mac_address': 'unknown',
        'duration': 1200.0, 'data_access_time': 'unknown', 'bytes': 0, 'src_port': 0, 'dst_port': 0,
        'random_generated': False
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def set_random_case_to_session(case):
    for k, v in case.items():
        st.session_state[k] = v
    st.session_state['random_generated'] = True


def get_case_data_from_state():
    object_value = st.session_state.get('object', '')
    if not object_value or str(object_value).strip() == '':
        object_value = 'unknown'

    return {
        'source': st.session_state['source'],
        'user': st.session_state['user'],
        'action': st.session_state['action'],
        'object': object_value,
        'process_id': st.session_state.get('process_id', 'unknown'),
        'parent_process': st.session_state.get('parent_process', 'unknown'),
        'device_type': st.session_state['device_type'],
        'device_id': st.session_state.get('device_id', 'unknown'),
        'firmware_version': st.session_state.get('firmware_version', 'unknown'),
        'src_ip': st.session_state['src_ip'],
        'dst_ip': st.session_state['dst_ip'],
        'cloud_service': st.session_state.get('cloud_service', 'unknown'),
        'resource_id': st.session_state.get('resource_id', 'unknown'),
        'protocol': st.session_state['protocol'],
        'method': st.session_state.get('method', 'unknown'),
        'mac_address': st.session_state.get('mac_address', 'unknown'),
        'duration': st.session_state['duration'],
        'data_access_time': st.session_state.get('data_access_time', 'unknown'),
        'bytes': st.session_state['bytes'],
        'src_port': st.session_state['src_port'],
        'dst_port': st.session_state['dst_port']
    }


def random_case_callback():
    set_random_case_to_session(random.choice(get_demo_cases()))



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

    return df[expected_cols]


def generate_explanation(data_dict):
    """Generate explanation for the prediction"""
    explanations = []

    # Check user
    if data_dict.get('user', '').lower() in ['unknown', 'service_account']:
        explanations.append(f"👤 Suspicious user account: '{data_dict['user']}'")

    # Check source
    if data_dict.get('source', '').lower() in ['firewall', 'ids_alert']:
        explanations.append(f"🛡️ Security source detected: '{data_dict['source']}' - may indicate blocked activity")

    # Check action
    if data_dict.get('action', '').lower() in ['block', 'deny', 'alert']:
        explanations.append(f"🚫 Suspicious action: '{data_dict['action']}' - security event triggered")

    # Check duration and bytes
    duration = data_dict.get('duration', 0)
    bytes_val = data_dict.get('bytes', 0)
    if duration > 2500 and bytes_val > 500000:
        explanations.append(f"⏱️ Long duration ({duration}s) with large data transfer ({bytes_val} bytes) - potential data exfiltration")

    # Check device type
    if data_dict.get('device_type', '').lower() in ['server', 'network_device']:
        explanations.append(f"🖥️ Critical device type: '{data_dict['device_type']}' - high-value asset")

    if len(explanations) == 0:
        explanations.append("✅ No suspicious indicators detected")
        explanations.append("🔒 Session appears normal based on available data")

    return explanations

def predict_case(data_dict):
    """Predict a single case with explanation"""
    df = pd.DataFrame([data_dict])
    df = preprocess_data(df)
    X = scaler.transform(df)
    model_proba = model.predict_proba(X)[0][1]  # Get probability for class 1 (UNSAFE)
    
    explanation = generate_explanation(data_dict)
    
    # Rule-based logic based on available features
    unsafe_score = 0
    
    # Check user
    if data_dict.get('user', '').lower() in ['unknown', 'service_account']:
        unsafe_score += 2
    
    # Check source
    if data_dict.get('source', '').lower() in ['firewall', 'ids_alert', 'network_logs']:
        unsafe_score += 2
    
    # Check action
    if data_dict.get('action', '').lower() in ['block', 'deny', 'alert', 'network_traffic']:
        unsafe_score += 2
    
    # Check object
    if 'malware' in data_dict.get('object', '').lower() or 'suspicious' in data_dict.get('object', '').lower():
        unsafe_score += 3
    
    # Check device type
    if data_dict.get('device_type', '').lower() in ['server', 'network_device']:
        unsafe_score += 1
    
    # Check cloud service
    if data_dict.get('cloud_service', '').lower() == 'unknown' and data_dict.get('source', '').lower() == 'cloud_logs':
        unsafe_score += 1
    
    # Check protocol
    if data_dict.get('protocol', '').lower() in ['tcp']:
        unsafe_score += 0.5
    
    # Decision logic
    if unsafe_score >= 3 or model_proba >= 0.3:
        prediction = 1
        confidence = max(model_proba, min(unsafe_score / 5, 0.99))  # Scale unsafe_score to 0-1
    else:
        prediction = 0
        confidence = max(1 - model_proba, 1 - (unsafe_score / 10))
    
    return prediction, confidence, explanation


# UI
st.markdown("""
<style>
body { background-color: #f8fafc; }
.css-1d391kg { background-color: #ffffff; }
.section-title { font-size: 24px; font-weight: 700; color: #0d4f8b; }
.stAlert { border-radius: 12px; }
</style>
""", unsafe_allow_html=True)

st.markdown("# 🛡️ SIEM AI - Unsafe Session Detection System")
st.markdown("### Zero Trust Security Analysis Platform")
st.markdown("---")

# Single Case Analysis
initialise_session_defaults()

with st.container():
    st.header("Single Case Prediction")
    st.write("Enter the case details below or click 'Generate Random Test Case' to auto-fill inputs.")

    col1, col2 = st.columns(2)

    with col1:
        st.selectbox("Username", ['unknown', 'admin', 'user1', 'user2', 'employee_001', 'service_account'], key='user')
        st.selectbox("Log Source", ['unknown', 'windows_logs', 'network_logs', 'cloud_logs', 'app_logs', 'firewall', 'web_server'], key='source')
        st.selectbox("Action", ['unknown', 'login', 'file_access', 'network_traffic', 'process_execution', 'resource_access', 'read', 'write', 'block', 'alert'], key='action')
        st.selectbox("Device Type", ['unknown', 'workstation', 'laptop', 'mobile', 'server', 'iot', 'desktop', 'network_device'], key='device_type')

    with col2:
        st.text_input("Source IP", key='src_ip')
        st.text_input("Destination IP", key='dst_ip')
        st.selectbox("Protocol", ['unknown', 'tcp', 'udp', 'http', 'https'], key='protocol')
        st.number_input("Duration (seconds)", min_value=1.0, max_value=3600.0, step=1.0, key='duration')
        st.number_input("Bytes Transferred", min_value=0, step=1, key='bytes')
        st.number_input("Source Port", min_value=0, max_value=65535, step=1, key='src_port')
        st.number_input("Destination Port", min_value=0, max_value=65535, step=1, key='dst_port')

    btn_col1, btn_col2 = st.columns([1, 1])

    with btn_col1:
        if st.button("🔍 Predict", key='btn_predict'):
            case_data = get_case_data_from_state()
            prediction, confidence, explanation = predict_case(case_data)

            st.markdown("---")
            out_col1, out_col2 = st.columns(2)
            with out_col1:
                if prediction == 1:
                    st.error("🚨 **UNSAFE SESSION DETECTED**")
                else:
                    st.success("✅ **SAFE SESSION**")
                st.metric("Threat Probability", f"{confidence*100:.2f}%")
            with out_col2:
                st.info("**Analysis Summary**")
                st.write(f"Status: {'🚨 UNSAFE' if prediction == 1 else '✅ SAFE'}")
                st.write(f"Model Score (UNSAFE): {confidence*100:.2f}%")
                st.write(f"Decision: {'Take action' if prediction == 1 else 'Monitoring suffices'}")

            st.markdown("### 🔎 Why this classification?")
            for exp in explanation:
                st.write(f"- {exp}")

            if prediction == 1:
                st.warning("⚠️ Recommended Actions:")
                st.write("• Review access policies")
                st.write("• Escalate and quarantine if needed")
            else:
                st.success("✅ Normal behavior detected.")

    with btn_col2:
        if st.button("🎲 Generate Random Test Case", key='btn_random_case', on_click=random_case_callback):
            pass

st.markdown("---")
st.markdown(
    "<center>🛡️ SIEM AI Detection System</center>",
    unsafe_allow_html=True
)

