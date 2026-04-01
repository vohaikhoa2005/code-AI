import pandas as pd

df = pd.read_csv('advanced_siem_dataset.csv')
df = df.fillna('unknown')
numeric_cols = ['duration', 'bytes', 'src_port', 'dst_port']
for col in numeric_cols:
    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

df['label'] = (
    (df['severity'].isin(['high', 'critical'])) |
    (df['alert_type'].notna()) |
    (df['duration'] > 5000) |
    (df['bytes'] > 1000000)
).astype(int)

print(df['label'].value_counts())