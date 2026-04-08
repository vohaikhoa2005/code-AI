import pandas as pd

def add_labels_based_on_guide(df):
    sensitive_ports = [22, 23, 3389, 445]
    risky_event_types = ['network', 'process', 'access', 'login']

    # Khởi tạo label = 0 (SAFE)
    df['label'] = 0

    # Điều kiện UNSAFE
    condition1 = (df['duration'] > 2500) & (df['bytes'] > 500000)
    condition2 = df['event_type'].isin(risky_event_types)
    condition3 = df['src_port'].isin(sensitive_ports) | df['dst_port'].isin(sensitive_ports)
    condition4 = (df['event_type'] == 'login') & (df['src_port'].isin(sensitive_ports) | df['dst_port'].isin(sensitive_ports))

    # Nếu bất kỳ điều kiện nào đúng, label = 1 (UNSAFE)
    df.loc[condition1 | condition2 | condition3 | condition4, 'label'] = 1

    return df

# Load dataset
df = pd.read_csv('advanced_siem_dataset.csv')

# Add labels
df = add_labels_based_on_guide(df)

# Save with labels
df.to_csv('advanced_siem_dataset_with_labels.csv', index=False)

print('Added labels to dataset.')
print('Label distribution:')
print(df['label'].value_counts())
print('Saved as advanced_siem_dataset_with_labels.csv')