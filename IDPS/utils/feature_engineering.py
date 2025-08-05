import pandas as pd

def preprocess_iot_features(df):
    """Transform NSL-KDD features for IoT context"""
    # Protocol type encoding (focus on IoT protocols)
    protocol_map = {
        'tcp': 0, 'udp': 1, 'icmp': 2,
        'rtp': 3, 'rspf': 4, 'igmp': 5  # IoT-relevant protocols
    }
    df['protocol_type'] = df['protocol_type'].map(
        lambda x: protocol_map.get(x.lower(), 6)  # 6=other
    )
    
    # Service encoding (common IoT services)
    iot_services = ['mqtt', 'coap', 'amqp', 'http', 'https', 'xmpp']
    df['service'] = df['service'].apply(
        lambda x: x if x in iot_services else 'other'
    )
    
    # One-hot encode top services
    top_services = ['mqtt', 'coap', 'http', 'other']
    for service in top_services:
        df[f'service_{service}'] = (df['service'] == service).astype(int)
    
    # Feature transformations
    df['src_bytes'] = np.log1p(df['src_bytes'])
    df['dst_bytes'] = np.log1p(df['dst_bytes'])
    
    # IoT-specific feature: Device communication ratio
    df['device_com_ratio'] = df['srv_count'] / (df['count'] + 1e-5)
    
    # Binary flags for IoT attack patterns
    df['is_dos'] = df['label'].isin(['neptune', 'smurf', 'back']).astype(int)
    df['is_probe'] = df['label'].isin(['portsweep', 'ipsweep']).astype(int)
    
    return df