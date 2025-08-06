import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ML_MODEL_PATH = os.path.join(BASE_DIR, 'ml', 'models', 'idps_rf_quantized.pkl')
SIGNATURE_DB = os.path.join(BASE_DIR, 'data', 'signatures.csv')
NSL_KDD_DATA = os.path.join(BASE_DIR, 'data', 'nsl_kdd.csv')
ANOMALY_THRESHOLD = 0.85 
BATCH_SIZE = 32
SNIFF_TIMEOUT = 10         
GDPR_COMPLIANCE = True
EDGE_INTERFACE = 'eth0'
PREVENTION_ACTIONS = {
    'signature': 'block',
    'anomaly': 'throttle'
}

# Feature names for packet feature extraction
FEATURE_NAMES = [
    'src_bytes', 'protocol_type', 'dst_bytes', 'count', 'srv_count',
    'device_com_ratio', 'service_mqtt', 'service_http', 'service_other'
]
