SIGNATURE_DB = "data/signatures.csv"
ML_MODEL_PATH = "ml/models/iot_idps_model.joblib"
EDGE_INTERFACE = "eth0"
GDPR_COMPLIANCE = True

FEATURE_MAP = {
    'protocol': 0, 
    'src_bytes': 1,
    'dst_bytes': 2,
    'duration': 3,
    'count': 4,
    'srv_count': 5
}

SIGNATURE_CONFIDENCE = 0.95
ANOMALY_THRESHOLD = 0.85