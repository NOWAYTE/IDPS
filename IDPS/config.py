import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ML_MODEL = os.path.join(BASE_DIR, 'ml', 'models', 'idps_rf_quantized.pkl')
SIGNATURE_DB = os.path.join(BASE_DIR, 'data', 'signatures.csv')
NSL_KDD_DATA = os.path.join(BASE_DIR, 'data', 'nsl_kdd.csv')
ANOMALY_THRESHOLD = 0.85 
BATCH_SIZE = 32          
GDPR_COMPLIANCE = True
EDGE_INTERFACE = 'eth0'
PREVENTION_ACTIONS = {
    'signature': 'block',
    'anomaly': 'throttle'
}