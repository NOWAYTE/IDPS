import joblib
import numpy as np
from .feature_extractor import extract_packet_features

class AnomalyDetector:
    def __init__(self, model_path):
        self.model = joblib.load(model_path)
        self.feature_names = list(config.FEATURE_MAP.keys())
    
    def detect_anomaly(self, packet):
        """Detect anomalies using ML model"""
        features = extract_packet_features(packet, self.feature_names)
        features_array = np.array([list(features.values())])
        probability = self.model.predict_proba(features_array)[0][1]
        return probability > config.ANOMALY_THRESHOLD, probability