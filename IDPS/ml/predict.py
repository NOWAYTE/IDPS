import joblib
import numpy as np
from config import FEATURE_NAMES

class AnomalyPredictor:
    def __init__(self, model_path=None):
        from config import ML_MODEL_PATH
        self.model = joblib.load(model_path or ML_MODEL_PATH)
    
    def predict(self, features_array):
        """Predict anomaly probabilities for batch"""
        return self.model.predict_proba(features_array)[:, 1]
    
    def predict_single(self, packet):
        """Predict single packet (less efficient)"""
        from utils.feature_extraction import extract_packet_features
        features = extract_packet_features(packet, FEATURE_NAMES)
        return self.predict(np.array([list(features.values())])[0])
