import joblib
import numpy as np

class AnomalyPredictor:
    def __init__(self, model_path=None):
        from config import ML_MODEL
        self.model = joblib.load(model_path or ML_MODEL)
    
    def predict(self, features_array):
        """Predict anomaly probabilities for batch"""
        return self.model.predict_proba(features_array)[:, 1]
    
    def predict_single(self, packet):
        """Predict single packet (less efficient)"""
        features = extract_packet_features(packet)
        return self.predict(np.array([list(features.values())])[0]