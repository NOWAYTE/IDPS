import numpy as np
from ml.predict import AnomalyPredictor
from utils.feature_extraction import extract_packet_features
import config

class AnomalyDetector:
    def __init__(self):
        self.predictor = AnomalyPredictor()
        self.batch_buffer = []
        self.batch_count = 0
    
    def detect(self, packet):
        """Add packet to batch buffer and process when full"""
        features = extract_packet_features(packet, config.FEATURE_NAMES)
        self.batch_buffer.append(features)
        
        if len(self.batch_buffer) >= config.BATCH_SIZE:
            return self.process_batch()
        
        return False, 0.0  # Return placeholder
    
    def process_batch(self):
        """Process accumulated packet features"""
        features_array = np.array([list(f.values()) for f in self.batch_buffer])
        probabilities = self.predictor.predict(features_array)
        
        results = []
        for i, prob in enumerate(probabilities):
            is_anomaly = prob > config.ANOMALY_THRESHOLD
            results.append((is_anomaly, prob))
        
        # Clear buffer and return results
        self.batch_buffer.clear()
        self.batch_count += 1
        return results
    
    def flush(self):
        """Process remaining packets in buffer"""
        if self.batch_buffer:
            return self.process_batch()
        return []
