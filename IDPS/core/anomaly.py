import numpy as np
from ml.predict import AnomalyPredictor
from utils.feature_extraction import extract_packet_features
import config

class AnomalyDetector:
    def __init__(self):
        self.predictor = AnomalyPredictor()
        self.batch_buffer = []
        self.packet_index_map = []
    
    def detect(self, packet):
        """Add packet to buffer and return its anomaly prediction if batch is full"""
        features = extract_packet_features(packet, config.FEATURE_NAMES)
        self.batch_buffer.append(features)
        self.packet_index_map.append(packet)  # map back to original order

        if len(self.batch_buffer) >= config.BATCH_SIZE:
            return self.process_batch_and_return_last()

        return False, 0.0
    
    def process_batch_and_return_last(self):
        """Run batch prediction and return result for the most recent packet only"""
        features_array = np.array([
            [f[name] for name in config.FEATURE_NAMES]
            for f in self.batch_buffer
        ])

        probabilities = self.predictor.predict(features_array)

        # Take the last prediction (corresponds to the most recent packet)
        last_prob = probabilities[-1]
        is_anomaly = last_prob > config.ANOMALY_THRESHOLD

        # Clear buffer
        self.batch_buffer.clear()
        self.packet_index_map.clear()

        return is_anomaly, last_prob

    def flush(self):
        """Optionally process remaining packets"""
        if not self.batch_buffer:
            return []

        features_array = np.array([
            [f[name] for name in config.FEATURE_NAMES]
            for f in self.batch_buffer
        ])
        probabilities = self.predictor.predict(features_array)

        results = [(prob > config.ANOMALY_THRESHOLD, prob) for prob in probabilities]
        self.batch_buffer.clear()
        self.packet_index_map.clear()
        return results