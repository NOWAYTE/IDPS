import numpy as np
from ml.predict import AnomalyPredictor
from utils.feature_extraction import extract_packet_features
import config
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('AnomalyDetector')

class AnomalyDetector:
    def __init__(self):
        self.predictor = AnomalyPredictor()
        self.batch_buffer = []
        self.batch_count = 0
        self.packet_index_map = {}
        logger.info("AnomalyDetector initialized")
    
    def detect(self, packet):
        """Add packet to batch buffer and process when full"""
        try:
            # Extract features from packet
            features = extract_packet_features(packet, config.FEATURE_NAMES)
            logger.debug(f"Extracted features: {features}")
            
            # Store packet index for reference
            packet_id = id(packet)
            self.packet_index_map[packet_id] = len(self.batch_buffer)
            self.batch_buffer.append(features)
            
            # Process batch if full
            if len(self.batch_buffer) >= config.BATCH_SIZE:
                return self.process_batch()
            
            return False, 0.0  # Return placeholder
            
        except Exception as e:
            logger.error(f"Error in detect: {str(e)}", exc_info=True)
            return False, 0.0

    def process_batch(self):
        """Process a batch of packet features"""
        if not self.batch_buffer:
            logger.warning("process_batch called with empty buffer")
            return False, 0.0
            
        try:
            # Convert features to numpy array
            features_array = np.array([
                [f[name] for name in config.FEATURE_NAMES]
                for f in self.batch_buffer
            ])
            
            logger.debug(f"Processing batch of {len(features_array)} packets")
            
            # Get predictions
            probabilities = self.predictor.predict(features_array)
            
            # Find the highest probability in the batch
            max_prob = float(np.max(probabilities))
            is_anomaly = max_prob > config.ANOMALY_THRESHOLD
            
            logger.debug(f"Batch results - Max probability: {max_prob:.4f}, "
                        f"Threshold: {config.ANOMALY_THRESHOLD}, "
                        f"Anomaly: {is_anomaly}")
            
            # Log detailed info for anomalous batches
            if is_anomaly:
                logger.warning(f" Anomaly detected! Probability: {max_prob:.4f}")
                for i, prob in enumerate(probabilities):
                    if prob > config.ANOMALY_THRESHOLD:
                        logger.warning(f"  - Packet {i}: Probability = {prob:.4f}")
                        logger.debug(f"     Features: {self.batch_buffer[i]}")
            
            return is_anomaly, max_prob
            
        except Exception as e:
            logger.error(f"Error processing batch: {str(e)}", exc_info=True)
            return False, 0.0
            
        finally:
            # Clear buffer
            self.batch_buffer.clear()
            self.packet_index_map.clear()
            self.batch_count += 1

    def flush(self):
        """Process any remaining packets in the buffer"""
        if not self.batch_buffer:
            return []
            
        logger.debug(f"Flushing {len(self.batch_buffer)} packets from buffer")
        return self.process_batch()