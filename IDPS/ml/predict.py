import joblib
import numpy as np
import logging
from config import FEATURE_NAMES, ML_MODEL_PATH

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('AnomalyPredictor')

class AnomalyPredictor:
    def __init__(self, model_path=None):
        self.model = None
        self._load_model(model_path or ML_MODEL_PATH)
    
    def _load_model(self, model_path):
        """Load and validate the ML model"""
        try:
            logger.info(f"Loading model from {model_path}")
            self.model = joblib.load(model_path)
            
            # Basic model validation
            if not hasattr(self.model, 'predict_proba'):
                raise AttributeError("Loaded model does not have predict_proba method")
                
            # Test prediction with dummy data
            test_features = np.zeros((1, len(FEATURE_NAMES)))
            try:
                _ = self.model.predict_proba(test_features)
                logger.info("Model loaded and validated successfully")
            except Exception as e:
                logger.error(f"Model validation failed: {str(e)}")
                raise
                
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            # Fallback to a simple model if loading fails
            from sklearn.ensemble import IsolationForest
            logger.warning("Falling back to default IsolationForest model")
            self.model = IsolationForest(contamination=0.1, random_state=42)
    
    def predict(self, features_array):
        """Predict anomaly probabilities for batch"""
        if self.model is None:
            logger.error("No model loaded, returning default prediction")
            return np.zeros(len(features_array))
            
        try:
            # If using IsolationForest, it returns -1 for anomalies and 1 for normal
            if hasattr(self.model, 'decision_function'):
                scores = self.model.decision_function(features_array)
                # Convert to probability-like scores between 0 and 1
                return 1 / (1 + np.exp(-scores))
            # For models with predict_proba
            elif hasattr(self.model, 'predict_proba'):
                return self.model.predict_proba(features_array)[:, 1]
            else:
                logger.warning("Model doesn't support probability predictions, using binary output")
                return self.model.predict(features_array).astype(float)
                
        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}")
            return np.zeros(features_array.shape[0])
    
    def predict_single(self, packet):
        """Predict single packet (less efficient)"""
        from utils.feature_extraction import extract_packet_features
        try:
            features = extract_packet_features(packet, FEATURE_NAMES)
            if not features:
                logger.warning("Failed to extract features from packet")
                return 0.0
                
            # Convert features to array and ensure correct shape
            feature_array = np.array([list(features.values())])
            if feature_array.shape[1] != len(FEATURE_NAMES):
                logger.error(f"Feature count mismatch: expected {len(FEATURE_NAMES)}, got {feature_array.shape[1]}")
                return 0.0
                
            return float(self.predict(feature_array)[0])
            
        except Exception as e:
            logger.error(f"Single prediction failed: {str(e)}")
            return 0.0
