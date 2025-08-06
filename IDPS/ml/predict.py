import joblib
import numpy as np
import logging
from config import FEATURE_NAMES, ML_MODEL_PATH
from sklearn.ensemble import IsolationForest

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
    
    def _create_default_model(self):
        """Create a default IsolationForest model as fallback"""
        logger.warning("Creating default IsolationForest model")
        return IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
    
    def _load_model(self, model_path):
        """Load and validate the ML model"""
        try:
            logger.info(f"Attempting to load model from {model_path}")
            self.model = joblib.load(model_path)
            
            # Basic validation
            if not hasattr(self.model, 'predict'):
                raise AttributeError("Loaded model is missing required 'predict' method")
                
            # Test prediction with dummy data
            test_features = np.zeros((1, len(FEATURE_NAMES)))
            try:
                _ = self.model.predict(test_features)
                logger.info("Model loaded and validated successfully")
                return
            except Exception as e:
                logger.error(f"Model validation failed: {str(e)}")
                raise
                
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            logger.info("Falling back to default model")
            self.model = self._create_default_model()
    
    def predict(self, features_array):
        """Predict anomaly scores for a batch of features"""
        if self.model is None:
            logger.error("No model available for prediction")
            return np.zeros(len(features_array))
            
        try:
            # Get predictions based on model type
            if hasattr(self.model, 'decision_function'):  # For IsolationForest
                scores = self.model.decision_function(features_array)
                # Convert to probability-like scores between 0 and 1
                return 1 / (1 + np.exp(-scores))
            elif hasattr(self.model, 'predict_proba'):  # For classifiers
                return self.model.predict_proba(features_array)[:, 1]
            else:  # Fallback to binary prediction
                logger.warning("Model doesn't support probability predictions, using binary output")
                return self.model.predict(features_array).astype(float)
                
        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}")
            return np.zeros(len(features_array))
    
    def predict_single(self, packet):
        """Predict single packet (less efficient)"""
        from utils.feature_extraction import extract_packet_features
        
        try:
            features = extract_packet_features(packet, FEATURE_NAMES)
            if not features:
                logger.warning("Failed to extract features from packet")
                return 0.0
                
            # Convert features to array in correct order
            feature_array = np.array([[features.get(f, 0) for f in FEATURE_NAMES]])
            if feature_array.shape[1] != len(FEATURE_NAMES):
                logger.error(f"Feature count mismatch: expected {len(FEATURE_NAMES)}, got {feature_array.shape[1]}")
                return 0.0
                
            return float(self.predict(feature_array)[0])
            
        except Exception as e:
            logger.error(f"Single prediction failed: {str(e)}")
            return 0.0
