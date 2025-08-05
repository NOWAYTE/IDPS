from .signature import SignatureDetector
from .anomaly import AnomalyDetector
import config

class HybridDetector:
    def __init__(self):
        self.sig_detector = SignatureDetector(config.SIGNATURE_DB)
        self.anomaly_detector = AnomalyDetector(config.ML_MODEL_PATH)
    
    def analyze_packet(self, packet):
        """Signature-based detection"""
        sig_match, sig_id = self.sig_detector.match_signature(packet)
        if sig_match:
            return "signature", sig_id
        
        anomaly, confidence = self.anomaly_detector.detect_anomaly(packet)
        if anomaly:
            return "anomaly", confidence
        
        return "clean", None