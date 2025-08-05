from .signature import SignatureDetector
from .anomaly import AnomalyDetector
import config

class HybridDetector:
    def __init__(self):
        self.sig_detector = SignatureDetector(config.SIGNATURE_DB)
        self.anomaly_detector = AnomalyDetector()
    
    def analyze_packet(self, packet):
        """Signature-based detection"""
        sig_match, sig_id = self.sig_detector.match_signature(packet)
        if sig_match:
            # Log signature detection
            ip_src = packet[IP].src if IP in packet else "unknown"
            audit_logger.log_event(
                event_type="signature_detection",
                source_ip=ip_src,
                action="detected",
                details={
                    "signature_id": sig_id,
                    "protocol": packet.sprintf("%IP.proto%")
                }
            )
            return "signature", sig_id
        
        anomaly, confidence = self.anomaly_detector.detect_anomaly(packet)
        if anomaly:
            return "anomaly", confidence
        
        return "clean", None