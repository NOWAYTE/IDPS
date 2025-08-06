from .signature import SignatureDetector
from .anomaly import AnomalyDetector
from compliance.audit_logger import AuditLogger
from scapy.all import IP
import config

class HybridDetector:
    def __init__(self):
        self.sig_detector = SignatureDetector(config.SIGNATURE_DB)
        self.anomaly_detector = AnomalyDetector()
        self.audit_logger = AuditLogger()
    
    def analyze_packet(self, packet):
        """Run signature and anomaly detection on a packet"""

        # Signature-based detection
        sig_match, sig_id = self.sig_detector.match_signature(packet)
        if sig_match:
            ip_src = packet[IP].src if IP in packet else "unknown"
            self.audit_logger.log_event(
                event_type="signature_detection",
                source_ip=ip_src,
                action="detected",
                details={
                    "signature_id": sig_id,
                    "protocol": packet.sprintf("%IP.proto%")
                }
            )
            return "signature", 1.0  # Use fixed confidence

        # ML-based anomaly detection
        anomaly, confidence = self.anomaly_detector.detect(packet)
        if anomaly:
            return "anomaly", confidence

        return "clean", None
