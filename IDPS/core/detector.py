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
        self.signature_counters = {}  # Track signature occurrences
    
    def analyze_packet(self, packet):
        """Run signature and anomaly detection on a packet"""
        # Get source IP for logging
        ip_src = packet[IP].src if IP in packet else "unknown"
        
        # Signature-based detection
        sig_match, sig_id = self.sig_detector.match_signature(packet)
        if sig_match:
            # Update signature counter
            self.signature_counters[sig_id] = self.signature_counters.get(sig_id, 0) + 1
            
            # Log the detection
            self.audit_logger.log_event(
                event_type="signature_detection",
                source_ip=ip_src,
                action="detected",
                details={
                    "signature_id": sig_id,
                    "protocol": packet.sprintf("%IP.proto%"),
                    "count": self.signature_counters[sig_id]  # Include current count
                }
            )
            return "signature", 1.0, sig_id  # Include sig_id in return

        # ML-based anomaly detection
        anomaly, confidence = self.anomaly_detector.detect(packet)
        if anomaly:
            self.audit_logger.log_event(
                event_type="anomaly_detection",
                source_ip=ip_src,
                action="detected",
                confidence=confidence,
                details={
                    "protocol": packet.sprintf("%IP.proto%")
                }
            )
            return "anomaly", confidence, None

        return "clean", None, None
