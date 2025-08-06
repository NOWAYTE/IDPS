from scapy.all import sniff, Ether
from core.detector import HybridDetector
from edge.prevention import PreventionEngine
from utils.performance_monitor import PerformanceMonitor
from compliance.anonymizer import anonymize_ip
import config
import time

class EdgeNode:
    def __init__(self):
        self.detector = HybridDetector()
        self.prevention = PreventionEngine()
        self.monitor = PerformanceMonitor()
        self.stats = {'packets': 0, 'signatures': 0, 'anomalies': 0, 'clean': 0}
    
    def packet_handler(self, packet):
        start_time = time.perf_counter()
        self.stats['packets'] += 1

        if config.GDPR_COMPLIANCE and Ether in packet:
            if hasattr(packet[Ether], "src"):
                packet[Ether].src = anonymize_ip(packet[Ether].src)
        if hasattr(packet[Ether], "dst"):
            packet[Ether].dst = anonymize_ip(packet[Ether].dst)

        # Detection
        detection_type, confidence, sig_id = self.detector.analyze_packet(packet)

        # Fallbacks for None values
        detection_label = detection_type.upper() if detection_type else "UNKNOWN"
        conf_display = f"{confidence:.2f}" if confidence is not None else "N/A"

        # Live feedback
        status_msg = f"📦 Packet #{self.stats['packets']} | Detection: {detection_label}"
        if detection_type == 'signature' and sig_id:
            status_msg += f" | Signature: {sig_id}"
        status_msg += f" | Confidence: {conf_display}"
        print(status_msg)

        # Record latency
        latency = (time.perf_counter() - start_time) * 1000
        self.monitor.record(detection_type or "unknown", latency)
    
        # Update statistics
        if detection_type in self.stats:
            self.stats[detection_type] += 1
        if detection_type != 'clean':
            self.prevention.respond(packet, detection_type, confidence)

        if self.stats['packets'] % 10 == 0:
            self.report_status()

    def report_status(self):
        print(f"\n[STATUS] Packets: {self.stats['packets']} | "
              f"Signatures: {self.stats['signatures']} | "
              f"Anomalies: {self.stats['anomalies']}")
        self.monitor.report()
    
    def start(self, interface=None):
        sniff(iface=interface or config.EDGE_INTERFACE, 
              prn=self.packet_handler, 
              store=0,
            #   timeout=config.SNIFF_TIMEOUT
              )