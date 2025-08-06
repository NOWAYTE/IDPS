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
        self.stats = {'packets': 0, 'signatures': 0, 'anomalies': 0}

    def packet_handler(self, packet):
        start_time = time.perf_counter()
        self.stats['packets'] += 1

    # GDPR-compliant anonymization (safe check)
        if config.GDPR_COMPLIANCE and Ether in packet:
            if hasattr(packet[Ether], "src") and hasattr(packet[Ether], "dst"):
                packet[Ether].src = anonymize_ip(packet[Ether].src)
                packet[Ether].dst = anonymize_ip(packet[Ether].dst)

    # Detection logic
        detection_type, confidence = self.detector.analyze_packet(packet)

    # Print feedback for every packet
        print(f"📦 Packet #{self.stats['packets']} | Detection: {detection_type.upper()} | Confidence: {confidence:.2f}")

    # Record performance
        latency = (time.perf_counter() - start_time) * 1000
        self.monitor.record(detection_type, latency)

    # React if necessary
        if detection_type != 'clean':
            self.stats[detection_type + 's'] += 1
        self.prevention.respond(packet, detection_type, confidence)

    # Show status every N packets
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