import subprocess
from scapy.all import IP
import config

class PreventionEngine:
    def respond(self, packet, detection_type, confidence):
        action = config.PREVENTION_ACTIONS.get(detection_type, 'alert')
        ip_src = packet[IP].src if IP in packet else None
        
        if not ip_src:
            return

        audit_logger.log_event(
            event_type=detection_type,
            source_ip=ip_src or "unknown",
            action=action,
            confidence=confidence,
            details={
                "rule_applied": action,
                "target": ip_src
            }
        )
        
        if action == 'block':
            self.block_ip(ip_src)
        elif action == 'throttle':
            self.throttle_ip(ip_src)
        elif action == 'alert':
            self.send_alert(ip_src, detection_type, confidence)
    
    def block_ip(self, ip):
        """Block IP using iptables"""
        try:
            subprocess.run(
                ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True
            )
            print(f"Blocked IP: {ip}")
        except Exception as e:
            print(f"Block failed: {e}")
    
    def throttle_ip(self, ip, limit_kbps=50):
        """Throttle IP using tc"""
        try:
            # Create classful qdisc if not exists
            subprocess.run(
                ['sudo', 'tc', 'qdisc', 'add', 'dev', config.EDGE_INTERFACE, 
                 'root', 'handle', '1:', 'htb'], stderr=subprocess.DEVNULL
            )
            
            # Add class for this IP
            subprocess.run(
                ['sudo', 'tc', 'class', 'add', 'dev', config.EDGE_INTERFACE,
                 'parent', '1:', 'classid', '1:1', 'htb', 'rate', f'{limit_kbps}kbit']
            )
            
            # Add filter
            subprocess.run(
                ['sudo', 'tc', 'filter', 'add', 'dev', config.EDGE_INTERFACE,
                 'protocol', 'ip', 'parent', '1:', 'prio', '1', 'u32',
                 'match', 'ip', 'src', ip, 'flowid', '1:1']
            )
            print(f"Throttled IP: {ip} to {limit_kbps}Kbps")
        except Exception as e:
            print(f"Throttle failed: {e}")
    
    def send_alert(self, ip, detection_type, confidence):
        print(f"ALERT: {detection_type} threat from {ip} (confidence: {confidence:.2f})")