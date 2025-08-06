import csv
import logging
from scapy.all import TCP, UDP, Raw, IP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger('SignatureDetector')

class SignatureDetector:
    def __init__(self, signature_db_path: str):
        self.signatures = self.load_signatures(signature_db_path)
        self._audit_logger = None
        logger.info(f"✅ Loaded {len(self.signatures)} signatures from '{signature_db_path}'")

    @property
    def audit_logger(self):
        if self._audit_logger is None:
            try:
                from compliance.audit_logger import audit_logger
                self._audit_logger = audit_logger
            except Exception as e:
                logger.warning(f"⚠️ Audit logger not available: {e}")
                # Create a dummy logger that does nothing
                class DummyLogger:
                    def log_event(self, *args, **kwargs):
                        pass
                self._audit_logger = DummyLogger()
        return self._audit_logger

    def load_signatures(self, db_path):
        signatures = []
        try:
            with open(db_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        pattern = bytes.fromhex(row['pattern']) if row['pattern'] else b''
                        signatures.append({
                            'id': row['id'],
                            'attack_name': row.get('attack_name', f"sig_{row['id']}"),
                            'severity': row.get('severity', 'medium'),
                            'proto': row['protocol'].strip().lower(),
                            'dst_port': int(row['src_port']) if row['src_port'].isdigit() else 0,
                            'pattern': pattern
                        })
                    except Exception as e:
                        logger.error(f"❌ Error loading signature {row.get('id', 'unknown')}: {e}")
                        continue
        except Exception as e:
            logger.error(f"❌ Failed to load signature database: {e}")
        return signatures

    def match_signature(self, packet):
        if not hasattr(packet, 'haslayer'):
            logger.warning("⚠️ Invalid packet format: no layer info")
            return False, None
            
        for sig in self.signatures:
            match, reason = self._packet_matches(packet, sig)
            if match:
                try:
                    ip_src = packet[IP].src if IP in packet else "unknown"
                    self.audit_logger.log_event(
                        event_type="signature_detection",
                        source_ip=ip_src,
                        action="detected",
                        details={
                            "signature_id": sig['id'],
                            "attack_name": sig['attack_name'],
                            "severity": sig['severity'],
                            "reason": reason
                        }
                    )
                    logger.info(f"🚨 Match: [{sig['attack_name']}] (ID: {sig['id']})")
                except Exception as e:
                    logger.warning(f"⚠️ Failed to log signature detection: {e}")
                return True, sig['id']
        return False, None

    def _get_proto_layer(self, packet, proto):
        proto = proto.upper()
        if proto == 'TCP' and packet.haslayer(TCP):
            return packet[TCP]
        elif proto == 'UDP' and packet.haslayer(UDP):
            return packet[UDP]
        return None

    def _packet_matches(self, packet, signature):
        proto_layer = self._get_proto_layer(packet, signature['proto'])
        if not proto_layer:
            return False, "Protocol mismatch"

        # Get packet info for logging
        pkt_info = {
            'src': packet[IP].src if packet.haslayer(IP) else 'N/A',
            'dst': packet[IP].dst if packet.haslayer(IP) else 'N/A',
            'sport': proto_layer.sport if hasattr(proto_layer, 'sport') else 'N/A',
            'dport': proto_layer.dport if hasattr(proto_layer, 'dport') else 'N/A',
            'has_raw': 'Yes' if packet.haslayer(Raw) else 'No'
        }
        logger.debug(f"Checking packet: {pkt_info}")

        # Check destination port if defined
        if signature['dst_port'] > 0 and hasattr(proto_layer, 'dport'):
            if proto_layer.dport != signature['dst_port']:
                logger.debug(f"Port mismatch: {proto_layer.dport} (dport) != {signature['dst_port']} (expected)")
                return False, "Port mismatch"

        # If no pattern to match, consider it a match if we got this far
        if not signature['pattern']:
            logger.debug("No pattern to match, port matched")
            return True, "Port matched"
            
        # Check for raw data if pattern exists
        if not packet.haslayer(Raw):
            logger.debug("No Raw layer in packet to match pattern")
            return False, "No payload to inspect"
            
        payload = packet[Raw].load
        logger.debug(f"Payload (hex): {payload.hex()}")
        
        if signature['pattern'] in payload:
            logger.warning(f"🚨 Pattern match found: {signature['pattern'].hex()} for {signature['attack_name']}")
            return True, f"Pattern matched: {signature['pattern'].hex()[:16]}..."
            
        logger.debug("Pattern not found in payload")
        return False, "Pattern not found"
