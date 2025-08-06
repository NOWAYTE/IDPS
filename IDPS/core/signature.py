import csv
import logging
from scapy.all import TCP, UDP, Raw, IP

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Use INFO in production; change to DEBUG for detailed view
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger('SignatureDetector')

class SignatureDetector:
    def __init__(self, signature_db_path: str):
        self.signatures = self.load_signatures(signature_db_path)
        logger.info(f"✅ Loaded {len(self.signatures)} signatures from '{signature_db_path}'")

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
                            'proto': row['protocol'].strip().lower(),
                            'dst_port': int(row['src_port']) if row['src_port'].isdigit() else 0,
                            'pattern': pattern
                        })
                    except Exception as e:
                        logger.error(f"❌ Error loading signature {row.get('id', 'unknown')}: {e}")
        except Exception as e:
            logger.error(f"❌ Failed to load signature database: {e}")
        return signatures

    def match_signature(self, packet):
        if not hasattr(packet, 'haslayer'):
            logger.warning("⚠️ Invalid packet format: no layer info")
            return False, None

        for sig in self.signatures:
            if self._packet_matches(packet, sig):
                logger.info(f"🚨 Match: [{sig['attack_name']}] (ID: {sig['id']})")
                return True, sig['attack_name']
        return False, None

    def _get_proto_layer(self, packet, proto):
        proto = proto.upper()
        if proto == 'TCP' and packet.haslayer(TCP):
            return packet[TCP]
        elif proto == 'UDP' and packet.haslayer(UDP):
            return packet[UDP]
        elif proto == 'IP' and packet.haslayer(IP):
            return packet[IP]
        return None

    def _packet_matches(self, packet, signature):
        proto_layer = self._get_proto_layer(packet, signature['proto'])
        if not proto_layer:
            return False

        if signature['dst_port'] > 0 and hasattr(proto_layer, 'dport'):
            if proto_layer.dport != signature['dst_port']:
                return False

        if not signature['pattern']:
            return True

        if not packet.haslayer(Raw):
            return False

        payload = packet[Raw].load
        if signature['pattern'] in payload:
            return True

        return False
