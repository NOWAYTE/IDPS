import csv
import logging
from scapy.all import TCP, UDP, Raw, IP

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG to see more detailed logs
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SignatureDetector')

class SignatureDetector:
    def __init__(self, signature_db_path: str):
        self.signatures = self.load_signatures(signature_db_path)
        logger.info(f"Initialized with {len(self.signatures)} signatures")

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
                            'src_port': int(row['src_port']) if row['src_port'].isdigit() else 0,
                            'pattern': pattern
                        })
                        logger.debug(f"Loaded signature: {row['id']} - {row.get('attack_name', '')}")
                    except Exception as e:
                        logger.error(f"Error loading signature {row.get('id', 'unknown')}: {str(e)}")
                        continue
        except Exception as e:
            logger.error(f"Failed to load signature database: {str(e)}")
            
        logger.info(f"Successfully loaded {len(signatures)} signatures from {db_path}")
        return signatures

    def match_signature(self, packet):
        if not hasattr(packet, 'haslayer'):
            logger.warning("Invalid packet format: no layer information")
            return False, None
            
        for sig in self.signatures:
            if self._packet_matches(packet, sig):
                logger.warning(f"🚨 Signature match: {sig['attack_name']} (ID: {sig['id']})")
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
        # Check protocol
        proto_layer = self._get_proto_layer(packet, signature['proto'])
        if not proto_layer:
            return False

        # Log packet info for debugging
        pkt_info = {
            'src': packet[IP].src if packet.haslayer(IP) else 'N/A',
            'dst': packet[IP].dst if packet.haslayer(IP) else 'N/A',
            'sport': proto_layer.sport if hasattr(proto_layer, 'sport') else 'N/A',
            'dport': proto_layer.dport if hasattr(proto_layer, 'dport') else 'N/A',
            'has_raw': 'Yes' if packet.haslayer(Raw) else 'No'
        }
        logger.debug(f"Checking packet: {pkt_info}")

        # Check source port if defined
        if signature['src_port'] > 0 and hasattr(proto_layer, 'sport'):
            if proto_layer.sport != signature['src_port']:
                logger.debug(f"Port mismatch: {proto_layer.sport} != {signature['src_port']}")
                return False

        # Check raw pattern
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            logger.debug(f"Payload (hex): {payload.hex()}")
            logger.debug(f"Looking for pattern: {signature['pattern'].hex()}")
            
            if signature['pattern'] in payload:
                logger.warning(f"Pattern match found in payload!")
                return True
            else:
                logger.debug("Pattern not found in payload")
        else:
            logger.debug("No Raw layer in packet")
            
        return False
