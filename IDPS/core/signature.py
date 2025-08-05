import csv
import logging
from scapy.all import TCP, UDP, Raw

logging.basicConfig(level=logging.INFO)

class SignatureDetector:
    def __init__(self, signature_db_path: str):
        self.signatures = self.load_signatures(signature_db_path)

    def load_signatures(self, db_path):
        signatures = []
        with open(db_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    pattern = bytes.fromhex(row['pattern']) if row['pattern'] else b''
                except ValueError:
                    logging.warning(f"Invalid hex pattern in signature {row['id']}")
                    pattern = b''
                
                signatures.append({
                    'id': row['id'],
                    'attack_name': row.get('attack_name', f"sig_{row['id']}"),
                    'proto': row['protocol'].strip().lower(),
                    'src_port': int(row['src_port']) if row['src_port'].isdigit() else 0,
                    'pattern': pattern
                })
        logging.info(f"Loaded {len(signatures)} signatures.")
        return signatures

    def match_signature(self, packet):
        for sig in self.signatures:
            if self._packet_matches(packet, sig):
                logging.info(f"🔴 Matched Signature: {sig['attack_name']} (ID: {sig['id']})")
                return True, sig['attack_name']
        return False, None

    def _packet_matches(self, packet, signature):
        proto_layer = self._get_proto_layer(packet, signature['proto'])
        if not proto_layer:
            return False

        # Check source port if defined
        if signature['src_port'] > 0 and hasattr(proto_layer, 'sport'):
            if proto_layer.sport != signature['src_port']:
                return False

        # Check raw pattern
        if Raw in packet and signature['pattern'] in packet[Raw].load:
            return True

        return False

    def _get_proto_layer(self, packet, proto_name):
        proto_map = {'tcp': TCP, 'udp': UDP}
        return packet.getlayer(proto_map.get(proto_name))
