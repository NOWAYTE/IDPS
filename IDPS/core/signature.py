import csv
from scapy.all import IP, TCP, UDP, Raw

class SignatureDetector:
    def __init__(self, signature_db):
        self.signatures = self.load_signatures(signature_db)
    
    def load_signatures(self, db_path):
        signatures = []
        with open(db_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                signatures.append({
                    'id': row['id'],
                    'proto': row['protocol'],
                    'src_port': int(row['src_port']),
                    'pattern': bytes.fromhex(row['pattern'])
                })
        return signatures

    def match_signature(self, packet):
        for sig in self.signatures:
            if self._packet_matches(packet, sig):
                return True, sig['id']
        return False, None

    def _packet_matches(self, packet, signature):
        proto_layer = self._get_proto_layer(packet, signature['proto'])
        if not proto_layer:
            return False
        
        if 'src_port' in signature and signature['src_port'] > 0:
            if proto_layer.sport != signature['src_port']:
                return False
        
        if Raw in packet and signature['pattern'] in packet[Raw].load:
            return True
        
        return False

    def _get_proto_layer(self, packet, proto_name):
        proto_map = {'tcp': TCP, 'udp': UDP}
        return packet.getlayer(proto_map.get(proto_name.lower()))