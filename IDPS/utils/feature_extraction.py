from scapy.all import IP, TCP, UDP
import config

def extract_packet_features(packet, feature_names):
    features = {name: 0.0 for name in feature_names}
    
    if IP in packet:
        features['src_bytes'] = np.log1p(len(packet[IP].payload))
        proto = packet[IP].proto
        features['protocol_type'] = {
            6: 0,   # TCP
            17: 1,  # UDP
            1: 2    # ICMP
        }.get(proto, 6)
        
        if TCP in packet:
            features['dst_bytes'] = np.log1p(packet[TCP].dport)
        elif UDP in packet:
            features['dst_bytes'] = np.log1p(packet[UDP].dport)
    
    features['count'] = 1
    features['srv_count'] = 1
    features['device_com_ratio'] = 1.0

    # One-hot services (if you can identify the app/service layer)
    features['service_mqtt'] = 0
    features['service_http'] = 1  # Example: set based on context
    features['service_other'] = 0

    return features