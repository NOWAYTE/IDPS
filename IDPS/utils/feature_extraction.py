from scapy.all import IP, TCP, UDP
import config

def extract_packet_features(packet, feature_names):
    """Extract relevant features from network packet"""
    features = {name: 0 for name in feature_names}
    
    if IP in packet:
        features['src_bytes'] = len(packet[IP].payload)
        features['protocol'] = packet[IP].proto
        if TCP in packet:
            features['dst_bytes'] = packet[TCP].dport
            features['duration'] = 0 
        elif UDP in packet:
            features['dst_bytes'] = packet[UDP].dport
    features['count'] = 1 
    features['srv_count'] = 1
    
    return features