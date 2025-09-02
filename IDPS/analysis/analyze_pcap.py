#!/usr/bin/env python3
"""
IDPS PCAP Analysis Script

This script analyzes PCAP files to detect potential security threats and generate reports.
"""

import os
import sys
import json
import argparse
from datetime import datetime
import pyshark
import numpy as np
from collections import defaultdict

# Constants
ANOMALY_THRESHOLD = 0.7  # Threshold for flagging anomalies

def analyze_pcap(pcap_file, scenario):
    """
    Analyze a PCAP file for potential security threats.
    
    Args:
        pcap_file (str): Path to the PCAP file
        scenario (str): Name of the test scenario
        
    Returns:
        dict: Analysis results
    """
    print(f"Analyzing {pcap_file} for scenario: {scenario}")
    
    # Initialize results
    results = {
        'scenario': scenario,
        'timestamp': datetime.utcnow().isoformat(),
        'total_packets': 0,
        'protocols': defaultdict(int),
        'source_ips': defaultdict(int),
        'destination_ips': defaultdict(int),
        'anomalies': [],
        'threats_detected': False
    }
    
    try:
        # Open the pcap file
        cap = pyshark.FileCapture(pcap_file, display_filter='tcp or udp or icmp')
        
        # Analyze packets
        for packet in cap:
            results['total_packets'] += 1
            
            # Track protocols
            try:
                protocol = packet.transport_layer
                if protocol:
                    results['protocols'][protocol] += 1
            except AttributeError:
                pass
                
            # Track source and destination IPs
            try:
                if hasattr(packet, 'ip'):
                    results['source_ips'][packet.ip.src] += 1
                    results['destination_ips'][packet.ip.dst] += 1
            except AttributeError:
                pass
        
        # Simple anomaly detection (can be enhanced with ML models)
        _detect_anomalies(results, scenario)
        
        cap.close()
        
    except Exception as e:
        results['error'] = f"Error analyzing pcap: {str(e)}"
    
    return results

def _detect_anomalies(results, scenario):
    """Detect anomalies based on traffic patterns"""
    # This is a simple example - you can enhance this with more sophisticated detection
    
    # Check for unusual protocol distribution
    total_packets = max(1, results['total_packets'])
    for proto, count in results['protocols'].items():
        ratio = count / total_packets
        
        # Example: Flag if more than 70% of traffic is a single protocol
        if ratio > ANOMALY_THRESHOLD:
            results['anomalies'].append({
                'type': 'protocol_distribution',
                'protocol': proto,
                'percentage': f"{ratio*100:.1f}%",
                'description': f"High concentration of {proto} traffic ({ratio*100:.1f}%)"
            })
    
    # Scenario-specific checks
    if scenario == 'ddos_attack':
        # Check for potential DDoS patterns
        if len(results['source_ips']) > 10:  # Many unique source IPs
            results['threats_detected'] = True
            results['anomalies'].append({
                'type': 'ddos_indicator',
                'description': 'Multiple source IPs detected, possible DDoS attack'
            })
    
    elif scenario == 'reconnaissance':
        # Check for port scanning patterns
        if len(results['destination_ips']) > 10:  # Many unique destination IPs
            results['threats_detected'] = True
            results['anomalies'].append({
                'type': 'reconnaissance',
                'description': 'Multiple destination IPs scanned, possible reconnaissance activity'
            })
    
    # Add more scenario-specific checks as needed

def save_results(results, output_file):
    """Save analysis results to a JSON file"""
    os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Analyze PCAP files for security threats')
    parser.add_argument('--pcap', required=True, help='Path to the PCAP file to analyze')
    parser.add_argument('--scenario', required=True, help='Test scenario name')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_arguments()
    
    # Check if pcap file exists
    if not os.path.exists(args.pcap):
        print(f"Error: PCAP file not found: {args.pcap}")
        sys.exit(1)
    
    # Run analysis
    results = analyze_pcap(args.pcap, args.scenario)
    
    # Save results
    save_results(results, args.output)
    print(f"Analysis complete. Results saved to {args.output}")

if __name__ == "__main__":
    main()
