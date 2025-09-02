#!/usr/bin/env python3
"""
PCAP Analysis for IDPS

This script analyzes network traffic captures (PCAP files) to detect security threats
using machine learning models.
"""

import os
import sys
import json
import pyshark
import numpy as np
from datetime import datetime
from collections import defaultdict
from pathlib import Path

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from ml.predict import IDPSModel
from config import BASE_DIR

class PCAPAnalyzer:
    def __init__(self, model_path=None):
        """Initialize the PCAP analyzer with a trained model"""
        self.model = IDPSModel()
        if model_path:
            self.model.load(model_path)
        
        # Initialize statistics
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'source_ips': defaultdict(int),
            'destination_ips': defaultdict(int),
            'anomalies': [],
            'threats_detected': False,
            'start_time': None,
            'end_time': None
        }
    
    def analyze_pcap(self, pcap_file, scenario):
        """
        Analyze a PCAP file for security threats
        
        Args:
            pcap_file (str): Path to the PCAP file
            scenario (str): Test scenario name
            
        Returns:
            dict: Analysis results
        """
        print(f"Analyzing {pcap_file} for scenario: {scenario}")
        
        results = {
            'scenario': scenario,
            'timestamp': datetime.utcnow().isoformat(),
            'pcap_file': os.path.basename(pcap_file),
            'analysis': {
                'packet_count': 0,
                'protocols': {},
                'anomalies': [],
                'threats': [],
                'start_time': None,
                'end_time': None,
                'duration_seconds': 0
            },
            'threats_detected': False
        }
        
        try:
            # Open the pcap file
            cap = pyshark.FileCapture(
                pcap_file,
                display_filter='tcp or udp or icmp or mqtt or http',
                use_json=True
            )
            
            # Process packets
            for i, pkt in enumerate(cap):
                self._process_packet(pkt, results)
                
                # Print progress every 1000 packets
                if i > 0 and i % 1000 == 0:
                    print(f"Processed {i} packets...")
            
            # Finalize results
            self._finalize_analysis(results)
            
            # Run ML model on the results
            self._run_ml_analysis(results)
            
            return results
            
        except Exception as e:
            print(f"Error analyzing pcap: {str(e)}", file=sys.stderr)
            results['error'] = str(e)
            return results
        finally:
            if 'cap' in locals():
                cap.close()
    
    def _process_packet(self, pkt, results):
        """Process a single packet and update statistics"""
        try:
            # Update packet count
            results['analysis']['packet_count'] += 1
            
            # Track protocols
            if hasattr(pkt, 'transport_layer'):
                proto = pkt.transport_layer
                results['analysis']['protocols'][proto] = results['analysis']['protocols'].get(proto, 0) + 1
            
            # Track IP addresses
            if hasattr(pkt, 'ip'):
                src = pkt.ip.src
                dst = pkt.ip.dst
                results['analysis'].setdefault('source_ips', {})[src] = results['analysis'].get('source_ips', {}).get(src, 0) + 1
                results['analysis'].setdefault('destination_ips', {})[dst] = results['analysis'].get('destination_ips', {}).get(dst, 0) + 1
            
            # Track timestamps
            if results['analysis']['start_time'] is None:
                results['analysis']['start_time'] = float(pkt.sniff_timestamp)
            results['analysis']['end_time'] = float(pkt.sniff_timestamp)
            
        except Exception as e:
            print(f"Error processing packet: {str(e)}", file=sys.stderr)
    
    def _finalize_analysis(self, results):
        """Finalize the analysis results"""
        # Calculate duration
        if results['analysis']['start_time'] and results['analysis']['end_time']:
            results['analysis']['duration_seconds'] = \
                results['analysis']['end_time'] - results['analysis']['start_time']
        
        # Convert protocols to regular dict for JSON serialization
        results['analysis']['protocols'] = dict(results['analysis']['protocols'])
    
    def _run_ml_analysis(self, results):
        """Run ML model on the analysis results"""
        try:
            # This is a placeholder for actual ML analysis
            # In a real implementation, you would:
            # 1. Extract features from the results
            # 2. Feed them to your ML model
            # 3. Update results with predictions
            
            # Example: Simple threshold-based anomaly detection
            if results['analysis'].get('packet_count', 0) > 10000:
                results['analysis']['anomalies'].append({
                    'type': 'high_packet_volume',
                    'severity': 'high',
                    'description': 'Unusually high number of packets detected',
                    'packet_count': results['analysis']['packet_count']
                })
                results['threats_detected'] = True
            
            # Add more detection logic here
            
        except Exception as e:
            print(f"Error in ML analysis: {str(e)}", file=sys.stderr)
            results['analysis']['errors'] = results['analysis'].get('errors', []) + [str(e)]

def save_results(results, output_file):
    """Save analysis results to a JSON file"""
    try:
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        # Save results
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"Results saved to {output_file}")
        return True
    except Exception as e:
        print(f"Error saving results: {str(e)}", file=sys.stderr)
        return False

def parse_arguments():
    """Parse command line arguments"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze PCAP files for security threats')
    parser.add_argument('--pcap', required=True, help='Path to the PCAP file to analyze')
    parser.add_argument('--scenario', required=True, help='Test scenario name')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    parser.add_argument('--model', help='Path to trained model (optional)')
    
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_arguments()
    
    # Check if pcap file exists
    if not os.path.exists(args.pcap):
        print(f"Error: PCAP file not found: {args.pcap}", file=sys.stderr)
        return 1
    
    # Initialize analyzer
    analyzer = PCAPAnalyzer(model_path=args.model)
    
    # Run analysis
    results = analyzer.analyze_pcap(args.pcap, args.scenario)
    
    # Save results
    save_results(results, args.output)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
