import json
import os
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict

# Base directory for the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, 'results')

def find_detection_files():
    """Find all detection files in the results directory"""
    detection_files = []
    for root, _, files in os.walk(RESULTS_DIR):
        if 'detections.json' in files:
            detection_files.append(os.path.join(root, 'detections.json'))
    return detection_files

def load_detections():
    """Load and analyze detection events from all test runs"""
    detection_files = find_detection_files()
    
    if not detection_files:
        print(f"No detection files found in {RESULTS_DIR} or its subdirectories")
        return []
    
    all_detections = []
    for file_path in detection_files:
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    try:
                        all_detections.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        print(f"Error parsing detection in {file_path}: {e}")
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
    
    print(f"Loaded {len(all_detections)} detections from {len(detection_files)} files")
    return all_detections

def load_metrics():
    """Load and analyze metrics from all test runs"""
    metrics_files = []
    for root, _, files in os.walk(RESULTS_DIR):
        if 'metrics.csv' in files:
            metrics_files.append(os.path.join(root, 'metrics.csv'))
    
    if not metrics_files:
        print(f"No metrics files found in {RESULTS_DIR} or its subdirectories")
        return None
    
    all_metrics = []
    for file_path in metrics_files:
        try:
            df = pd.read_csv(file_path)
            df['source_file'] = os.path.basename(os.path.dirname(file_path))
            all_metrics.append(df)
        except Exception as e:
            print(f"Error loading metrics from {file_path}: {e}")
    
    if not all_metrics:
        return None
        
    return pd.concat(all_metrics, ignore_index=True)

def generate_report():
    """Generate a comprehensive test report"""
    print("\n=== IDPS Test Results Report ===\n")
    
    # Load data
    detections = load_detections()
    metrics_df = load_metrics()
    
    # Print detection summary
    if detections:
        print("=== DETECTIONS ===")
        detection_counts = defaultdict(int)
        for d in detections:
            detection_counts[d['type']] += 1
        
        for d_type, count in detection_counts.items():
            print(f"{d_type.upper()}: {count} detections")
        
        # Print sample detections
        print("\nSample detections:")
        for d in detections[:3]:  # Show first 3 detections
            print(f"  - {d['timestamp']}: {d['type']} (confidence: {d['confidence']:.2f})")
    else:
        print("No detections found")
    
    # Print metrics summary
    if metrics_df is not None and not metrics_df.empty:
        print("\n=== METRICS ===")
        print(f"Total metrics collected: {len(metrics_df)}")
        
        # Group by metric type
        metric_groups = metrics_df.groupby('metric')
        for metric, group in metric_groups:
            print(f"\n{metric.upper()}:")
            print(f"  Total: {len(group)}")
            if 'value' in group.columns:
                print(f"  Avg value: {group['value'].mean():.2f}")
    
    # Generate plots
    if metrics_df is not None and not metrics_df.empty:
        try:
            print("\nGenerating plots...")
            
            # Create results directory if it doesn't exist
            results_dir = Path(RESULTS_DIR)
            results_dir.mkdir(exist_ok=True)
            
            # Plot packet counts over time
            if 'packet_count' in metrics_df['metric'].values:
                plt.figure(figsize=(12, 6))
                pkts = metrics_df[metrics_df['metric'] == 'packet_count']
                pkts['timestamp'] = pd.to_datetime(pkts['timestamp'])
                pkts = pkts.set_index('timestamp')
                pkts['value'].plot(title='Packet Rate Over Time')
                plt.savefig(results_dir / 'packet_rate.png')
                print("  - Created packet_rate.png")
            
            # Plot detection types
            if detections:
                plt.figure(figsize=(10, 6))
                detection_types = [d['type'] for d in detections]
                pd.Series(detection_types).value_counts().plot(kind='bar')
                plt.title('Detection Types')
                plt.savefig(results_dir / 'detection_types.png')
                print("  - Created detection_types.png")
                
            # Plot port scan activity if present
            if 'port_scan' in metrics_df['metric'].values:
                plt.figure(figsize=(12, 6))
                scans = metrics_df[metrics_df['metric'] == 'port_scan']
                port_counts = scans['details'].value_counts().head(10)  # Top 10 ports
                port_counts.plot(kind='bar')
                plt.title('Top Scanned Ports')
                plt.savefig(results_dir / 'port_scan_activity.png')
                print("  - Created port_scan_activity.png")
                
        except Exception as e:
            print(f"Error generating plots: {e}")
    
    print("\n=== REPORT COMPLETE ===\n")
    print("For detailed analysis, see the files in the 'results' directory")

if __name__ == "__main__":
    generate_report()
