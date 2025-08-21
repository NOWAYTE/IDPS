import json
import os
import pandas as pd
import re
from datetime import datetime
from collections import defaultdict

# Base directory for the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, 'results')

def find_log_files():
    """Find all log files in the results directory"""
    log_files = []
    for root, _, files in os.walk(RESULTS_DIR):
        for file in files:
            if file.endswith('.log'):
                log_files.append(os.path.join(root, file))
    return log_files

def parse_log_file(log_file):
    """Parse a single log file and extract detections and metrics"""
    detections = []
    metrics = []
    
    # Extract test type from filename (e.g., 'ddos_attack' from 'ddos_attack_20250821_232037.log')
    test_type = os.path.basename(log_file).split('_')[0] + '_' + os.path.basename(log_file).split('_')[1]
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                    
                # Try to parse as JSON (for detections)
                if line.startswith('{') and line.endswith('}'):
                    try:
                        data = json.loads(line)
                        if 'type' in data and 'timestamp' in data:  # This looks like a detection
                            data['test_type'] = test_type
                            detections.append(data)
                    except json.JSONDecodeError:
                        pass
                
                # Parse metrics (e.g., packet counts, scan results)
                metrics_match = re.search(r'(\d{2}:\d{2}):\s*(\w+):?\s*(\d+)', line)
                if metrics_match:
                    timestamp, metric_name, value = metrics_match.groups()
                    metrics.append({
                        'timestamp': datetime.now().strftime('%Y-%m-%d ') + timestamp,
                        'metric': metric_name.lower(),
                        'value': float(value),
                        'test_type': test_type
                    })
    except Exception as e:
        print(f"Error parsing {log_file}: {e}")
    
    return detections, metrics

def load_detections():
    """Load detections from all log files"""
    log_files = find_log_files()
    all_detections = []
    
    if not log_files:
        print(f"No log files found in {RESULTS_DIR}")
        return []
    
    for log_file in log_files:
        detections, _ = parse_log_file(log_file)
        all_detections.extend(detections)
    
    print(f"Loaded {len(all_detections)} detections from {len(log_files)} log files")
    return all_detections

def load_metrics():
    """Load metrics from all log files"""
    log_files = find_log_files()
    all_metrics = []
    
    if not log_files:
        print(f"No log files found in {RESULTS_DIR}")
        return None
    
    for log_file in log_files:
        _, metrics = parse_log_file(log_file)
        all_metrics.extend(metrics)
    
    if not all_metrics:
        print("No metrics found in log files")
        return None
        
    return pd.DataFrame(all_metrics)

def generate_report():
    """Generate a comprehensive test report"""
    print("\n=== IDPS Test Results Report ===\n")
    print(f"Analyzing logs from: {RESULTS_DIR}\n")
    
    # Load data
    detections = load_detections()
    metrics_df = load_metrics()
    
    # Print detection summary
    if detections:
        print("=== DETECTIONS BY TEST TYPE ===")
        detection_counts = defaultdict(lambda: defaultdict(int))
        
        # Count detections by type and test
        for d in detections:
            test_type = d.get('test_type', 'unknown')
            detection_type = d.get('type', 'unknown')
            detection_counts[test_type][detection_type] += 1
        
        # Print detections by test type
        for test_type, counts in detection_counts.items():
            print(f"\n{test_type.replace('_', ' ').title()}:")
            for d_type, count in counts.items():
                print(f"  - {d_type.upper()}: {count}")
        
        # Print sample detections
        print("\nSample detections:")
        for d in detections[:3]:
            print(f"  - [{d.get('test_type', 'unknown')}] {d.get('timestamp')}: {d.get('type')} (confidence: {d.get('confidence', 0):.2f})")
    else:
        print("No detections found in log files")
    
    # Print metrics summary if available
    if metrics_df is not None and not metrics_df.empty:
        print("\n=== METRICS ===")
        print(f"Total metrics collected: {len(metrics_df)}")
        
        # Group by test type and metric
        if 'test_type' in metrics_df.columns:
            print("\nMetrics by test type:")
            for test_type, group in metrics_df.groupby('test_type'):
                print(f"\n{test_type.replace('_', ' ').title()}:")
                for metric, metric_group in group.groupby('metric'):
                    print(f"  - {metric}: {len(metric_group)} records")
                    if 'value' in metric_group.columns and pd.api.types.is_numeric_dtype(metric_group['value']):
                        print(f"    Avg: {metric_group['value'].mean():.2f}")
    
    print("\n=== REPORT COMPLETE ===\n")
    print(f"For detailed analysis, see the log files in: {RESULTS_DIR}")

if __name__ == "__main__":
    generate_report()
