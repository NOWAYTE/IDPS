import os
import json
import pandas as pd
from compliance.audit_verifier import AuditVerifier
import sys
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
from config import BASE_DIR

def analyze_scenario(scenario):
    """Analyze IDPS performance for a test scenario"""
    log_dir = os.path.join(BASE_DIR, 'results', f'{scenario}_logs')
    if not os.path.exists(log_dir):
        return None
    
    # Initialize verifier (use actual key in production)
    verifier = AuditVerifier(encryption_key=os.urandom(32))
    
    # Find and verify log file
    log_files = [f for f in os.listdir(log_dir) if f.endswith('.enc')]
    if not log_files:
        return None
    
    log_file = os.path.join(log_dir, log_files[0])
    events = verifier.verify_log_file(log_file)
    
    # Filter out header entries
    events = [e for e in events if 'event_type' in e]
    
    # Calculate metrics
    df = pd.DataFrame(events)
    metrics = {
        'scenario': scenario,
        'total_events': len(df),
        'detection_events': len(df[df['event_type'] != 'normal']),
        'attack_types': df['event_type'].value_counts().to_dict(),
        'prevention_actions': df['action'].value_counts().to_dict(),
        'avg_confidence': df['confidence'].mean() if 'confidence' in df else 0,
        'max_latency': df['latency'].max() if 'latency' in df else 0
    }
    
    return metrics

def generate_report(scenarios):
    """Generate comprehensive test report"""
    report = {"scenarios": {}}
    
    for scenario in scenarios:
        metrics = analyze_scenario(scenario)
        if metrics:
            report["scenarios"][scenario] = metrics
    
    # Save report
    report_path = os.path.join(BASE_DIR, 'results', 'test_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report_path

if __name__ == "__main__":
    scenarios = ['baseline', 'ddos_attack', 'reconnaissance', 'iot_exploit', 'mixed_threats']
    report_path = generate_report(scenarios)
    print(f"Generated report at: {report_path}")