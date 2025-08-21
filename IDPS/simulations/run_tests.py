#!/usr/bin/env python3
"""
IDPS Test Runner

This script automates the execution of all test scenarios and generates a comprehensive report.
"""

import os
import sys
import time
import subprocess
import json
from datetime import datetime
from pathlib import Path
import random

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from config import BASE_DIR
from utils.results_analyzer import analyze_scenario

# Test scenarios to run
TEST_SCENARIOS = [
    'baseline',
    'ddos_attack',
    'reconnaissance',
    'iot_exploit',
    'mixed_threats'
]

def cleanup_between_scenarios():
    """Ensure clean environment between test scenarios"""
    print("\n[+] Cleaning up between scenarios...")
    
    # Import cleanup function from mininet_iot
    from mininet_iot import cleanup_network
    
    # Run cleanup
    cleanup_network()
    
    # Additional cleanup commands
    cleanup_cmds = [
        'sudo pkill -f "python.*mininet"',
        'sudo pkill -f "ovs-vswitchd"',
        'sudo pkill -f "ovsdb-server"',
        'sudo rm -rf /var/run/openvswitch/*',
        'sudo service openvswitch-switch restart',
    ]
    
    for cmd in cleanup_cmds:
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] Warning during cleanup: {e}")
    
    # Give the system a moment to stabilize
    time.sleep(5)

def run_scenario(scenario):
    """Run a single test scenario and return execution status"""
    print(f"\n{'='*50}")
    print(f"Starting scenario: {scenario}")
    print(f"{'='*50}")
    
    # Clean up before starting the scenario
    cleanup_between_scenarios()
    
    # Initialize audit logger for this test
    from compliance.audit_logger import AuditLogger
    audit_logger = AuditLogger(test_mode=True, test_name=scenario)
    
    try:
        # Create log directory first
        log_dir = os.path.join(BASE_DIR, 'results', f'{scenario}_logs')
        os.makedirs(log_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(log_dir, f'{scenario}_{timestamp}.log')
        
        # Log test start
        audit_logger.log_event(
            event_type="test_start",
            description=f"Starting test scenario: {scenario}",
            severity="info"
        )
        
        # Run the scenario with both stdout and stderr redirected
        cmd = f"sudo python3 {os.path.join('simulations', 'mininet_iot.py')} {scenario} 2>&1"
        process = subprocess.Popen(
            cmd,
            shell=True,
            cwd=project_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        start_time = time.time()
        
        # Capture and log all output in real-time
        with open(log_file, 'w') as f_log:
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    # Write to log file
                    f_log.write(output)
                    f_log.flush()
                    
                    # Print to console with timestamp
                    elapsed = time.time() - start_time
                    mins = int(elapsed) // 60
                    secs = int(elapsed) % 60
                    print(f"[{mins:02d}:{secs:02d}] {output.strip()}")
                    
                    # Log important events to audit log
                    if "detected" in output.lower() or "alert" in output.lower():
                        audit_logger.log_event(
                            event_type="detection",
                            description=output.strip(),
                            severity="high" if "alert" in output.lower() else "medium"
                        )
        
        # Log test completion
        test_duration = time.time() - start_time
        audit_logger.log_event(
            event_type="test_complete",
            description=f"Completed test scenario: {scenario}",
            severity="info",
            duration=test_duration
        )
        
        # Ensure all logs are written
        audit_logger.shutdown()
        
        # Check return code
        return_code = process.poll()
        if return_code != 0:
            print(f"[!] Scenario {scenario} failed with return code {return_code}")
            # Show last 10 lines of log for debugging
            with open(log_file, 'r') as f:
                lines = f.readlines()
                print("\nLast 10 lines of log:")
                for line in lines[-10:]:
                    print(f"  {line.strip()}")
            return False
            
        print(f"[{int(time.time() - start_time)//60:02d}:{int(time.time() - start_time)%60:02d}] Scenario completed successfully")
        return True
        
    except Exception as e:
        # Log test failure
        audit_logger.log_event(
            event_type="test_error",
            description=f"Error in test scenario {scenario}: {str(e)}",
            severity="critical"
        )
        audit_logger.shutdown()
        print(f"[!] Error running scenario {scenario}: {str(e)}")
        if 'log_file' in locals() and os.path.exists(log_file):
            with open(log_file, 'r') as f:
                print("\nLog file contents:")
                print(f.read())
        return False

def generate_report(scenarios):
    """Generate a test report from all scenario results"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "scenarios": {}
    }
    
    for scenario in scenarios:
        metrics = analyze_scenario(scenario)
        if metrics:
            report["scenarios"][scenario] = metrics
    
    # Save the report
    report_dir = os.path.join(BASE_DIR, 'results')
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, 'test_report.json')
    
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report_path

def main():
    """Main function to run all test scenarios"""
    print("="*50)
    print("Starting IDPS Test Suite")
    print("="*50)
    
    # Initial cleanup
    cleanup_between_scenarios()
    
    # Ensure results directory exists
    results_dir = os.path.join(BASE_DIR, 'results')
    os.makedirs(results_dir, exist_ok=True)
    
    # Run each scenario
    results = {}
    for scenario in TEST_SCENARIOS:
        start_time = time.time()
        success = run_scenario(scenario)
        duration = time.time() - start_time
        
        results[scenario] = {
            "status": "PASS" if success else "FAIL",
            "duration_seconds": round(duration, 2)
        }
        
        # Clean up after each scenario
        cleanup_between_scenarios()
    
    # Generate final report
    print("\nGenerating test report...")
    report_path = generate_report(TEST_SCENARIOS)
    
    # Print summary
    print("\n" + "="*50)
    print("Test Suite Summary")
    print("="*50)
    for scenario, result in results.items():
        print(f"{scenario:<20} {result['status']:<6} ({result['duration_seconds']}s)")
    
    print(f"\nDetailed report generated at: {report_path}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTest suite interrupted by user")
        sys.exit(1)
