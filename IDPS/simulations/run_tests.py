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

def run_scenario(scenario):
    """Run a single test scenario and return execution status"""
    print(f"\n{'='*50}")
    print(f"Starting scenario: {scenario}")
    print(f"{'='*50}")
    
    try:
        # Run the scenario
        cmd = f"sudo python3 {os.path.join('simulations', 'mininet_iot.py')} {scenario}"
        process = subprocess.Popen(
            cmd,
            shell=True,
            cwd=project_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for the scenario to complete
        stdout, stderr = process.communicate()
        
        # Log the output
        log_dir = os.path.join(BASE_DIR, 'results', f'{scenario}_logs')
        os.makedirs(log_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        with open(os.path.join(log_dir, f'{scenario}_{timestamp}.log'), 'w') as f:
            f.write(f"=== STDOUT ===\n{stdout}\n")
            f.write(f"\n=== STDERR ===\n{stderr}")
        
        if process.returncode != 0:
            print(f"[!] Scenario {scenario} failed with return code {process.returncode}")
            print(f"[!] Error: {stderr}")
            return False
            
        return True
        
    except Exception as e:
        print(f"[!] Error running scenario {scenario}: {e}")
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
        
        # Brief pause between scenarios
        if scenario != TEST_SCENARIOS[-1]:
            print("\nPreparing next scenario...")
            time.sleep(5)
    
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
