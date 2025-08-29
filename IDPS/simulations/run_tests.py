#!/usr/bin/env python3
"""
IDPS Test Runner - Fixed Version

This script automates the execution of all test scenarios and generates a comprehensive report.
"""

import os
import sys
import time
import subprocess
import json
import shutil
from datetime import datetime
from pathlib import Path
import random

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from config import BASE_DIR

# Test scenarios to run
TEST_SCENARIOS = [
    'baseline',
    'ddos_attack',
    'reconnaissance',
    'iot_exploit',
    'mixed_threats'
]

# Timeout for each scenario (in seconds)
SCENARIO_TIMEOUT = 1800  # 30 minutes

def cleanup_between_scenarios():
    """Ensure clean environment between test scenarios"""
    print("\n[+] Cleaning up between scenarios...")
    
    # Import cleanup function from mininet_iot
    try:
        from mininet_iot import cleanup_network
        cleanup_network()
    except ImportError:
        print("[!] Could not import cleanup_network from mininet_iot")
        # Fallback cleanup commands
        cleanup_cmds = [
            'sudo mn -c >/dev/null 2>&1',
            'sudo pkill -f "python.*mininet"',
            'sudo pkill -f "ovs-vswitchd"',
            'sudo pkill -f "ovsdb-server"',
            'sudo rm -rf /var/run/openvswitch/*',
            'sudo service openvswitch-switch restart',
        ]
        
        for cmd in cleanup_cmds:
            try:
                subprocess.run(cmd, shell=True, check=True, timeout=60)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
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
    
    # Create log directory
    log_dir = os.path.join(BASE_DIR, 'results', f'{scenario}_logs')
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(log_dir, f'{scenario}_{timestamp}.log')
    
    try:
        # Run the scenario with both stdout and stderr redirected
        cmd = [
            "sudo", "python3", 
            os.path.join('simulations', 'mininet_iot.py'), 
            scenario
        ]
        
        with open(log_file, 'w') as f_log:
            process = subprocess.Popen(
                cmd,
                cwd=project_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            start_time = time.time()
            timeout_reached = False
            
            # Capture and log all output in real-time
            while True:
                # Check for timeout
                if time.time() - start_time > SCENARIO_TIMEOUT:
                    process.kill()
                    timeout_reached = True
                    break
                    
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
        
        if timeout_reached:
            print(f"[!] Scenario {scenario} timed out after {SCENARIO_TIMEOUT} seconds")
            return False
            
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
        print(f"[!] Error running scenario {scenario}: {str(e)}")
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                print("\nLog file contents:")
                print(f.read())
        return False

def run_idps_analysis(scenario):
    """Run IDPS analysis on the captured data for a scenario"""
    print(f"\n[+] Running IDPS analysis for {scenario}")
    
    # Ensure the analysis module exists
    analysis_script = os.path.join(project_root, 'analysis', 'analyze_pcap.py')
    if not os.path.exists(analysis_script):
        print(f"[!] Analysis script not found at {analysis_script}")
        return False
    
    # Find the latest pcap file for this scenario
    pcap_dir = os.path.join(BASE_DIR, 'pcaps')
    scenario_pcaps = []
    
    if os.path.exists(pcap_dir):
        for file in os.listdir(pcap_dir):
            if file.startswith(scenario) and file.endswith('.pcap'):
                scenario_pcaps.append(os.path.join(pcap_dir, file))
    
    if not scenario_pcaps:
        print(f"[!] No pcap files found for scenario {scenario}")
        return False
    
    # Use the most recent pcap file
    latest_pcap = max(scenario_pcaps, key=os.path.getctime)
    
    # Run the analysis
    try:
        cmd = [
            "python3", analysis_script,
            "--pcap", latest_pcap,
            "--scenario", scenario,
            "--output", os.path.join(BASE_DIR, 'results', f'{scenario}_results.json')
        ]
        
        result = subprocess.run(cmd, cwd=project_root, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            print(f"[!] Analysis failed for {scenario}: {result.stderr}")
            return False
            
        print(f"[+] Analysis completed for {scenario}")
        return True
        
    except subprocess.TimeoutExpired:
        print(f"[!] Analysis timed out for {scenario}")
        return False
    except Exception as e:
        print(f"[!] Error running analysis for {scenario}: {str(e)}")
        return False

def generate_report(scenarios):
    """Generate a test report from all scenario results"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "scenarios": {}
    }
    
    for scenario in scenarios:
        # First run the IDPS analysis
        analysis_success = run_idps_analysis(scenario)
        
        if analysis_success:
            # Try to import the results analyzer
            try:
                from utils.results_analyzer import analyze_scenario
                # Then analyze the scenario results
                metrics = analyze_scenario(scenario)
                if metrics:
                    report["scenarios"][scenario] = metrics
                else:
                    report["scenarios"][scenario] = {
                        "status": "ANALYSIS_COMPLETE",
                        "message": "No metrics returned from analyzer"
                    }
            except ImportError:
                print(f"[!] Could not import results_analyzer for {scenario}")
                report["scenarios"][scenario] = {
                    "status": "ANALYSIS_COMPLETE",
                    "message": "Could not import results analyzer"
                }
        else:
            report["scenarios"][scenario] = {
                "status": "ANALYSIS_FAILED",
                "error": "IDPS analysis failed for this scenario"
            }
    
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
    
    # Ensure pcap directory exists
    pcap_dir = os.path.join(BASE_DIR, 'pcaps')
    os.makedirs(pcap_dir, exist_ok=True)
    
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
    
    # Check if report is empty
    if os.path.exists(report_path):
        with open(report_path, 'r') as f:
            content = f.read().strip()
            if not content:
                print("\n[WARNING] Report file is empty!")
            else:
                print("\n[SUCCESS] Report generated successfully")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTest suite interrupted by user")
        sys.exit(1)