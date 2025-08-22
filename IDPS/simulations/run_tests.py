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
import logging
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from config import BASE_DIR
from utils.results_analyzer import analyze_scenario
from compliance.audit_verifier import AuditVerifier

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
    logger.info("Cleaning up between scenarios...")
    
    try:
        # Import cleanup function from mininet_iot
        from mininet_iot import cleanup_network
        cleanup_network()
    except Exception as e:
        logger.warning(f"Error during cleanup: {e}")
    
    # Additional cleanup commands
    cleanup_cmds = [
        'sudo pkill -f "python.*mininet" || true',
        'sudo pkill -f "ovs-vswitchd" || true',
        'sudo pkill -f "ovsdb-server" || true',
        'sudo rm -rf /var/run/openvswitch/* || true',
        'sudo service openvswitch-switch restart || true',
        'sudo mn -c >/dev/null 2>&1 || true',
    ]
    
    for cmd in cleanup_cmds:
        try:
            subprocess.run(cmd, shell=True, check=False)
        except Exception as e:
            logger.warning(f"Cleanup command failed: {cmd} - {e}")
    
    # Give the system a moment to stabilize
    time.sleep(5)

def run_scenario(scenario):
    """Run a single test scenario and return execution status"""
    logger.info(f"Starting scenario: {scenario}")
    
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
        cmd = [
            'sudo', 'python3', 
            os.path.join('simulations', 'mininet_iot.py'),
            scenario
        ]
        
        with open(log_file, 'w') as f:
            process = subprocess.Popen(
                cmd,
                cwd=project_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Stream output to both console and log file
            for line in process.stdout:
                print(line, end='')
                f.write(line)
                f.flush()
                
            # Wait for process to complete
            return_code = process.wait()
            
        if return_code != 0:
            logger.error(f"Scenario {scenario} failed with return code {return_code}")
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Error running scenario {scenario}: {e}", exc_info=True)
        return False
    finally:
        # Ensure audit logs are flushed
        if 'audit_logger' in locals():
            del audit_logger

def generate_report(scenarios):
    """Generate a test report from all scenario results"""
    report = {
        'timestamp': datetime.now().isoformat(),
        'scenarios': {},
        'summary': {
            'total': len(scenarios),
            'passed': 0,
            'failed': 0,
            'success_rate': 0.0
        }
    }
    
    # Create reports directory
    reports_dir = os.path.join(BASE_DIR, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    # Initialize audit verifier
    try:
        verifier = AuditVerifier()
    except Exception as e:
        logger.error(f"Failed to initialize audit verifier: {e}")
        verifier = None
    
    for scenario in scenarios:
        scenario_report = {
            'success': False,
            'error': None,
            'metrics': {},
            'audit': {
                'status': 'not_verified',
                'entries': 0,
                'error': None
            }
        }
        
        try:
            # Analyze scenario results
            metrics = analyze_scenario(scenario)
            scenario_report['metrics'] = metrics
            
            # Verify audit logs if verifier is available
            if verifier:
                log_dir = os.path.join(BASE_DIR, 'audit_logs')
                log_files = sorted([f for f in os.listdir(log_dir) 
                                 if f.startswith(f'audit_log_{scenario}')])
                
                if not log_files:
                    logger.warning(f"No audit logs found for scenario: {scenario}")
                    scenario_report['audit']['status'] = 'no_logs_found'
                else:
                    try:
                        log_path = os.path.join(log_dir, log_files[-1])  # Use most recent log
                        verified_entries = verifier.verify_log_file(log_path)
                        scenario_report['audit'].update({
                            'status': 'verified',
                            'entries': len(verified_entries),
                            'sample_entry': verified_entries[0] if verified_entries else None
                        })
                    except Exception as e:
                        logger.error(f"Failed to verify audit logs for {scenario}: {e}")
                        scenario_report['audit'].update({
                            'status': 'verification_failed',
                            'error': str(e)
                        })
            
            # Check if scenario was successful
            if metrics.get('success', False):
                report['summary']['passed'] += 1
                scenario_report['success'] = True
            else:
                report['summary']['failed'] += 1
                scenario_report['error'] = metrics.get('error', 'Unknown error')
                
        except Exception as e:
            logger.error(f"Error generating report for {scenario}: {e}")
            report['summary']['failed'] += 1
            scenario_report['error'] = str(e)
        
        report['scenarios'][scenario] = scenario_report
    
    # Calculate success rate
    if report['summary']['total'] > 0:
        report['summary']['success_rate'] = (
            report['summary']['passed'] / report['summary']['total'] * 100
        )
    
    # Save report to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(reports_dir, f'test_report_{timestamp}.json')
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    # Print summary
    print("\n" + "="*60)
    print(f"TEST EXECUTION SUMMARY - {timestamp}")
    print("="*60)
    print(f"{'Scenario':<20} {'Status':<10} {'Audit':<15} Details")
    print("-"*60)
    
    for scenario, data in report['scenarios'].items():
        status = 'PASSED' if data['success'] else 'FAILED'
        audit_status = data['audit']['status']
        details = data.get('error', '')
        print(f"{scenario:<20} {status:<10} {audit_status:<15} {details}")
    
    print("="*60)
    print(f"Total: {report['summary']['total']}  "
          f"Passed: {report['summary']['passed']}  "
          f"Failed: {report['summary']['failed']}  "
          f"Success Rate: {report['summary']['success_rate']:.1f}%")
    print(f"\nDetailed report saved to: {report_file}")
    print("="*60 + "\n")
    
    return report_file

def main():
    """Main function to run all test scenarios"""
    logger.info("Starting IDPS test suite")
    
    # Parse command line arguments
    scenarios_to_run = TEST_SCENARIOS
    if len(sys.argv) > 1:
        if sys.argv[1] == '--help':
            print(f"Usage: {sys.argv[0]} [scenario1 scenario2 ...]")
            print(f"Available scenarios: {', '.join(TEST_SCENARIOS)}")
            return
        scenarios_to_run = [s for s in sys.argv[1:] if s in TEST_SCENARIOS]
    
    # Run each scenario
    results = {}
    for scenario in scenarios_to_run:
        success = run_scenario(scenario)
        results[scenario] = 'PASSED' if success else 'FAILED'
    
    # Generate report
    try:
        report_path = generate_report(scenarios_to_run)
        logger.info(f"Test report saved to: {report_path}")
    except Exception as e:
        logger.error(f"Failed to generate test report: {e}", exc_info=True)
    
    # Print summary
    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    for scenario, result in results.items():
        print(f"{scenario:20} {result}")
    print("="*50)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Test execution interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
