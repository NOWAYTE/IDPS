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
import traceback

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

def get_audit_logger():
    """Initialize audit logger"""
    from compliance.audit_logger import AuditLogger
    return AuditLogger(test_mode=True)

def run_test_scenario(scenario_name, timeout_seconds=300):
    """Run a single test scenario with timeout and proper cleanup"""
    logger = get_audit_logger()
    start_time = time.time()
    test_passed = False
    error_message = None
    test_run_id = f"{scenario_name}_{int(start_time)}"
    
    try:
        # Set test name for logging
        os.environ['TEST_NAME'] = test_run_id
        
        logger.log_event(
            event_type="test_started",
            description=f"Starting test scenario: {scenario_name}",
            severity="info",
            details={
                "test_name": scenario_name,
                "test_run_id": test_run_id
            }
        )
        
        # Run the test in a separate process with timeout
        cmd = [sys.executable, "mininet_iot.py", "--test", scenario_name]
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_seconds
            )
            
            # Check test results
            if result.returncode == 0:
                test_passed = True
                logger.log_event(
                    event_type="test_passed",
                    description=f"Test scenario passed: {scenario_name}",
                    severity="info",
                    details={
                        "test_name": scenario_name,
                        "test_run_id": test_run_id,
                        "stdout": result.stdout[-2000:],  # Last 2000 chars of output
                        "execution_time": time.time() - start_time
                    }
                )
            else:
                error_message = f"Test failed with return code {result.returncode}"
                logger.log_event(
                    event_type="test_failed",
                    description=f"Test scenario failed: {scenario_name}",
                    severity="error",
                    details={
                        "test_name": scenario_name,
                        "test_run_id": test_run_id,
                        "return_code": result.returncode,
                        "stdout": result.stdout[-2000:],
                        "stderr": result.stderr[-2000:],
                        "execution_time": time.time() - start_time
                    }
                )
                
        except subprocess.TimeoutExpired:
            error_message = f"Test timed out after {timeout_seconds} seconds"
            logger.log_event(
                event_type="test_timeout",
                description=f"Test scenario timed out: {scenario_name}",
                severity="error",
                details={
                    "test_name": scenario_name,
                    "test_run_id": test_run_id,
                    "timeout_seconds": timeout_seconds
                }
            )
            
    except Exception as e:
        error_message = f"Unexpected error: {str(e)}"
        logger.log_event(
            event_type="test_error",
            description=f"Unexpected error in test scenario: {scenario_name}",
            severity="critical",
            details={
                "test_name": scenario_name,
                "test_run_id": test_run_id,
                "error": str(e),
                "traceback": traceback.format_exc()
            }
        )
        
    finally:
        # Ensure cleanup happens even if test fails
        try:
            from mininet_iot import cleanup_network
            cleanup_network()
        except Exception as e:
            logger.log_event(
                event_type="cleanup_error",
                description="Error during test cleanup",
                severity="error",
                details={
                    "test_name": scenario_name,
                    "test_run_id": test_run_id,
                    "error": str(e)
                }
            )
    
    return {
        "name": scenario_name,
        "passed": test_passed,
        "error": error_message,
        "duration": time.time() - start_time
    }

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
            # Run the test scenario
            result = run_test_scenario(scenario)
            scenario_report['success'] = result['passed']
            scenario_report['error'] = result['error']
            
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
            
            # Update summary
            if scenario_report['success']:
                report['summary']['passed'] += 1
            else:
                report['summary']['failed'] += 1
                
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
        result = run_test_scenario(scenario)
        results[scenario] = result
    
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
        print(f"{scenario:20} {result['passed']}")
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
