#!/usr/bin/env python3
import sys
import os
import traceback

# Add project root to Python path before any other imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Now import other modules
from compliance.audit_logger import AuditLogger
from config import BASE_DIR
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController, Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.link import TCLink
import subprocess
import time
import signal

# Global audit logger instance and encryption key
audit_logger = None
encryption_key = None

def get_audit_logger():
    """Get or create the audit logger instance with consistent encryption key"""
    global audit_logger, encryption_key
    if audit_logger is None:
        # Use the same encryption key for all loggers
        if encryption_key is None:
            from compliance.audit_logger import AuditLogger as AuditLoggerClass
            encryption_key = AuditLoggerClass.get_encryption_key()
        
        # Initialize logger with consistent test name and encryption key
        test_name = os.environ.get('TEST_NAME', 'mininet_iot')
        audit_logger = AuditLogger(
            test_mode=True, 
            test_name=test_name,
            encryption_key=encryption_key
        )
    return audit_logger

def cleanup_network():
    """Comprehensive network cleanup with timeouts and better process management"""
    logger = get_audit_logger()
    logger.log_event(
        event_type="cleanup_start",
        description="Starting network cleanup",
        severity="info"
    )
    
    def run_command(cmd, timeout=10):
        """Helper to run a command with timeout"""
        try:
            return subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout
            )
        except subprocess.TimeoutExpired:
            logger.log_event(
                event_type="cleanup_warning",
                description=f"Command timed out: {cmd}",
                severity="warning"
            )
            return None
        except Exception as e:
            logger.log_event(
                event_type="cleanup_error",
                description=f"Error running command '{cmd}': {str(e)}",
                severity="error"
            )
            return None
    
    # First, try to stop any running Mininet instances gracefully
    try:
        from mininet.clean import cleanup
        cleanup()
    except Exception as e:
        logger.log_event(
            event_type="cleanup_warning",
            description=f"Mininet cleanup failed: {str(e)}",
            severity="warning"
        )
    
    # List of commands to clean up network state with timeouts
    commands = [
        # Stop any running Mininet instances (5s timeout)
        ('sudo mn -c >/dev/null 2>&1 || true', 5),
        # Kill any remaining Python processes (5s timeout)
        ('sudo pkill -f "python.*mininet" || true', 5),
        (r'sudo pkill -f "python.*main\.py" || true', 5),
        # Clean up OVS (5s timeout)
        ('sudo ovs-vsctl del-br s1 2>/dev/null || true', 5),
        ('sudo ovs-vsctl del-manager 2>/dev/null || true', 5),
        ('sudo pkill -f "ovs-vswitchd" || true', 5),
        ('sudo pkill -f "ovsdb-server" || true', 5),
        # Clean up network namespaces (5s timeout)
        ('sudo ip -all netns delete 2>/dev/null || true', 5),
        # Clean up any remaining interfaces (5s timeout)
        ('sudo ip link del s1-eth1 2>/dev/null || true', 5),
        ('sudo ip link del s1-eth2 2>/dev/null || true', 5),
        ('sudo ip link del edge_router-eth0 2>/dev/null || true', 5),
        ('sudo ip link del therm-eth0 2>/dev/null || true', 5),
        ('sudo ip link del cam-eth0 2>/dev/null || true', 5),
        ('sudo ip link del lock-eth0 2>/dev/null || true', 5),
        ('sudo ip link del health-eth0 2>/dev/null || true', 5),
        ('sudo ip link del malicious-eth0 2>/dev/null || true', 5),
        # Clean up OVS data (5s timeout)
        ('sudo rm -rf /var/run/openvswitch/* 2>/dev/null || true', 5),
        # Final cleanup (10s timeout)
        ('sudo fuser -k 6633/tcp 2>/dev/null || true', 10),
        ('sudo fuser -k 6653/tcp 2>/dev/null || true', 10),
    ]
    
    # Execute each command with its specified timeout
    for cmd, timeout in commands:
        run_command(cmd, timeout)
    
    logger.log_event(
        event_type="cleanup_complete",
        description="Network cleanup completed",
        severity="info"
    )

def start_ovs_service():
    """Ensure Open vSwitch service is running with proper verification"""
    logger = get_audit_logger()
    
    def is_ovs_running():
        """Check if OVS is running and responsive"""
        try:
            result = subprocess.run(
                ['ovs-vsctl', 'show'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    # Check if OVS is already running
    if is_ovs_running():
        logger.log_event(
            event_type="ovs_info",
            description="OVS is already running",
            severity="info"
        )
        return True
    
    # Ensure OVS database directory exists with correct permissions
    ovs_db_dir = '/var/run/openvswitch'
    os.makedirs(ovs_db_dir, exist_ok=True)
    subprocess.run(['sudo', 'chmod', '755', ovs_db_dir], check=False)
    subprocess.run(['sudo', 'chown', '-R', 'openvswitch:openvswitch', ovs_db_dir], check=False)
    
    try:
        # Stop any running OVS processes
        logger.log_event(
            event_type="ovs_cleanup",
            description="Stopping any existing OVS processes",
            severity="info"
        )
        
        for proc in ['ovsdb-server', 'ovs-vswitchd']:
            subprocess.run(['sudo', 'pkill', '-f', proc], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE)
        
        # Give processes time to terminate
        time.sleep(2)
        
        # Initialize OVS database if it doesn't exist
        db_file = '/etc/openvswitch/conf.db'
        if not os.path.exists(db_file):
            os.makedirs(os.path.dirname(db_file), exist_ok=True)
            subprocess.run(['sudo', 'ovsdb-tool', 'create', db_file], check=True)
        
        # Set proper permissions on database file
        subprocess.run(['sudo', 'chown', 'openvswitch:openvswitch', db_file], check=False)
        
        # Start OVS database server
        logger.log_event(
            event_type="ovs_start",
            description="Starting OVS database server",
            severity="info"
        )
        
        db_server = subprocess.Popen(
            ['sudo', 'ovsdb-server', 
             '--remote=punix:/var/run/openvswitch/db.sock',
             '--remote=db:Open_vSwitch,Open_vSwitch,manager_options',
             '--pidfile', '--detach', '--log-file'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for database server to be ready
        time.sleep(2)
        
        # Initialize OVS database if needed
        logger.log_event(
            event_type="ovs_init",
            description="Initializing OVS database",
            severity="info"
        )
        
        subprocess.run(['sudo', 'ovs-vsctl', '--no-wait', 'init'], check=True)
        
        # Start OVS vswitch daemon
        logger.log_event(
            event_type="ovs_start",
            description="Starting OVS vswitch daemon",
            severity="info"
        )
        
        vswitchd = subprocess.Popen(
            ['sudo', 'ovs-vswitchd', '--pidfile', '--detach', '--log-file'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for OVS to be ready with timeout
        max_attempts = 10
        for attempt in range(max_attempts):
            if is_ovs_running():
                logger.log_event(
                    event_type="ovs_ready",
                    description="OVS is ready",
                    severity="info"
                )
                return True
            time.sleep(1)
        
        # If we get here, OVS didn't start properly
        raise RuntimeError("Failed to start OVS: timeout waiting for service to become ready")
        
    except Exception as e:
        logger.log_event(
            event_type="ovs_error",
            description=f"Failed to start OVS: {str(e)}",
            severity="error",
            details={
                "error": str(e),
                "traceback": traceback.format_exc()
            }
        )
        return False

class IoTTopo(Topo):
    """IoT Network Topology with all required devices for testing"""
    def build(self):
        # Define all devices with their IPs
        devices = [
            ('therm', '192.168.0.101/24'),     # thermostat
            ('cam', '192.168.0.102/24'),       # security_cam
            ('lock', '192.168.0.103/24'),      # smart_lock
            ('health', '192.168.0.104/24'),    # health_monitor
            ('malicious', '192.168.0.200/24'), # malicious_device
            ('edge', '192.168.0.1/24')         # edge_router
        ]
        
        # Add devices to network
        hosts = {}
        for name, ip in devices:
            hosts[name] = self.addHost(name, ip=ip)
        
        # Create switch
        s1 = self.addSwitch('s1')
        
        # Add all devices to switch
        for name in hosts.keys():
            self.addLink(hosts[name], s1)

def run_attack(host, attack_type):
    """Run specific attack from a host"""
    if attack_type == 'ddos':
        host.cmd('hping3 --flood --rand-source 192.168.0.1 &')
    elif attack_type == 'portscan':
        host.cmd('nmap -T4 -A 192.168.0.1 &')
    elif attack_type == 'mqtt':
        host.cmd('python simulations/attack_generators.py --attack mqtt &')
    info(f"Started {attack_type} attack from {host.name}\n")

def run_test_scenario(net, scenario):
    """Run predefined test scenario with audit logging"""
    audit_logger = get_audit_logger()
    
    info(f"=== Starting scenario: {scenario} ===\n")
    
    # Log the start of the scenario
    audit_logger.log_event(
        event_type="scenario_start",
        description=f"Starting scenario: {scenario}",
        severity="info"
    )
    
    try:
        # Start network
        net.start()
        
        # Get host objects
        hosts = {}
        for host in net.hosts:
            hosts[host.name] = host
        
        # Run scenario-specific test logic
        if scenario == "ddos_attack":
            # Start normal traffic
            for host in ['therm', 'cam', 'lock', 'health']:
                if host in hosts:
                    hosts[host].cmd('python3 -m http.server 80 &')
            
            # Start DDoS attack
            if 'malicious' in hosts:
                target = hosts['therm'].IP()
                info(f"Starting DDoS attack from malicious to {target}\n")
                hosts['malicious'].cmd(f'python3 -c "import os; os.system(\'hping3 -c 1000 -d 120 -S -w 64 -p 80 --flood {target} &\')"')
                
                # Log the attack
                audit_logger.log_event(
                    event_type="attack_started",
                    description=f"DDoS attack started from malicious to {target}",
                    severity="high"
                )
        
        # Add similar blocks for other scenarios...
        
        # Let the scenario run
        time.sleep(60)  # Run for 1 minute for testing
        
        # Log scenario completion
        audit_logger.log_event(
            event_type="scenario_complete",
            description=f"Completed scenario: {scenario}",
            severity="info"
        )
        
    except Exception as e:
        # Log any errors
        audit_logger.log_event(
            event_type="scenario_error",
            description=f"Error in scenario {scenario}: {str(e)}",
            severity="critical"
        )
        raise
    finally:
        # Ensure all logs are written
        audit_logger.shutdown()

def main(scenario=None):
    """Main function with enhanced testing capabilities"""
    # Set up signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logger = get_audit_logger()
        logger.log_event(
            event_type="shutdown_signal",
            description=f"Received signal {sig}, shutting down...",
            severity="warning"
        )
        cleanup_network()
        sys.exit(0)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize audit logging
    logger = get_audit_logger()
    
    try:
        # Log test start
        logger.log_event(
            event_type="test_start",
            description=f"Starting test scenario: {scenario}",
            severity="info"
        )
        
        # Initialize network
        start_ovs_service()
        
        # Create and start network
        topo = IoTTopo()
        net = Mininet(
            topo=topo,
            switch=OVSSwitch,
            controller=RemoteController('c0', ip='127.0.0.1', port=6633),
            link=TCLink,
            autoSetMacs=True,
            autoStaticArp=True
        )
        
        # Start network
        net.start()
        
        try:
            # Run the test scenario
            run_test_scenario(net, scenario)
            
            # Log successful completion
            logger.log_event(
                event_type="test_complete",
                description=f"Successfully completed test scenario: {scenario}",
                severity="info"
            )
            return 0
            
        except Exception as e:
            # Log any errors during test execution
            logger.log_event(
                event_type="test_error",
                description=f"Error during test execution: {str(e)}",
                severity="error",
                details={"exception": str(e), "type": type(e).__name__}
            )
            return 1
            
        finally:
            # Always clean up the network
            net.stop()
            cleanup_network()
            
    except Exception as e:
        # Log any initialization errors
        logger.log_event(
            event_type="test_error",
            description=f"Test initialization failed: {str(e)}",
            severity="error",
            details={"exception": str(e), "type": type(e).__name__}
        )
        cleanup_network()
        return 1
    
    finally:
        # Ensure all logs are flushed
        if 'logger' in locals():
            logger.shutdown()

if __name__ == '__main__':
    scenario = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(main(scenario))