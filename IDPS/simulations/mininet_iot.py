#!/usr/bin/env python3
import sys
import os
import json
from datetime import datetime

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

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

def cleanup_network():
    """Comprehensive network cleanup"""
    commands = [
        'sudo mn -c >/dev/null 2>&1',
        'sudo pkill -f "python3.*main.py"',
        'sudo pkill -f "ovs-vswitchd"',
        'sudo pkill -f "ovsdb-server"',
        'sudo pkill -f "tcpdump"',
        'sudo rm -rf /var/run/openvswitch/*',
        'sudo rm -rf /tmp/*.out /tmp/*.log',
        'sudo ip link del s1-eth1 >/dev/null 2>&1 || true',
        'sudo ip link del s1-eth2 >/dev/null 2>&1 || true',
        'sudo ip netns del edge_router >/dev/null 2>&1 || true',
        'sudo ip netns del thermostat >/dev/null 2>&1 || true',
        'sudo ovs-vsctl --if-exists del-br s1',
        'sudo ovs-vsctl --if-exists del-manager',
        'sudo service openvswitch-switch restart',
        'sleep 2'  # Give OVS time to restart
    ]
    
    for cmd in commands:
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] Warning during cleanup: {e}")
    time.sleep(2)  # Additional delay to ensure cleanup completes

def start_ovs_service():
    """Ensure Open vSwitch service is running"""
    try:
        # Check if OVS service is active
        result = subprocess.run(['systemctl', 'is-active', 'openvswitch-switch'], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE,
                               text=True)
        if result.stdout.strip() != 'active':
            info("*** Starting Open vSwitch service...\n")
            subprocess.run(['sudo', 'systemctl', 'start', 'openvswitch-switch'], check=True)
            time.sleep(2)  # Wait for service to start
        
        # Verify OVS database connection
        result = subprocess.run(['ovs-vsctl', 'show'], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE,
                               text=True)
        if result.returncode != 0:
            error(f"*** OVS still not working: {result.stderr}\n")
            return False
            
        return True
    except Exception as e:
        error(f"*** OVS service error: {str(e)}\n")
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

def capture_traffic(scenario, duration):
    """Capture network traffic during the scenario"""
    # Ensure pcap directory exists
    pcap_dir = os.path.join(BASE_DIR, 'pcaps')
    os.makedirs(pcap_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    pcap_file = os.path.join(pcap_dir, f'{scenario}_{timestamp}.pcap')
    
    # Start tcpdump to capture traffic
    cmd = f"sudo tcpdump -i any -w {pcap_file} -s 0 &"
    tcpdump_process = subprocess.Popen(cmd, shell=True)
    
    info(f"*** Started traffic capture: {pcap_file}\n")
    
    # Let it run for the scenario duration
    time.sleep(duration)
    
    # Stop tcpdump
    subprocess.run("sudo pkill -f tcpdump", shell=True)
    tcpdump_process.wait()
    
    info(f"*** Stopped traffic capture: {pcap_file}\n")
    return pcap_file

def run_idps_model(pcap_file, scenario):
    """Run the IDPS model on captured traffic"""
    model_script = os.path.join(BASE_DIR, 'models', 'run_model.py')
    
    if not os.path.exists(model_script):
        error("*** IDPS model script not found!\n")
        return False
    
    try:
        # Ensure results directory exists
        results_dir = os.path.join(BASE_DIR, 'results')
        os.makedirs(results_dir, exist_ok=True)
        
        cmd = [
            "python3", model_script,
            "--pcap", pcap_file,
            "--scenario", scenario,
            "--output", os.path.join(results_dir, f'{scenario}_detections.json')
        ]
        
        info(f"*** Running IDPS model: {' '.join(cmd)}\n")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            error(f"*** Model execution failed: {result.stderr}\n")
            return False
            
        info("*** IDPS model executed successfully\n")
        return True
        
    except subprocess.TimeoutExpired:
        error("*** Model execution timed out\n")
        return False
    except Exception as e:
        error(f"*** Error running model: {str(e)}\n")
        return False

def run_test_scenario(net, scenario):
    """Run predefined test scenario with full pipeline"""
    from test_scenarios import SCENARIOS
    
    if scenario not in SCENARIOS:
        error(f"*** Unknown scenario: {scenario}\n")
        return False
    
    test = SCENARIOS[scenario]
    info(f"=== Starting scenario: {test['name']} ===\n")
    
    try:
        # Start traffic capture
        pcap_file = capture_traffic(scenario, test['duration'])
        
        # Start attacks
        for attack in test['attacks']:
            try:
                device = net.get(attack['device'].split('_')[0])  # Convert 'malicious_device' to 'malicious'
                run_attack(device, attack['type'])
            except Exception as e:
                error(f"*** Failed to start attack {attack['type']}: {e}\n")
        
        # Start benign traffic
        for traffic in test['benign_traffic']:
            try:
                device = net.get(traffic['device'].split('_')[0])
                device.cmd(f'python simulations/attack_generators.py --traffic {traffic["type"]} &')
            except Exception as e:
                error(f"*** Failed to start traffic {traffic['type']}: {e}\n")
        
        # Run for scenario duration
        info(f"\n=== Running scenario for {test['duration']} seconds ===\n")
        time.sleep(test['duration'])
        
        # Run IDPS model on captured traffic
        info("=== Running IDPS model analysis ===\n")
        model_success = run_idps_model(pcap_file, scenario)
        
        if not model_success:
            error("*** IDPS model analysis failed\n")
        
        return model_success
        
    except KeyboardInterrupt:
        info("\n=== Scenario interrupted by user ===\n")
        return True
    except Exception as e:
        error(f"*** Error in scenario: {e}\n")
        return False

def main(scenario=None):
    """Main function with enhanced testing capabilities"""
    setLogLevel('info')
    
    # Ensure OVS service is running
    if not start_ovs_service():
        error("*** FATAL: Open vSwitch is required but could not be started.\n")
        return 1
    
    cleanup_network()
    time.sleep(1)
    
    try:
        info("*** Creating network\n")
        net = Mininet(
            topo=IoTTopo(),
            controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
            switch=OVSSwitch,
            link=TCLink,
            autoSetMacs=True,
            autoStaticArp=True,
            waitConnected=True,
            cleanup=True
        )
        
        info("*** Starting network\n")
        net.start()
        
        # Configure edge router as gateway
        edge = net.get('edge')
        edge.cmd('sysctl -w net.ipv4.ip_forward=1')
        
        # Set default routes for all devices
        for host in net.hosts:
            if host.name != 'edge':
                host.cmd(f'ip route add default via 192.168.0.1')
        
        # Run specific scenario or enter CLI
        if scenario:
            success = run_test_scenario(net, scenario)
            if not success:
                error("*** Scenario execution failed!\n")
                return 1
        else:
            info("\n=== Starting Mininet CLI (type 'exit' to quit) ===\n")
            CLI(net)
        
        return 0
        
    except Exception as e:
        error(f"*** Critical error: {str(e)}\n")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        try:
            info("*** Cleaning up\n")
            net.stop()
        except:
            pass
        cleanup_network()

if __name__ == '__main__':
    scenario = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(main(scenario))