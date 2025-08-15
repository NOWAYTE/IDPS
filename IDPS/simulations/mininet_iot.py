from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController, Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.link import TCLink
import subprocess
import time
import os
import sys
import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from config import BASE_DIR

class IoTTopo(Topo):
    """IoT Network Topology with standard interface naming"""
    def build(self):
        # Create IoT devices
        devices = [
            ('thermostat', '192.168.0.101/24'),
            ('security_cam', '192.168.0.102/24'),
            ('smart_lock', '192.168.0.103/24'),
            ('health_monitor', '192.168.0.104/24'),
            ('malicious_device', '192.168.0.200/24'),
            ('edge_router', '192.168.0.1/24')
        ]
        
        # Add devices to network
        hosts = {}
        for name, ip in devices:
            hosts[name] = self.addHost(name, ip=ip)
        
        # Create switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        cloud_server = self.addHost('cloud_server', ip='10.0.0.1/24')
        
        # Add links - use standard Mininet interface naming
        for name in ['thermostat', 'security_cam', 'smart_lock', 'health_monitor', 'malicious_device']:
            self.addLink(hosts[name], s1)
        
        self.addLink(hosts['edge_router'], s1)
        self.addLink(s1, s2)
        self.addLink(s2, cloud_server)

def cleanup_network():
    """Clean up any existing network configurations"""
    commands = [
        'sudo mn -c',
        'sudo pkill -f "pox"',
        'sudo pkill -f "mininet"',
        'sudo pkill -f "ovs-"',
        'sudo rm -rf /var/run/openvswitch/*',
        'sudo rm -rf /tmp/*.out /tmp/*.log',
        'sudo ip link del edge_router-eth0 2>/dev/null || true',
        'sudo ip netns del edge_router 2>/dev/null || true'
    ]
    
    for cmd in commands:
        subprocess.call(cmd, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(2)

def start_idps(node):
    """Start IDPS on edge router"""
    idps_path = os.path.join(BASE_DIR, 'main.py')
    node.cmd(f'python3 {idps_path} > {BASE_DIR}/idps.log 2>&1 &')
    info(f"Started IDPS on {node.name}\n")

def run_attack(host, attack_type):
    """Run specific attack from a host"""
    target = '192.168.0.1'  # Edge router IP
    if attack_type == 'ddos':
        host.cmd(f'hping3 --flood --rand-source {target} > /dev/null 2>&1 &')
    elif attack_type == 'portscan':
        host.cmd(f'nmap -T4 -A {target} > /dev/null 2>&1 &')
    elif attack_type == 'mqtt_exploit':
        host.cmd(f'python3 {BASE_DIR}/simulations/attack_generators.py --attack mqtt --target {target} > /dev/null 2>&1 &')
    info(f"Started {attack_type} attack from {host.name}\n")

def monitor_network(net, duration=120):
    """Monitor network during test"""
    start = time.time()
    edge = net.get('edge_router')
    
    while time.time() - start < duration:
        try:
            # Check IDPS status
            idps_status = edge.cmd('pgrep -f "python3.*main.py"')
            if not idps_status.strip():
                info("IDPS process crashed! Stopping test.\n")
                return False
            
            # Check connectivity to edge router
            for host_name in ['thermostat', 'security_cam']:
                host = net.get(host_name)
                ping_result = host.cmd(f'ping -c 1 -W 1 {edge.IP()}')
                if '1 received' not in ping_result:
                    info(f"Connectivity lost from {host_name}! Stopping test.\n")
                    return False
        except Exception as e:
            error(f"Monitoring error: {str(e)}\n")
            return False
        
        time.sleep(5)
    
    return True

def run_test_scenario(net, scenario):
    """Run predefined test scenario"""
    try:
        sys.path.append(os.path.join(BASE_DIR, 'simulations'))
        from test_scenarios import SCENARIOS
        
        if scenario not in SCENARIOS:
            info(f"Unknown scenario: {scenario}\n")
            return False
        
        test = SCENARIOS[scenario]
        info(f"Starting scenario: {test['name']}\n")
        
        # Start attacks
        for attack in test['attacks']:
            device = net.get(attack['device'])
            run_attack(device, attack['type'])
        
        # Run benign traffic
        for traffic in test['benign_traffic']:
            device = net.get(traffic['device'])
            device.cmd(f'python3 {BASE_DIR}/simulations/attack_generators.py --traffic {traffic["type"]} > /dev/null 2>&1 &')
        
        # Monitor and collect results
        success = monitor_network(net, test.get('duration', 120))
        
        # Collect IDPS logs
        edge = net.get('edge_router')
        edge.cmd('pkill -f "python3.*main.py"')
        time.sleep(2)
        edge.cmd(f'mkdir -p {BASE_DIR}/results')
        edge.cmd(f'mv {BASE_DIR}/audit_logs {BASE_DIR}/results/{scenario}_logs 2>/dev/null || true')
        
        return success
    except Exception as e:
        error(f"Scenario error: {str(e)}\n")
        return False

def configure_network(net):
    """Configure network settings and routes"""
    try:
        edge = net.get('edge_router')
        
        # Enable IP forwarding
        edge.cmd('sysctl -w net.ipv4.ip_forward=1')
        
        # Configure NAT
        edge.cmd('iptables -t nat -A POSTROUTING -o edge_router-eth0 -j MASQUERADE')
        
        # Set default routes for IoT devices
        for device in ['thermostat', 'security_cam', 'smart_lock', 'health_monitor', 'malicious_device']:
            host = net.get(device)
            host.cmd('ip route add default via 192.168.0.1')
        
        return True
    except Exception as e:
        error(f"Configuration error: {str(e)}\n")
        return False

def main(scenario=None):
    """Main function to create and test network"""
    setLogLevel('info')
    
    # Clean up previous network state
    cleanup_network()
    time.sleep(2)
    
    # Initialize Mininet
    net = Mininet(
        topo=IoTTopo(),
        switch=OVSSwitch,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True,
        waitConnected=True,
        cleanup=True
    )
    
    try:
        # Start network
        net.start()
        
        # Configure network settings
        if not configure_network(net):
            error("Network configuration failed!\n")
            return 1
        
        # Start IDPS
        start_idps(net.get('edge_router'))
        
        # Create results directory
        net.get('edge_router').cmd(f'mkdir -p {BASE_DIR}/results')
        
        if scenario:
            # Run test scenario
            result = run_test_scenario(net, scenario)
            info(f"Scenario {scenario} completed: {'Success' if result else 'Failure'}\n")
            return 0 if result else 1
        else:
            # Interactive mode
            info("Network ready. Starting CLI...\n")
            CLI(net)
            return 0
    except Exception as e:
        error(f"Runtime error: {str(e)}\n")
        return 1
    finally:
        # Stop network and clean up
        net.stop()
        cleanup_network()

if __name__ == '__main__':
    scenario = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(main(scenario))