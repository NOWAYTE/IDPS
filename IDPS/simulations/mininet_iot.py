from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import subprocess
import time
import os
import sys
from config import BASE_DIR

class IoTTopo(Topo):
    def build(self):
        """Create IoT network topology with shorter interface names"""
        # Create IoT devices with shorter names
        devices = [
            ('therm', '192.168.0.101/24'),  # thermostat
            ('cam', '192.168.0.102/24'),    # security_cam
            ('lock', '192.168.0.103/24'),   # smart_lock
            ('monitor', '192.168.0.104/24'), # health_monitor
            ('malicious', '192.168.0.200/24'), # malicious_device
            ('edge', '192.168.0.1/24')      # edge_router
        ]
        
        # Add devices to network
        for name, ip in devices:
            self.addHost(name, ip=ip)
        
        # Create switches
        iot_switch = self.addSwitch('s1')
        cloud_switch = self.addSwitch('s2')
        
        # Create cloud server with shorter name
        cloud = self.addHost('cloud', ip='10.0.0.1/24')
        
        # Add links with explicit port numbers to avoid long interface names
        for name, _ in devices[:-1]:  # All except edge router
            self.addLink(name, iot_switch)
        
        # Connect switches
        self.addLink(iot_switch, cloud_switch)
        
        # Connect cloud server
        self.addLink(cloud_switch, cloud, port1=2, port2=0)
        
        # Add IDPS monitoring port with explicit interface names
        self.addLink(iot_switch, 'edge', port1=len(devices), port2=0)

def start_idps(node):
    """Start IDPS on edge router"""
    idps_path = os.path.join(BASE_DIR, 'main.py')
    node.cmd(f'python {idps_path} &')
    info(f"Started IDPS on {node.name}\n")

def run_attack(host, attack_type):
    """Run specific attack from a host"""
    if attack_type == 'ddos':
        host.cmd('hping3 --flood --rand-source 192.168.0.1 &')
    elif attack_type == 'portscan':
        host.cmd('nmap -T4 -A 192.168.0.1 &')
    elif attack_type == 'mqtt_exploit':
        host.cmd('python simulations/attack_generators.py --attack mqtt &')
    info(f"Started {attack_type} attack from {host.name}\n")

def monitor_network(net, duration=120):
    """Monitor network during test"""
    start = time.time()
    while time.time() - start < duration:
        # Check IDPS status
        edge = net.get('edge')
        idps_status = edge.cmd('ps aux | grep main.py | grep -v grep')
        
        if not idps_status:
            info("IDPS process crashed! Stopping test.\n")
            return False
        
        # Check device connectivity
        cloud = net.get('cloud')
        ping_result = edge.cmd('ping -c 1 192.168.0.1')
        if '100% packet loss' in ping_result:
            info("Edge router unreachable! Stopping test.\n")
            return False
        
        time.sleep(5)
    
    return True

def run_test_scenario(net, scenario):
    """Run predefined test scenario"""
    from .test_scenarios import SCENARIOS
    if scenario not in SCENARIOS:
        info(f"Unknown scenario: {scenario}\n")
        return
    
    test = SCENARIOS[scenario]
    info(f"Starting scenario: {test['name']}\n")
    
    # Start attacks
    for attack in test['attacks']:
        device = net.get(attack['device'])
        run_attack(device, attack['type'])
    
    # Run benign traffic
    for traffic in test['benign_traffic']:
        device = net.get(traffic['device'])
        device.cmd(f'python simulations/attack_generators.py --traffic {traffic["type"]} &')
    
    # Monitor and collect results
    success = monitor_network(net, test['duration'])
    
    # Collect IDPS logs
    edge = net.get('edge')
    edge.cmd('pkill -f main.py')  # Stop IDPS gently
    time.sleep(2)
    edge.cmd(f'mv {BASE_DIR}/audit_logs {BASE_DIR}/results/{scenario}_logs')
    
    return success

def main(scenario=None):
    """Create and test network with improved interface naming"""
    # Set environment variable to allow long interface names
    os.environ['LANG'] = 'C'
    
    # Initialize Mininet with custom topology
    net = Mininet(
        topo=IoTTopo(),
        switch=OVSSwitch,
        controller=lambda name: RemoteController(name, ip='127.0.0.1'),
        link=TCLink,
        autoStaticArp=True,
        waitConnected=True
    )
    
    # Start network
    net.start()
    
    try:
        # Configure edge router as gateway
        edge = net.get('edge')
        edge.cmd('sysctl net.ipv4.ip_forward=1')
        
        # Configure NAT for internet access
        edge.cmd('iptables -t nat -A POSTROUTING -o edge-eth0 -j MASQUERADE')
        
        # Set default route for IoT devices
        for device in ['therm', 'cam', 'lock', 'monitor', 'malicious']:
            host = net.get(device)
            host.cmd('ip route add default via 192.168.0.1')
        
        # Start IDPS
        start_idps(edge)
        
        # Create results directory
        edge.cmd(f'mkdir -p {BASE_DIR}/results')
        
        if scenario:
            # Run specific scenario
            result = run_test_scenario(net, scenario)
            info(f"Scenario {scenario} completed: {'Success' if result else 'Failure'}\n")
        else:
            # Interactive mode
            CLI(net)
    finally:
        # Ensure cleanup happens even if there's an error
        net.stop()
        subprocess.call(['mn', '-c'])

if __name__ == '__main__':
    setLogLevel('info')
    scenario = sys.argv[1] if len(sys.argv) > 1 else None
    main(scenario)
