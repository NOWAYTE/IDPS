from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller, RemoteController, Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.link import TCLink, Intf
import subprocess
import time
import os
import sys
import re
from config import BASE_DIR

class CustomHost(Host):
    """Custom host with shorter interface names"""
    def __init__(self, name, *args, **kwargs):
        super().__init__(name, *args, **kwargs)
        self.intfNames = []  # Track interface names

    def addIntf(self, intf, **kwargs):
        """Add an interface with a shorter name"""
        # Generate a shorter interface name (e.g., e0, e1, etc.)
        if not hasattr(self, 'intfCounter'):
            self.intfCounter = 0
        intfName = f"e{self.intfCounter}"
        self.intfCounter += 1
        
        # Store the original name mapping
        if not hasattr(self, 'intfMap'):
            self.intfMap = {}
        self.intfMap[intfName] = intf.name
        
        # Update the interface name
        intf.name = intfName
        self.intfNames.append(intfName)
        
        # Call the parent class method
        return super().addIntf(intf, **kwargs)

class IoTTopo(Topo):
    """IoT Network Topology with custom host class"""
    def __init__(self):
        """Create custom topology with shorter interface names"""
        Topo.__init__(self, host=CustomHost)

    def build(self):
        """Build the IoT network topology"""
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
        hosts = {}
        for name, ip in devices:
            hosts[name] = self.addHost(name, ip=ip)
        
        # Create switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        
        # Create cloud server with shorter name
        cloud = self.addHost('cloud', ip='10.0.0.1/24')
        
        # Add links with explicit port numbers and names
        for i, name in enumerate(['therm', 'cam', 'lock', 'monitor', 'malicious']):
            self.addLink(hosts[name], s1, port1=0, port2=i+1)
        
        # Connect edge router
        self.addLink(hosts['edge'], s1, port1=0, port2=len(devices))
        
        # Connect switches and cloud
        self.addLink(s1, s2, port1=len(devices)+1, port2=1)
        self.addLink(s2, cloud, port1=2, port2=0)

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
        try:
            edge = net.get('edge')
            idps_status = edge.cmd('ps aux | grep main.py | grep -v grep')
            
            if not idps_status:
                info("IDPS process crashed! Stopping test.\n")
                return False
            
            # Check device connectivity
            ping_result = edge.cmd('ping -c 1 192.168.0.1')
            if '100% packet loss' in ping_result:
                info("Edge router unreachable! Stopping test.\n")
                return False
        except Exception as e:
            error(f"Error during monitoring: {e}\n")
            return False
        
        time.sleep(5)
    
    return True

def run_test_scenario(net, scenario):
    """Run predefined test scenario"""
    try:
        from .test_scenarios import SCENARIOS
        if scenario not in SCENARIOS:
            info(f"Unknown scenario: {scenario}\n")
            return False
        
        test = SCENARIOS[scenario]
        info(f"Starting scenario: {test['name']}\n")
        
        # Start attacks
        for attack in test['attacks']:
            try:
                device = net.get(attack['device'])
                run_attack(device, attack['type'])
            except Exception as e:
                error(f"Failed to start attack {attack['type']}: {e}\n")
        
        # Run benign traffic
        for traffic in test['benign_traffic']:
            try:
                device = net.get(traffic['device'])
                device.cmd(f'python simulations/attack_generators.py --traffic {traffic["type"]} &')
            except Exception as e:
                error(f"Failed to start traffic {traffic['type']}: {e}\n")
        
        # Monitor and collect results
        success = monitor_network(net, test.get('duration', 120))
        
        # Collect IDPS logs
        try:
            edge = net.get('edge')
            edge.cmd('pkill -f main.py')  # Stop IDPS gently
            time.sleep(2)
            edge.cmd(f'mkdir -p {BASE_DIR}/results')
            edge.cmd(f'mv {BASE_DIR}/audit_logs {BASE_DIR}/results/{scenario}_logs 2>/dev/null || true')
        except Exception as e:
            error(f"Error collecting logs: {e}\n")
        
        return success
    except Exception as e:
        error(f"Error in test scenario: {e}\n")
        return False

def main(scenario=None):
    """Create and test network with improved interface naming"""
    # Set environment variables
    os.environ['LANG'] = 'C'
    os.environ['PATH'] += ':/usr/sbin:/sbin'
    
    # Clean up any previous Mininet instances
    subprocess.call(['mn', '-c'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    
    # Initialize Mininet with custom topology
    try:
        net = Mininet(
            topo=IoTTopo(),
            switch=OVSSwitch,
            controller=lambda name: RemoteController(name, ip='127.0.0.1'),
            link=TCLink,
            autoStaticArp=True,
            waitConnected=True,
            cleanup=True
        )
        
        # Start network
        net.start()
        
        try:
            # Configure edge router as gateway
            edge = net.get('edge')
            
            # Enable IP forwarding
            edge.cmd('sysctl -w net.ipv4.ip_forward=1')
            
            # Find the correct interface name (it should be e0 for the first interface)
            intf = edge.intfNames()[0]  # Get the first interface name
            
            # Configure NAT with the correct interface name
            edge.cmd('iptables -t nat -F')  # Flush existing rules
            edge.cmd(f'iptables -t nat -A POSTROUTING -o {intf} -j MASQUERADE')
            
            # Set default route for IoT devices
            for device in ['therm', 'cam', 'lock', 'monitor', 'malicious']:
                try:
                    host = net.get(device)
                    host.cmd('ip route del default 2>/dev/null || true')
                    host.cmd('ip route add default via 192.168.0.1')
                except Exception as e:
                    error(f"Error configuring {device}: {e}\n")
            
            # Start IDPS
            start_idps(edge)
            
            # Create results directory
            edge.cmd(f'mkdir -p {BASE_DIR}/results')
            
            if scenario:
                # Run specific scenario
                result = run_test_scenario(net, scenario)
                info(f"Scenario {scenario} completed: {'Success' if result else 'Failure'}\n")
                return 0 if result else 1
            else:
                # Interactive mode
                info("Starting Mininet CLI. Type 'exit' or press Ctrl-D to end.\n")
                CLI(net)
                return 0
                
        except KeyboardInterrupt:
            info("\nStopping network...\n")
            return 0
        except Exception as e:
            error(f"Error in network setup: {e}\n")
            return 1
        finally:
            # Clean up
            net.stop()
            subprocess.call(['mn', '-c'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            
    except Exception as e:
        error(f"Failed to create network: {e}\n")
        return 1

if __name__ == '__main__':
    setLogLevel('info')
    scenario = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(main(scenario))
