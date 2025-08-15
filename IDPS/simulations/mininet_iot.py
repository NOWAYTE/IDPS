#!/usr/bin/env python3
import sys
import os

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
        'sudo rm -rf /var/run/openvswitch/*',
        'sudo rm -rf /tmp/*.out /tmp/*.log',
        'sudo ip link del s1-eth1 >/dev/null 2>&1 || true',
        'sudo ip link del s1-eth2 >/dev/null 2>&1 || true',
        'sudo ip netns del edge_router >/dev/null 2>&1 || true',
        'sudo ip netns del thermostat >/dev/null 2>&1 || true'
    ]
    
    for cmd in commands:
        subprocess.run(cmd, shell=True)
    time.sleep(1)

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
    """Simplified IoT Network Topology"""
    def build(self):
        # Create IoT devices
        devices = [
            ('thermostat', '192.168.0.101/24'),
            ('edge_router', '192.168.0.1/24')
        ]
        
        # Add devices to network
        hosts = {}
        for name, ip in devices:
            hosts[name] = self.addHost(name, ip=ip)
        
        # Create switch
        s1 = self.addSwitch('s1')
        
        # Add links
        for name in ['thermostat', 'edge_router']:
            self.addLink(hosts[name], s1)

def main(scenario=None):
    """Main function with enhanced OVS handling"""
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
            switch=OVSSwitch,
            controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
            link=TCLink,
            autoSetMacs=True,
            autoStaticArp=True,
            waitConnected=True,
            cleanup=True
        )
        
        info("*** Starting network\n")
        net.start()
        
        # Simple ping test
        info("*** Testing connectivity\n")
        edge = net.get('edge_router')
        thermostat = net.get('thermostat')
        
        # Configure basic networking
        edge.cmd('sysctl -w net.ipv4.ip_forward=1')
        thermostat.cmd('ip route add default via 192.168.0.1')
        
        # Test connectivity
        ping_result = thermostat.cmd('ping -c 1 192.168.0.1')
        
        if '1 received' not in ping_result:
            error("*** Basic connectivity test failed!\n")
            error(f"Ping result: {ping_result}\n")
            return 1
        
        info("*** Connectivity test passed\n")
        
        # If we reached here, basic network works
        info("*** Test completed successfully\n")
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