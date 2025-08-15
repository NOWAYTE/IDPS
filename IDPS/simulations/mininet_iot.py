#!/usr/bin/env python3
import sys
import os

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from config import BASE_DIR
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error, debug
from mininet.link import TCLink
import subprocess
import time
import signal

# Handle SIGTERM gracefully
def sigterm_handler(signum, frame):
    error("\nReceived SIGTERM. Cleaning up...\n")
    cleanup_network()
    sys.exit(1)

signal.signal(signal.SIGTERM, sigterm_handler)

class IoTTopo(Topo):
    def build(self):
        # Simplified topology for debugging
        s1 = self.addSwitch('s1')
        edge = self.addHost('edge_router', ip='192.168.0.1/24')
        thermostat = self.addHost('thermostat', ip='192.168.0.101/24')
        
        self.addLink(thermostat, s1)
        self.addLink(edge, s1)

def cleanup_network():
    """Comprehensive network cleanup"""
    commands = [
        'sudo mn -c',
        'sudo pkill -f "python3.*main.py"',
        'sudo pkill -f "ovs-vswitchd"',
        'sudo pkill -f "ovsdb-server"',
        'sudo rm -rf /var/run/openvswitch/*',
        'sudo rm -rf /tmp/*.out /tmp/*.log',
        'sudo ip link del s1-eth1 2>/dev/null || true',
        'sudo ip link del s1-eth2 2>/dev/null || true',
        'sudo ip netns del edge_router 2>/dev/null || true',
        'sudo ip netns del thermostat 2>/dev/null || true'
    ]
    
    for cmd in commands:
        subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(1)

def verify_ovs():
    """Check if Open vSwitch is running"""
    try:
        result = subprocess.run(['ovs-vsctl', 'show'], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE,
                               text=True)
        if "ovs-vsctl: unix:/var/run/openvswitch/db.sock: connection failed" in result.stderr:
            error("Open vSwitch not running! Starting service...\n")
            subprocess.run(['sudo', 'systemctl', 'start', 'openvswitch-switch'])
            time.sleep(2)
        return True
    except FileNotFoundError:
        error("Open vSwitch not installed!\n")
        return False

def main(scenario=None):
    """Main function with enhanced debugging"""
    setLogLevel('info')
    
    # Verify OVS status
    if not verify_ovs():
        error("Open vSwitch dependency failed\n")
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
        
        # Verify controller connection
        if not net.controllers or not net.controllers[0].isActive():
            error("*** Controller connection failed!\n")
            return 1
        
        info("*** Network started successfully\n")
        
        # Simple ping test
        info("*** Testing connectivity\n")
        edge = net.get('edge_router')
        thermostat = net.get('thermostat')
        ping_result = thermostat.cmd('ping -c 1 192.168.0.1')
        
        if '1 received' not in ping_result:
            error("*** Basic connectivity test failed!\n")
            return 1
        
        info("*** Connectivity test passed\n")
        
        # Continue with your scenario logic...
        info("*** Test completed successfully\n")
        return 0
        
    except Exception as e:
        error(f"*** Critical error: {str(e)}\n")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        info("*** Cleaning up\n")
        net.stop()
        cleanup_network()

if __name__ == '__main__':
    scenario = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(main(scenario))