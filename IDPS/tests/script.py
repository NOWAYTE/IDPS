from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
import os

# Make sure the directory exists
os.makedirs("tests", exist_ok=True)

# Your interface MAC address
src_mac = "00:15:5d:68:14:67"
dst_mac = "ff:ff:ff:ff:ff:ff"  # Broadcast, or set your target's MAC if known
dst_ip = "192.168.1.100"       # Replace with the IP of the system you're sending to

packets = [
    Ether(src=src_mac, dst=dst_mac)/IP(dst=dst_ip)/TCP(sport=1883, dport=80)/Raw(load=bytes.fromhex("4D5154544578706C6F6974")),
    Ether(src=src_mac, dst=dst_mac)/IP(dst=dst_ip)/UDP(sport=5683, dport=5683)/Raw(load=bytes.fromhex("436F4150466C6F6F64")),
    Ether(src=src_mac, dst=dst_mac)/IP(dst=dst_ip)/TCP(sport=12345, dport=80)/Raw(load=b"GET / HTTP/1.1\r\n\r\n"),
    Ether(src=src_mac, dst=dst_mac)/IP(dst=dst_ip)/UDP(sport=5000, dport=5001)/Raw(load=b"NormalStuff")
]

wrpcap("tests/sample_traffic.pcap", packets)
print("✅ sample_traffic.pcap generated with proper Ethernet headers.")

