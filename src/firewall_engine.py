import json
from scapy.all import sniff, IP, TCP, UDP

# Load rules from config file
with open("../config/rules.json", "r") as f:
    rules = json.load(f)

BLOCK_IPS = rules["block_ips"]
BLOCK_PORTS = rules["block_ports"]


def check_ip_rule(src_ip):
    return src_ip in BLOCK_IPS


def check_port_rule(port):
    return port in BLOCK_PORTS


def process_packet(packet):

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "OTHER"
    port = ""

    if packet.haslayer(TCP):
        protocol = "TCP"
        port = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = "UDP"
        port = packet[UDP].dport

    # Apply rules
    if check_ip_rule(src_ip):
        print(f"[BLOCKED:IP] {src_ip} -> {dst_ip}")

    elif check_port_rule(port):
        print(f"[BLOCKED:PORT] {protocol} {src_ip} -> {dst_ip} PORT:{port}")

    else:
        print(f"[ALLOWED] {protocol} {src_ip} -> {dst_ip} PORT:{port}")


# Capture packets
sniff(prn=process_packet, count=30)
