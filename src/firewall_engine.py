import json
from scapy.all import sniff, IP, TCP, UDP
from enforce_firewall import enforce_ip_block
from logger import write_log

# Load rules
with open("../config/rules.json", "r") as f:
    rules = json.load(f)

BLOCK_IPS = rules["block_ips"]
BLOCK_PORTS = rules["block_ports"]

# IDS alert tracking
BLOCK_COUNTS = {}
ALERT_THRESHOLD = 3


def check_ip_rule(src_ip):
    return src_ip in BLOCK_IPS


def check_port_rule(port):
    return port in BLOCK_PORTS


def check_alert(src_ip):

    if src_ip not in BLOCK_COUNTS:
        BLOCK_COUNTS[src_ip] = 0

    BLOCK_COUNTS[src_ip] += 1

    if BLOCK_COUNTS[src_ip] == ALERT_THRESHOLD:

        alert_msg = f"[ALERT] Suspicious repeated blocks from {src_ip}"

        print(alert_msg)
        write_log(alert_msg)


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

    # Rule processing
    if check_ip_rule(src_ip):

        msg = f"[BLOCKED:IP] {src_ip} -> {dst_ip}"
        print(msg)
        write_log(msg)

        check_alert(src_ip)

        enforce_ip_block(src_ip)

    elif check_port_rule(port):

        msg = f"[BLOCKED:PORT] {protocol} {src_ip} -> {dst_ip} PORT:{port}"
        print(msg)
        write_log(msg)

    else:

        msg = f"[ALLOWED] {protocol} {src_ip} -> {dst_ip} PORT:{port}"
        print(msg)
        write_log(msg)


# Capture packets
sniff(prn=process_packet, count=30)