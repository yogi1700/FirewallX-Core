import json
import time
import socket
from scapy.all import sniff, IP, TCP, UDP
from enforce_firewall import enforce_ip_block
from logger import write_log


# ---------- Dynamic Local IP Detection ----------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


LOCAL_IP = get_local_ip()
print(f"[INFO] Local IP detected: {LOCAL_IP}")


# ---------- Flexible Monitoring Configuration ----------
MONITORED_IPS = {LOCAL_IP}


# ---------- Load Firewall Rules ----------
with open("../config/rules.json", "r") as f:
    rules = json.load(f)

BLOCK_IPS = rules["block_ips"]
BLOCK_PORTS = rules["block_ports"]


# ---------- Threat Scoring System ----------
THREAT_SCORE = {}


# ---------- Detection Configuration ----------
BLOCK_COUNTS = {}
ALERT_THRESHOLD = 3

SCAN_PORTS = {}
SCAN_THRESHOLD = 3

COMMON_SAFE_PORTS = {80, 443, 53}

DST_TRACKING = {}
DST_THRESHOLD = 3

RATE_TRACKER = {}
RATE_THRESHOLD = 5
TIME_WINDOW = 5


# ---------- Alert Control (Prevent Duplicates) ----------
HOST_SWEEP_ALERTED = set()
RATE_ALERTED = set()
SCAN_ALERTED = set()
REPEAT_ALERTED = set()


# ---------- Threat Scoring Logic ----------
def update_threat_score(src_ip, score):

    if src_ip not in THREAT_SCORE:
        THREAT_SCORE[src_ip] = 0

    THREAT_SCORE[src_ip] += score

    level = "LOW"

    if THREAT_SCORE[src_ip] >= 10:
        level = "CRITICAL"
    elif THREAT_SCORE[src_ip] >= 7:
        level = "HIGH"
    elif THREAT_SCORE[src_ip] >= 4:
        level = "MEDIUM"

    print(f"[THREAT] {src_ip} Score={THREAT_SCORE[src_ip]} Level={level}")


# ---------- Rule Check Functions ----------
def check_ip_rule(src_ip):
    return src_ip in BLOCK_IPS


def check_port_rule(port):
    return port in BLOCK_PORTS


# ---------- Repeated Block Detection ----------
def check_alert(src_ip):

    if src_ip not in BLOCK_COUNTS:
        BLOCK_COUNTS[src_ip] = 0

    BLOCK_COUNTS[src_ip] += 1

    if (
        BLOCK_COUNTS[src_ip] == ALERT_THRESHOLD
        and src_ip not in REPEAT_ALERTED
    ):
        REPEAT_ALERTED.add(src_ip)

        alert_msg = f"[ALERT] Suspicious repeated blocks from {src_ip}"
        print(alert_msg)
        write_log(alert_msg)

        update_threat_score(src_ip, 2)


# ---------- Port Scan Detection ----------
def check_port_scan(src_ip, port):

    if port in COMMON_SAFE_PORTS:
        return

    if src_ip not in SCAN_PORTS:
        SCAN_PORTS[src_ip] = set()

    SCAN_PORTS[src_ip].add(port)

    if (
        len(SCAN_PORTS[src_ip]) == SCAN_THRESHOLD
        and src_ip not in SCAN_ALERTED
    ):
        SCAN_ALERTED.add(src_ip)

        alert_msg = (
            f"[SCAN ALERT] Possible port scan from {src_ip} "
            f"({len(SCAN_PORTS[src_ip])} unique suspicious ports)"
        )

        print(alert_msg)
        write_log(alert_msg)

        update_threat_score(src_ip, 4)


# ---------- Host Sweep Detection ----------
def check_host_sweep(src_ip, dst_ip):

    if src_ip not in DST_TRACKING:
        DST_TRACKING[src_ip] = set()

    DST_TRACKING[src_ip].add(dst_ip)

    if (
        len(DST_TRACKING[src_ip]) == DST_THRESHOLD
        and src_ip not in HOST_SWEEP_ALERTED
    ):
        HOST_SWEEP_ALERTED.add(src_ip)

        alert_msg = (
            f"[HOST SWEEP ALERT] Possible recon from {src_ip} "
            f"({len(DST_TRACKING[src_ip])} unique destinations)"
        )

        print(alert_msg)
        write_log(alert_msg)

        update_threat_score(src_ip, 3)


# ---------- Rate-Based Detection ----------
def check_rate_limit(src_ip):

    current_time = time.time()

    if src_ip not in RATE_TRACKER:
        RATE_TRACKER[src_ip] = []

    RATE_TRACKER[src_ip] = [
        t for t in RATE_TRACKER[src_ip]
        if current_time - t <= TIME_WINDOW
    ]

    RATE_TRACKER[src_ip].append(current_time)

    if (
        len(RATE_TRACKER[src_ip]) == RATE_THRESHOLD
        and src_ip not in RATE_ALERTED
    ):
        RATE_ALERTED.add(src_ip)

        alert_msg = (
            f"[RATE ALERT] High activity from {src_ip} "
            f"({len(RATE_TRACKER[src_ip])} events in {TIME_WINDOW}s)"
        )

        print(alert_msg)
        write_log(alert_msg)

        update_threat_score(src_ip, 3)


# ---------- Packet Processing Engine ----------
def process_packet(packet):

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "OTHER"
    port = ""

    # ---------- Rate Detection ----------
    if src_ip in MONITORED_IPS:
        check_rate_limit(src_ip)

    # ---------- Protocol Parsing ----------
    if packet.haslayer(TCP):
        protocol = "TCP"
        port = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = "UDP"
        port = packet[UDP].dport

    # ---------- Behavior Detection ----------
    if src_ip in MONITORED_IPS:

        if port:
            check_port_scan(src_ip, port)

        check_host_sweep(src_ip, dst_ip)

    # ---------- Rule Engine ----------
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


# ---------- Start Packet Capture ----------
sniff(prn=process_packet, count=30)


# ---------- Session Summary ----------
print("\n--- Summary ---")
print("Blocked Sources:", BLOCK_COUNTS)
print("Scan Tracking:", SCAN_PORTS)
print("Destination Tracking:", DST_TRACKING)
print("Rate Tracking:", {k: len(v) for k, v in RATE_TRACKER.items()})
print("Threat Scores:", THREAT_SCORE)