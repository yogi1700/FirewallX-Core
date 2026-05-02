import json
import time
import socket
from scapy.all import sniff, IP, TCP, UDP
from enforce_firewall import enforce_ip_block
from logger import write_log


# ---------- Dynamic Local IP Detection ----------
def get_local_ip():
    """
    Purpose:
    Dynamically determine the system's active network IP.

    Why:
    Avoid hardcoding IP addresses so the program works
    across different networks (WiFi, VPN, DHCP).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


LOCAL_IP = get_local_ip()
print(f"[INFO] Local IP detected: {LOCAL_IP}")

# Monitor only local machine behavior
MONITORED_IPS = {LOCAL_IP}


# ---------- Load Firewall Rules ----------
with open("../config/rules.json", "r") as f:
    rules = json.load(f)

BLOCK_IPS = rules["block_ips"]
BLOCK_PORTS = rules["block_ports"]


# ---------- Threat Scoring System ----------
THREAT_SCORE = {}
AUTO_BLOCKED = set()


# ---------- Detection Configuration ----------
SCAN_PORTS = {}
SCAN_THRESHOLD = 3

DST_TRACKING = {}
DST_THRESHOLD = 3

RATE_TRACKER = {}
RATE_THRESHOLD = 5
TIME_WINDOW = 5

COMMON_SAFE_PORTS = {80, 443, 53}


# ---------- Cooldown Tracking (per detector) ----------
RATE_LAST = {}
SCAN_LAST = {}
HOST_LAST = {}
COOLDOWN = 2


def allow_alert(store, ip):
    """
    Purpose:
    Prevent alert spam by limiting how often alerts can trigger.

    Why:
    Continuous packet flow can trigger the same alert repeatedly.
    This ensures alerts happen only after a cooldown period.
    """
    now = time.time()
    last = store.get(ip, 0)

    if now - last > COOLDOWN:
        store[ip] = now
        return True
    return False


# ---------- Threat Scoring Logic ----------
def update_threat_score(src_ip, score):
    """
    Purpose:
    Maintain cumulative threat score for each IP.

    Why:
    Combine multiple suspicious behaviors into a severity level
    instead of reacting to single isolated events.
    """

    THREAT_SCORE[src_ip] = THREAT_SCORE.get(src_ip, 0) + score

    # Determine severity level
    level = "LOW"
    if THREAT_SCORE[src_ip] >= 10:
        level = "CRITICAL"
    elif THREAT_SCORE[src_ip] >= 7:
        level = "HIGH"
    elif THREAT_SCORE[src_ip] >= 4:
        level = "MEDIUM"

    print(f"[THREAT] {src_ip} Score={THREAT_SCORE[src_ip]} Level={level}")

    # ---------- Auto Response (IPS Layer) ----------
    if level == "HIGH":
        msg = f"[WARNING] High threat detected from {src_ip}"
        print(msg)
        write_log(msg)

    elif level == "CRITICAL" and src_ip not in AUTO_BLOCKED:
        AUTO_BLOCKED.add(src_ip)

        msg = f"[CRITICAL] Blocking {src_ip}"
        print(msg)
        write_log(msg)

        enforce_ip_block(src_ip)


# ---------- Rate Detection ----------
def check_rate_limit(src_ip):
    """
    Purpose:
    Detect high-frequency traffic from a single source.

    Why:
    Sudden bursts of traffic may indicate abnormal behavior
    such as flooding or automated requests.
    """

    now = time.time()
    RATE_TRACKER.setdefault(src_ip, [])

    # Keep only recent timestamps
    RATE_TRACKER[src_ip] = [
        t for t in RATE_TRACKER[src_ip]
        if now - t <= TIME_WINDOW
    ]

    RATE_TRACKER[src_ip].append(now)

    if len(RATE_TRACKER[src_ip]) >= RATE_THRESHOLD:
        if allow_alert(RATE_LAST, src_ip):
            msg = f"[RATE ALERT] High traffic from {src_ip}"
            print(msg)
            write_log(msg)

            update_threat_score(src_ip, 3)


# ---------- Port Scan Detection ----------
def check_port_scan(src_ip, port):
    """
    Purpose:
    Detect access to multiple unusual ports.

    Why:
    Trying different ports quickly is a common scanning technique
    used to discover open services.
    """

    if port in COMMON_SAFE_PORTS:
        return

    SCAN_PORTS.setdefault(src_ip, set()).add(port)

    if len(SCAN_PORTS[src_ip]) >= SCAN_THRESHOLD:
        if allow_alert(SCAN_LAST, src_ip):
            msg = f"[SCAN ALERT] Port scan from {src_ip}"
            print(msg)
            write_log(msg)

            update_threat_score(src_ip, 4)


# ---------- Host Sweep Detection ----------
def check_host_sweep(src_ip, dst_ip):
    """
    Purpose:
    Detect communication with multiple destination IPs.

    Why:
    Contacting many hosts can indicate reconnaissance
    or network scanning behavior.
    """

    DST_TRACKING.setdefault(src_ip, set()).add(dst_ip)

    if len(DST_TRACKING[src_ip]) >= DST_THRESHOLD:
        if allow_alert(HOST_LAST, src_ip):
            msg = f"[HOST SWEEP ALERT] Recon from {src_ip}"
            print(msg)
            write_log(msg)

            update_threat_score(src_ip, 3)


# ---------- Rule Checks ----------
def check_ip_rule(src_ip):
    """
    Purpose:
    Check if the IP is explicitly blocked.

    Why:
    Enforce predefined firewall rules.
    """
    return src_ip in BLOCK_IPS


def check_port_rule(port):
    """
    Purpose:
    Check if a port is blocked.

    Why:
    Prevent communication over restricted services.
    """
    return port in BLOCK_PORTS


# ---------- Packet Processing Engine ----------
def process_packet(packet):
    """
    Purpose:
    Main engine that processes each captured packet.

    Flow:
    1. Extract IP, protocol, port
    2. Run detection logic
    3. Apply firewall rules
    4. Log results

    Why:
    Acts as the central pipeline connecting detection,
    scoring, and enforcement.
    """

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "OTHER"
    port = ""

    # Behavior monitoring (only for local system)
    if src_ip in MONITORED_IPS:
        check_rate_limit(src_ip)

    # Protocol parsing
    if packet.haslayer(TCP):
        protocol = "TCP"
        port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        port = packet[UDP].dport

    # Detection layer
    if src_ip in MONITORED_IPS:
        if port:
            check_port_scan(src_ip, port)
        check_host_sweep(src_ip, dst_ip)

    # ---------- Firewall Rule Engine ----------
    if check_ip_rule(src_ip):

        msg = f"[BLOCKED:IP] {src_ip} -> {dst_ip}"
        print(msg)
        write_log(msg)

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
print("Scan Tracking:", SCAN_PORTS)
print("Destination Tracking:", DST_TRACKING)
print("Rate Tracking:", {k: len(v) for k, v in RATE_TRACKER.items()})
print("Threat Scores:", THREAT_SCORE)