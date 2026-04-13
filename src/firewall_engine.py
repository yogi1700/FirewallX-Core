from scapy.all import sniff, IP, TCP, UDP

# Rules
BLOCK_IPS = ["10.232.93.238"]
BLOCK_PORTS = [53]

def process_packet(packet):
    if packet.haslayer(IP):
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

        # Rule Engine
        if src_ip in BLOCK_IPS:
            print(f"[BLOCKED ❌ IP] {src_ip} → {dst_ip}")
        elif port in BLOCK_PORTS:
            print(f"[BLOCKED ❌ PORT] {protocol} {src_ip} → {dst_ip} | PORT: {port}")
        else:
            print(f"[ALLOWED ✅] {protocol} {src_ip} → {dst_ip} | PORT: {port}")

sniff(prn=process_packet, count=30)
