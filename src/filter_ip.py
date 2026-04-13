from scapy.all import sniff, IP

# Change this IP based on your observed traffic
BLOCK_IP = "10.232.93.238"

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Apply IP blocking rule
        if src_ip == BLOCK_IP:
            print(f"[IP FILTER] BLOCKED ❌ | SRC: {src_ip} → DST: {dst_ip}")
        else:
            print(f"[IP FILTER] ALLOWED ✅ | SRC: {src_ip} → DST: {dst_ip}")

# Capture packets
sniff(prn=process_packet, count=20)
