from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = "Other"
        port = ""

        if packet.haslayer(TCP):
            protocol = "TCP"
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            port = packet[UDP].dport

        print(f"{protocol} | SRC: {src_ip} → DST: {dst_ip} | PORT: {port}")

sniff(prn=process_packet, count=20)