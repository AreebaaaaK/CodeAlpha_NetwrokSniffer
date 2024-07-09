from scapy.all import sniff, IP, TCP, UDP, ICMP
def pcall(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "Other"
        sport = dport = None

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif ICMP in packet:
            proto = "ICMP"
        print(f"{proto} Packet: {ip_src}:{sport} -> {ip_dst}:{dport}")
print("Starting network sniffer...")
sniff(prn=pcall, store=0)
