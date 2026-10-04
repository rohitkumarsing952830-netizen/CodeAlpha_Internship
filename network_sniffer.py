from scapy.all import sniff, IP, TCP, UDP, ICMP


def packet_callback(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_length = len(packet)

        print("\n" + "=" * 60)
        print("        NETWORK PACKET CAPTURED")
        print("=" * 60)

        print(f"Source IP      : {source_ip}")
        print(f"Destination IP : {destination_ip}")
        print(f"Protocol       : {protocol}")
        print(f"Packet Length  : {packet_length} bytes")

        if TCP in packet:
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
            print("Transport      : TCP")

        elif UDP in packet:
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
            print("Transport      : UDP")

        elif ICMP in packet:
            print("Transport      : ICMP")

        print("=" * 60)


print("Starting Network Sniffer...")
print("Capturing packets on your local network.")
print("Press CTRL+C to stop.\n")

sniff(prn=packet_callback, store=False)