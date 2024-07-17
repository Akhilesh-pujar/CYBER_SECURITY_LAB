from scapy.all import sniff, wrpcap

def packet_handler(packet):
    print(packet.summary())
    packets.append(packet)

packets = []

# Sniff udP packets
sniff(filter="udp", count=10, prn=packet_handler)

# Save the captured packets to a file
wrpcap('udp_packets.pcap', packets)

