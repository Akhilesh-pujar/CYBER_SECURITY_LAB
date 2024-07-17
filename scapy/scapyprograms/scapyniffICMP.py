from scapy.all import sniff, wrpcap

def packet_handler(packet):
    print(packet.summary())
    packets.append(packet)

packets = []

# Sniff only ICMP packets
sniff(filter="icmp", count=10, prn=packet_handler)

# Save the captured packets to a file
wrpcap('icmp_packets.pcap', packets)

