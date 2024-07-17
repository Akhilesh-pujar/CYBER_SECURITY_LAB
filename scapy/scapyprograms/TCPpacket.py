from scapy.all import sniff, wrpcap

def packet_handler(packet):
    print(packet.summary())
    packets.append(packet)

packets = []

# Sniff TCP packets
sniff(filter="tcp", count=10, prn=packet_handler)

# Save the captured packets to a file
wrpcap('tcp_packets.pcap', packets)

