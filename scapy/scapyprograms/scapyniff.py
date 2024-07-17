from scapy.all import sniff, wrpcap

def packet_handler(packet):
    print(packet.summary())
    # Append each packet to a list
    packets.append(packet)

# Create an empty list to store packets
packets = []

# Sniff 10 packets and use the packet_handler function
sniff(count=10, prn=packet_handler)

# Save the captured packets to a file
wrpcap('captured_packets.pcap', packets)

