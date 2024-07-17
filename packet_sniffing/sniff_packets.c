#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define ICMP_PROTOCOL 1
#define TCP_PROTOCOL 6

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header;
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        if (ip_header->ip_p == ICMP_PROTOCOL) {
            // ICMP packet
            struct icmphdr *icmp_header;
            icmp_header = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            // Check if it's between specific hosts
            char *source_ip = inet_ntoa(ip_header->ip_src);
            char *dest_ip = inet_ntoa(ip_header->ip_dst);
            if (strcmp(source_ip, "10.0.0.1") == 0 && strcmp(dest_ip, "10.0.0.2") == 0) {
                // Process ICMP packet between specific hosts
                printf("ICMP packet between 10.0.0.1 and 10.0.0.2\n");
            }
        } else if (ip_header->ip_p == TCP_PROTOCOL) {
            // TCP packet
            struct tcphdr *tcp_header;
            tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            // Check if destination port is in range 10 to 50
            int dest_port = ntohs(tcp_header->th_dport);
            if (dest_port >= 10 && dest_port <= 50) {
                // Process TCP packet with destination port in range 10 to 50
                printf("TCP packet with destination port in range 10 to 50\n");
            }
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *dev = "eth0"; // Change this to your network interface

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}
