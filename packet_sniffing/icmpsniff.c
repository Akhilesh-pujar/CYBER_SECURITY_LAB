#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *iph = (struct ip *)(packet + 14); // Skip Ethernet header
    if (iph->ip_p == IPPROTO_ICMP) {
        struct icmphdr *icmph = (struct icmphdr *)(packet + 14 + iph->ip_hl * 4);
        printf("Captured ICMP packet from %s to %s\n", inet_ntoa(iph->ip_src), inet_ntoa(iph->ip_dst));
        printf("Type: %d, Code: %d\n", icmph->type, icmph->code);
        
        // Print the packet length
        printf("Packet length: %d\n", pkthdr->len);
        
        // Print the raw packet data
        for (int i = 0; i < pkthdr->len; i++) {
            printf("%02x ", packet[i]);
            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }
        printf("\n\n");
    }
}

int main() {
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;

    // Find all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Could not find devices: %s\n", errbuf);
        return 2;
    }

    // Print available devices and select the first one
    for (d = alldevs; d; d = d->next) {
        if (d->name != NULL) {
            dev = d->name;
            break;
        }
    }

    if (dev == NULL) {
        fprintf(stderr, "No device found\n");
        pcap_freealldevs(alldevs);
        return 2;
    }

    printf("Using device: %s\n", dev);

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net = 0;

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freealldevs(alldevs);
        pcap_close(handle);
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freealldevs(alldevs);
        pcap_close(handle);
        return 2;
    }

    pcap_loop(handle, 10, packet_handler, NULL); // Capture 10 packets

    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}


