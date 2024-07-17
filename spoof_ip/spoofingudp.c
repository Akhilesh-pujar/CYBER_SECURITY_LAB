#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    char packet[4096];
    struct ip *iph = (struct ip *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    char *data = packet + sizeof(struct ip) + sizeof(struct udphdr);
    strcpy(data, "Hello, this is a spoofed UDP packet!");

    memset(packet, 0, 4096);

    // Fill in the IP Header
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(data);
    iph->ip_id = htonl(54321); // ID of this packet
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0; // Set to 0 before calculating checksum
    iph->ip_src.s_addr = inet_addr("1.2.3.4"); // Spoofed source IP
    iph->ip_dst.s_addr = inet_addr("5.6.7.8");

    // Calculate the IP checksum
    iph->ip_sum = checksum((unsigned short *)packet, iph->ip_len);

    // Fill in the UDP Header
    udph->source = htons(12345);
    udph->dest = htons(80);
    udph->len = htons(sizeof(struct udphdr) + strlen(data));
    udph->check = 0; // Leave checksum 0 now

    // Now the UDP checksum
    psh.source_address = inet_addr("1.2.3.4");
    psh.dest_address = inet_addr("5.6.7.8");
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    char *pseudogram = malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + strlen(data));

    udph->check = checksum((unsigned short *)pseudogram, psize);

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        return 1;
    }

    // Send the packet
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iph->ip_dst.s_addr;

    if (sendto(sock, packet, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("Send failed");
    } else {
        printf("Packet Sent. Length : %d \n", iph->ip_len);
    }

    return 0;
}
