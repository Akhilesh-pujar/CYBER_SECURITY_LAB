#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct ipheader {
    unsigned char iph_ihl : 4, iph_ver : 4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_offset;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    unsigned int iph_sourceip;
    unsigned int iph_destip;
};

int main() {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    struct ipheader iph;
    iph.iph_ihl = 5;
    iph.iph_ver = 4;
    iph.iph_tos = 0;
    iph.iph_len = sizeof(struct ipheader);
    iph.iph_ident = htons(54321);
    iph.iph_ttl = 255;
    iph.iph_protocol = IPPROTO_TCP;
    iph.iph_chksum = 0;
    iph.iph_sourceip = inet_addr("source_ip_address");
    iph.iph_destip = inet_addr("destination_ip_address");

    char packet[sizeof(struct ipheader)];
    memcpy(packet, &iph, sizeof(struct ipheader));

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = iph.iph_destip;
    memset(dest_addr.sin_zero, 0, sizeof(dest_addr.sin_zero));

    if (sendto(sockfd, packet, sizeof(struct ipheader), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Packet sending failed");
        exit(1);
    } else {
        printf("Spoofed packet sent successfully.\n");
    }

    close(sockfd);
    return 0;
}

