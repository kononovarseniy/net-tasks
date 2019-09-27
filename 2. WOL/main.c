#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h> //sockaddr_ll
#include <netinet/ether.h> // ether_aton, ether_addr
#include <netinet/in.h> // htons
#include <net/ethernet.h> // ether_header
#include <net/if.h> // if_nametoindex
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#define WOL_ADDR_REP 16
#define WOL_PREAMBLE_LEN 6
#define WOL_PACKET_SIZE (ETH_ALEN * WOL_ADDR_REP + WOL_PREAMBLE_LEN)
#define PACKET_SIZE (ETH_HLEN + WOL_PACKET_SIZE)
#define ETH_P_WOL 0x0842

int main(int argc, char *argv[]) {
    char *ifname = NULL;
    struct ether_addr src, dst;
    int src_set = 0, dst_set = 0;

    int opt;
    while ((opt = getopt(argc, argv, ":i:s:d:")) != -1) {
        struct ether_addr *addr;
        switch (opt) {
            case 'i':
                ifname = strdup(optarg);
                break;
            case 's':
                if ((addr = ether_aton(optarg)) == NULL) {
                    fprintf(stderr, "Source address is invalid\n");
                    exit(1);
                }
                src = *addr;
                src_set = 1;
                break;
            case 'd':
                if ((addr = ether_aton(optarg)) == NULL) {
                    fprintf(stderr, "Destination address is invalid\n");
                    exit(1);
                }
                dst = *addr;
                dst_set = 1;
                break;
            case ':': // Missing arg
                fprintf(stderr, "Missing argument for option -%c\n", (char)optopt);
                exit(1);
            case '?': // Unknown option
                fprintf(stderr, "Unknown option -%c\n", (char)optopt);
                exit(1);
        }
    }
    if (ifname == NULL) {
        fprintf(stderr, "Interface is not set\n");
        exit(1);
    }
    if (!src_set || ! dst_set) {
        fprintf(stderr, "Source or destination is not set\n");
        exit(1);
    }

    unsigned int if_index = if_nametoindex(ifname);
    if (if_index == 0) {
        perror("if_nametosocket failed");
        exit(1);
    }
    printf("Interface %s has ifindex %d\n", ifname, if_index);

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_halen = ETH_ALEN;
    addr.sll_ifindex = if_index; 
    memcpy(&addr.sll_addr, &dst, ETH_ALEN);
    printf("Socket address structure initialized\n");

    uint8_t buf[PACKET_SIZE], *ptr = buf;
    struct ether_header *hdr = (struct ether_header *)ptr;

    memcpy(hdr->ether_dhost, &dst, ETH_ALEN);
    memcpy(hdr->ether_shost, &src, ETH_ALEN);
    hdr->ether_type = htons(ETH_P_WOL);
    ptr += ETH_HLEN;
    printf("Ethernet header initialized\n");

    memset(ptr, 0xff, WOL_PREAMBLE_LEN);
    ptr += WOL_PREAMBLE_LEN;

    for (int i = 0; i < WOL_ADDR_REP; i++) {
        memcpy(ptr, &dst, ETH_ALEN);
        ptr += ETH_ALEN;
    }
    printf("WOL payload written\n");

    // Open socket, send a packet and close the socket.
    int so = socket(AF_PACKET, SOCK_RAW, 0);
    if (so == -1) {
        perror("Unable to create socket");
        exit(1);
    }
    printf("Socket successfuly open\n");

    ssize_t sent = sendto(
            so, buf, PACKET_SIZE,
            0, (struct sockaddr *)&addr, sizeof(addr));
    if (sent == -1) {
        perror("Send failed");
        exit(1);
    }
    if (sent < WOL_PACKET_SIZE) {
        fprintf(stderr, "Send failed");
        exit(1);
    }
    printf("Packet sent\n");

    if (close(so)) {
        perror("Unable to close socket");
        exit(1);
    }
    printf("Socket closed\n");

    return 0;
}
