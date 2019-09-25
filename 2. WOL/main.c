#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h> //sockaddr_ll
//#include <netinet/ether.h>
#include <netinet/in.h> // htons
#include <net/ethernet.h> // ether_header
#include <net/if.h> // ifreq
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

int main(int argc, const char *argv[]) {
    int so = socket(AF_PACKET, SOCK_RAW, 0);
    if (so == -1) {
        perror("Unable to create socket");
        exit(1);
    }
    printf("Socket successfuly open\n");

    uint8_t src[ETH_ALEN] = { 0x40, 0x16, 0x7e, 0x84, 0x41, 0x59 },
            dst[ETH_ALEN] = { 0x40, 0x16, 0x7e, 0x84, 0x41, 0x59 };
    //memset(src, 0, ETH_ALEN);
    //memset(dst, 0, ETH_ALEN);

    char *ifname = "enp5s0";
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(so, SIOCGIFINDEX, &ifr) == -1) {
        fprintf(stderr, "SIOCGIFINDEX on %s failed: %s\n", ifname,
                strerror(errno));
        exit(1);
    }
    printf("Interface %s has ifindex %d\n", ifname, ifr.ifr_ifindex);

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_halen = ETH_ALEN;
    addr.sll_ifindex = ifr.ifr_ifindex;
    memcpy(&addr.sll_addr, dst, ETH_ALEN);
    printf("Socket address structure initialized\n");

    uint8_t buf[PACKET_SIZE], *ptr = buf;
    struct ether_header *hdr = (struct ether_header *)ptr;

    memcpy(hdr->ether_dhost, dst, ETH_ALEN);
    memcpy(hdr->ether_shost, src, ETH_ALEN);
    hdr->ether_type = htons(ETH_P_WOL);
    ptr += ETH_HLEN;
    printf("Ethernet header initialized\n");

    for (int i = 0; i < WOL_PREAMBLE_LEN; i++)
        *ptr++ = 0xff;

    for (int i = 0; i < WOL_ADDR_REP * ETH_ALEN; i++)
        *ptr++ = dst[i % ETH_ALEN];
    printf("WOL payload written\n");

    // Send a packet and close the socket.
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
