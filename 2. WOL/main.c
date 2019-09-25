#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define WOL_PACKET_SIZE


int main(int argc, const char *argv[]) {
    int so = socket(AF_PACKET, SOCK_RAW, 0);
    if (so == -1) {
        perror("Unable to create socket");
        exit(1);
    }

    char buf[100];
    size_t len = 100;
    ssize_t sent = send(so, buf, len, 0);
    if (sent == -1) {
        perror("Send failed");
        exit(1);
    }

    if (close(so)) {
        perror("Unable to close socket");
        exit(1);
    }

    return 0;
}
