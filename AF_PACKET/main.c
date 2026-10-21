#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define FRAME_SIZE 65536
static volatile sig_atomic_t stopping;

static void on_signal(int sig) { (void)sig; stopping = 1; }

static int open_packet_socket(void) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) perror("socket(AF_PACKET)");
    return fd;
}

int main(int argc, char **argv) {
    int rx = -1, tx = -1;
    unsigned int src_index, dst_index;
    unsigned char frame[FRAME_SIZE];
    unsigned long long packets = 0, bytes = 0, errors = 0;
    struct sockaddr_ll addr;
    struct sigaction sa;

    if (argc != 3) {
        fprintf(stderr, "Использование: sudo %s <исходный-интерфейс> <целевой-интерфейс>\n", argv[0]);
        fprintf(stderr, "Пример: sudo %s eth0 eth1\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (!strcmp(argv[1], argv[2])) {
        fprintf(stderr, "Исходный и целевой интерфейсы должны различаться.\n");
        return EXIT_FAILURE;
    }

    src_index = if_nametoindex(argv[1]);
    dst_index = if_nametoindex(argv[2]);
    if (!src_index || !dst_index) {
        fprintf(stderr, "Не найден интерфейс: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    rx = open_packet_socket();
    if (rx < 0) goto fail;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = (int)src_index;
    if (bind(rx, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind(source)");
        goto fail;
    }

    tx = open_packet_socket();
    if (tx < 0) goto fail;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = (int)dst_index;
    if (bind(tx, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind(destination)");
        goto fail;
    }

    printf("SPAN через AF_PACKET: %s -> %s\n", argv[1], argv[2]);
    printf("Нажмите Ctrl+C для остановки.\n");

    while (!stopping) {
        struct sockaddr_ll from;
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(rx, frame, sizeof(frame), 0,
                             (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            errors++;
            continue;
        }

        /* Не пересылаем исходящие кадры, чтобы не создавать петлю. */
        if (from.sll_pkttype == PACKET_OUTGOING) continue;

        memset(&addr, 0, sizeof(addr));
        addr.sll_family = AF_PACKET;
        addr.sll_protocol = htons(ETH_P_ALL);
        addr.sll_ifindex = (int)dst_index;
        addr.sll_halen = ETH_ALEN;

        ssize_t sent = sendto(tx, frame, (size_t)n, 0,
                              (struct sockaddr *)&addr, sizeof(addr));
        if (sent < 0 || sent != n) {
            if (sent < 0) perror("sendto");
            else fprintf(stderr, "sendto: отправлено %zd из %zd байт\n", sent, n);
            errors++;
            continue;
        }

        packets++;
        bytes += (unsigned long long)n;
        if (packets % 1000 == 0) {
            printf("Кадров: %llu, байт: %llu, ошибок: %llu\n", packets, bytes, errors);
            fflush(stdout);
        }
    }

    printf("\nИтого: кадров=%llu, байт=%llu, ошибок=%llu\n", packets, bytes, errors);
    close(tx);
    close(rx);
    return EXIT_SUCCESS;

fail:
    if (tx >= 0) close(tx);
    if (rx >= 0) close(rx);
    return EXIT_FAILURE;
}
