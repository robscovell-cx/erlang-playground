#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define COUNTER_HOST "127.0.0.1"
#define COUNTER_PORT 9090
#define COUNTER_BUFSIZE 256

/* Connect to the counter server. Returns the socket fd, or exits on failure. */
static inline int counter_connect(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(1); }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(COUNTER_PORT),
    };
    if (inet_pton(AF_INET, COUNTER_HOST, &addr.sin_addr) <= 0) {
        perror("inet_pton"); exit(1);
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); exit(1);
    }
    return sock;
}

/* Send a command and read the response into buf (null-terminated, newline stripped).
   Returns the number of bytes in the response, or -1 on connection close. */
static inline int counter_transact(int sock, const char *cmd, char *buf, int bufsize) {
    if (send(sock, cmd, strlen(cmd), 0) < 0 ||
        send(sock, "\n", 1, 0) < 0) {
        perror("send"); exit(1);
    }
    ssize_t n = recv(sock, buf, bufsize - 1, 0);
    if (n <= 0) return -1;
    buf[n] = '\0';
    if (n > 0 && buf[n - 1] == '\n') buf[--n] = '\0';
    return (int)n;
}
