#include <stdio.h>
#include "counter_proto.h"

int main(void) {
    int sock = counter_connect();
    printf("Connected to counter server at %s:%d\n", COUNTER_HOST, COUNTER_PORT);
    printf("Commands: i=increment  d=decrement  r=reset  v=value  q=quit\n\n");

    char line[COUNTER_BUFSIZE];
    char resp[COUNTER_BUFSIZE];

    while (1) {
        printf("> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) break;

        const char *cmd = NULL;
        switch (line[0]) {
            case 'i': cmd = "increment"; break;
            case 'd': cmd = "decrement"; break;
            case 'r': cmd = "reset";     break;
            case 'v': cmd = "value";     break;
            case 'q': close(sock); return 0;
            default:  printf("unknown command — use i, d, r, v, or q\n"); continue;
        }

        if (counter_transact(sock, cmd, resp, sizeof(resp)) < 0) {
            fprintf(stderr, "server closed connection\n");
            break;
        }
        printf("%s\n", resp);
    }

    close(sock);
    return 0;
}
