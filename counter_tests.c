#include <stdio.h>
#include <string.h>
#include "counter_proto.h"

static int sock;
static int passed = 0;
static int failed = 0;

static void cmd(const char *c, char *out) {
    if (counter_transact(sock, c, out, COUNTER_BUFSIZE) < 0) {
        fprintf(stderr, "server closed connection during test\n");
        exit(1);
    }
}

static void check(const char *name, const char *command, const char *expected) {
    char resp[COUNTER_BUFSIZE];
    cmd(command, resp);
    if (strcmp(resp, expected) == 0) {
        printf("PASS  %s\n", name);
        passed++;
    } else {
        printf("FAIL  %s — expected \"%s\", got \"%s\"\n", name, expected, resp);
        failed++;
    }
}

int main(void) {
    sock = counter_connect();
    printf("Running counter tests against %s:%d\n\n", COUNTER_HOST, COUNTER_PORT);

    /* Establish a known baseline before every run. */
    char discard[COUNTER_BUFSIZE];
    cmd("reset", discard);

    check("initial value is 0",        "value",     "0");
    check("increment returns ok",      "increment", "ok");
    check("value is 1 after increment","value",     "1");
    check("increment again",           "increment", "ok");
    check("value is 2",                "value",     "2");
    check("decrement returns ok",      "decrement", "ok");
    check("value is 1 after decrement","value",     "1");
    check("reset returns ok",          "reset",     "ok");
    check("value is 0 after reset",    "value",     "0");
    check("decrement below zero",      "decrement", "ok");
    check("value is -1",               "value",     "-1");
    check("unknown command is error",  "badcmd",    "error: unknown command");

    printf("\n%d passed, %d failed\n", passed, failed);
    close(sock);
    return failed > 0 ? 1 : 0;
}
