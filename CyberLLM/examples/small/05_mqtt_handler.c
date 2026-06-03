/*
 * MQTT broker callback for an in-vehicle infotainment unit.
 * Receives JSON-ish messages on /vehicle/cmd/<vin>/<action>.
 *
 * Vulnerabilities to flag (all deliberate):
 *  - CODE-013: strcpy / sprintf into a fixed buffer (stack overflow).
 *  - CODE-001: system() invoked with a concatenated topic component.
 *  - CODE-014: strcmp(secret, recv) NOT constant time → secret leak.
 *  - CODE-015: format-string vulnerability in printf(topic).
 *  - CODE-016: missing NULL-check after malloc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SHARED_SECRET "infotainment-rev-7-secret"   /* CODE-003 too */

static int verify_secret(const char *given) {
    /* CODE-014: short-circuit comparison, leaks length via timing. */
    return strcmp(SHARED_SECRET, given) == 0;
}

void on_message(const char *topic, const char *payload) {
    char cmd[64];
    char log_line[128];

    /* CODE-013: no bounds check on either copy. */
    strcpy(cmd, payload);
    sprintf(log_line, "received on %s: %s", topic, payload);

    /* CODE-015: topic is attacker-controlled and goes into the
       format string of printf. */
    printf(topic);
    printf("\n");

    /* CODE-001: command injection through the action segment. */
    char shell[256];
    sprintf(shell, "/usr/bin/ivi-action --do=%s", cmd);
    system(shell);
}

char *prepare_response(size_t size) {
    char *buf = (char *)malloc(size);
    /* CODE-016: no NULL check; the next write would segfault if
       malloc failed under memory pressure. */
    memset(buf, 0, size);
    return buf;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <topic> <payload>\n", argv[0]);
        return 1;
    }
    if (!verify_secret(getenv("MQTT_SECRET") ? getenv("MQTT_SECRET") : "")) {
        fprintf(stderr, "auth failed\n");
        return 2;
    }
    on_message(argv[1], argv[2]);
    char *resp = prepare_response(4096);
    free(resp);
    return 0;
}
