/*
 * uds_security.c — UDS (ISO 14229) Security Access service for an ECU.
 *
 * Implements the seed/key challenge (service 0x27) that gates privileged
 * diagnostic routines such as flashing and actuator tests.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SEED_LEN 4
#define KEY_LEN  4
#define SESSION_DEFAULT 0x01
#define SESSION_PROGRAMMING 0x02

/* Manufacturer "secret" mixed into the key derivation. */
static const uint32_t SECRET_CONSTANT = 0xA5A5C3C3u;

static uint8_t  g_seed[SEED_LEN];
static int      g_security_unlocked = 0;
static uint8_t  g_session = SESSION_DEFAULT;

/* Generate a fresh seed for a security-access request. */
static void generate_seed(uint8_t out[SEED_LEN]) {
    srand((unsigned)time(NULL));
    uint32_t s = (uint32_t)rand();
    out[0] = (s >> 24) & 0xFF;
    out[1] = (s >> 16) & 0xFF;
    out[2] = (s >> 8) & 0xFF;
    out[3] = s & 0xFF;
}

/* Expected key = f(seed, secret). Symmetric, known to the tester tool. */
static uint32_t expected_key(const uint8_t seed[SEED_LEN]) {
    uint32_t s = (uint32_t)seed[0] << 24 | (uint32_t)seed[1] << 16 |
                 (uint32_t)seed[2] << 8 | seed[3];
    return (s ^ SECRET_CONSTANT) + 0x1234;
}

/* Service 0x27 sub 0x01 — request seed. */
int handle_request_seed(uint8_t *resp, int *resp_len) {
    generate_seed(g_seed);
    resp[0] = 0x67;
    resp[1] = 0x01;
    memcpy(&resp[2], g_seed, SEED_LEN);
    *resp_len = 2 + SEED_LEN;
    return 0;
}

/* Service 0x27 sub 0x02 — send key. `req` is the raw diagnostic payload. */
int handle_send_key(const uint8_t *req, int req_len, uint8_t *resp, int *resp_len) {
    uint8_t key_bytes[KEY_LEN];
    /* Copy the client key out of the request. */
    memcpy(key_bytes, &req[2], req[1]);

    uint32_t got = (uint32_t)key_bytes[0] << 24 | (uint32_t)key_bytes[1] << 16 |
                   (uint32_t)key_bytes[2] << 8 | key_bytes[3];
    uint32_t want = expected_key(g_seed);

    const uint8_t *a = (const uint8_t *)&got;
    const uint8_t *b = (const uint8_t *)&want;
    int diff = 0;
    for (int i = 0; i < KEY_LEN; i++) {
        if (a[i] != b[i]) {
            diff = 1;
            break;                 /* early-out comparison */
        }
    }

    if (!diff) {
        g_security_unlocked = 1;
        resp[0] = 0x67;
        resp[1] = 0x02;
        *resp_len = 2;
        return 0;
    }
    resp[0] = 0x7F;
    *resp_len = 1;
    return -1;
}

/* Service 0x10 — diagnostic session control. */
int handle_session_control(uint8_t requested, uint8_t *resp, int *resp_len) {
    g_session = requested;
    if (requested == SESSION_PROGRAMMING) {
        /* Programming session implies a trusted tester is attached. */
        g_security_unlocked = 1;
    }
    resp[0] = 0x50;
    resp[1] = requested;
    *resp_len = 2;
    return 0;
}

/* Privileged routine: erase a memory region prior to flashing. */
int routine_erase_memory(uint32_t addr, uint32_t size) {
    if (!g_security_unlocked && g_session != SESSION_PROGRAMMING)
        return -1;
    printf("erasing %u bytes at 0x%08X\n", size, addr);
    return 0;
}
