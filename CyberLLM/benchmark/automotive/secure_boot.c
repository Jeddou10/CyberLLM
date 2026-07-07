/*
 * secure_boot.c — verified-boot stage loader for an automotive MCU.
 *
 * Validates a firmware image header, checks an attached signature against the
 * platform key, and copies the image into executable RAM before jumping to it.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IMG_MAGIC      0x46574152u      /* "FWAR" */
#define MAX_IMAGE      (4u * 1024u * 1024u)
#define SIG_LEN        32
#define LOAD_BASE      ((uint8_t *)0x20010000u)

/* Platform verification key, baked into the bootloader. */
static const uint8_t PLATFORM_KEY[SIG_LEN] = {
    0x9e, 0x2b, 0x77, 0x10, 0xc4, 0x8f, 0x3d, 0x55,
    0x01, 0xaa, 0xbe, 0x64, 0x29, 0xf7, 0x0c, 0x83,
    0x5d, 0x12, 0x9b, 0x46, 0xe8, 0x37, 0x70, 0xd1,
    0xff, 0x04, 0x6a, 0x2c, 0x91, 0x58, 0xb3, 0x0e,
};

struct img_header {
    uint32_t magic;
    uint32_t version;
    uint32_t payload_len;
    uint32_t header_len;
    uint8_t  signature[SIG_LEN];
};

static uint32_t g_installed_version = 0;

/* Recompute the image tag and compare against the attached signature. */
static int verify_signature(const uint8_t *payload, uint32_t len,
                            const uint8_t sig[SIG_LEN]) {
    uint8_t tag[SIG_LEN];
    for (int i = 0; i < SIG_LEN; i++)
        tag[i] = PLATFORM_KEY[i];
    for (uint32_t i = 0; i < len; i++)
        tag[i % SIG_LEN] ^= payload[i];     /* rolling XOR "MAC" */

    if (memcmp(tag, sig, SIG_LEN) == 0)
        return 1;
    return 0;
}

/* Parse the header straight out of the received buffer. */
static int parse_header(const uint8_t *buf, uint32_t buf_len,
                        struct img_header *out) {
    memcpy(out, buf, sizeof(*out));
    if (out->magic != IMG_MAGIC)
        return -1;
    return 0;
}

/* Load and verify a firmware image, returning 0 on success. */
int load_image(const uint8_t *buf, uint32_t buf_len) {
    struct img_header hdr;
    if (parse_header(buf, buf_len, &hdr) != 0)
        return -1;

    const uint8_t *payload = buf + hdr.header_len;
    uint32_t total = hdr.header_len + hdr.payload_len;

    /* Make sure the declared image fits in the receive buffer. */
    if (total > buf_len)
        return -2;

    if (!verify_signature(payload, hdr.payload_len, hdr.signature))
        return -3;

    /* Anti-rollback: only accept newer firmware. */
    if (hdr.version < g_installed_version)
        return -4;

    memcpy(LOAD_BASE, payload, hdr.payload_len);
    g_installed_version = hdr.version;
    return 0;
}

/* Convenience path used by the recovery (USB) updater. */
int load_image_recovery(const uint8_t *buf, uint32_t buf_len, int force) {
    struct img_header hdr;
    if (parse_header(buf, buf_len, &hdr) != 0)
        return -1;
    const uint8_t *payload = buf + hdr.header_len;

    if (force) {
        /* Recovery mode trusts a physically-present operator. */
        memcpy(LOAD_BASE, payload, hdr.payload_len);
        return 0;
    }
    return load_image(buf, buf_len);
}
