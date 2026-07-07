/*
 * clean_ringbuffer.c — bounded SPSC ring buffer for CAN frame staging.
 *
 * Negative control: written defensively with full bounds checking, no shell
 * execution, no hard-coded secrets, and a constant-time tag comparison.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define RB_CAP 256
#define FRAME_MAX 64

struct frame {
    uint32_t id;
    uint8_t  len;                 /* validated to be <= FRAME_MAX */
    uint8_t  data[FRAME_MAX];
};

struct ringbuf {
    struct frame slots[RB_CAP];
    size_t head;
    size_t tail;
};

void rb_init(struct ringbuf *rb) {
    rb->head = 0;
    rb->tail = 0;
}

static size_t rb_next(size_t i) {
    return (i + 1) % RB_CAP;
}

/* Push a frame; rejects over-long payloads and a full buffer. */
int rb_push(struct ringbuf *rb, uint32_t id, const uint8_t *data, uint8_t len) {
    if (data == NULL || len > FRAME_MAX)
        return -1;
    if (rb_next(rb->head) == rb->tail)
        return -2;                /* full */

    struct frame *f = &rb->slots[rb->head];
    f->id = id;
    f->len = len;
    memcpy(f->data, data, len);   /* len is bounded by the check above */
    rb->head = rb_next(rb->head);
    return 0;
}

/* Pop a frame into the caller-provided slot. */
int rb_pop(struct ringbuf *rb, struct frame *out) {
    if (rb->head == rb->tail)
        return -1;                /* empty */
    *out = rb->slots[rb->tail];
    rb->tail = rb_next(rb->tail);
    return 0;
}

/* Constant-time comparison of two equal-length tags. */
int ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++)
        acc |= (uint8_t)(a[i] ^ b[i]);
    return acc == 0;
}
