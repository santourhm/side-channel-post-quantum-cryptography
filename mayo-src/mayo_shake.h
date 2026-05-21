#ifndef MAYO_SHAKE_H
#define MAYO_SHAKE_H

#include <stdint.h>
#include <stddef.h>

/*
 * Minimal SHAKE256 (Keccak-f[1600], rate = 136 bytes).
 * Global context is defined in mayo_shake.c so it lives in BSS
 * and doesn't cost stack.
 */

#define SHAKE256_RATE   136

typedef struct {
    uint64_t state[25]; /* 200 bytes */
    uint8_t  buf_pos;   /* position within rate window */
    uint8_t  squeezing; /* 0 = absorbing, 1 = squeezing */
} shake256_ctx;

/* Global shared context (one at a time — sequential use only) */
extern shake256_ctx g_shake;

void shake256_init(shake256_ctx *ctx);
void shake256_absorb(shake256_ctx *ctx, const uint8_t *in, size_t len);
void shake256_finalize(shake256_ctx *ctx);
void shake256_squeeze(shake256_ctx *ctx, uint8_t *out, size_t len);

/*
 * One-shot: hash up to 4 concatenated inputs and produce outlen bytes.
 * Pass NULL/0 for unused slots.
 */
void shake256_multi(
    const uint8_t *a, size_t alen,
    const uint8_t *b, size_t blen,
    const uint8_t *c, size_t clen,
    const uint8_t *d, size_t dlen,
    uint8_t *out, size_t outlen);

#endif /* MAYO_SHAKE_H */
