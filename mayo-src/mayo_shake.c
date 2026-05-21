#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mayo_shake.h"

/* ------------------------------------------------------------------ */
/*  Keccak-f[1600]  — 64-bit lanes, 24 rounds                         */
/* ------------------------------------------------------------------ */

#define ROT64(x, n)  (((uint64_t)(x) << (n)) | ((uint64_t)(x) >> (64 - (n))))

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

/* Rho rotation offsets indexed as state[5*y+x] */
static const uint8_t RHO[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

/* Static temp buffer avoids 200 bytes of stack inside keccak_f */
static uint64_t kf_B[25];

static void keccak_f1600(uint64_t *a)
{
    int i;
    uint64_t c[5], d[5];

    for (i = 0; i < 24; i++) {
        /* Theta */
        c[0] = a[0] ^ a[5]  ^ a[10] ^ a[15] ^ a[20];
        c[1] = a[1] ^ a[6]  ^ a[11] ^ a[16] ^ a[21];
        c[2] = a[2] ^ a[7]  ^ a[12] ^ a[17] ^ a[22];
        c[3] = a[3] ^ a[8]  ^ a[13] ^ a[18] ^ a[23];
        c[4] = a[4] ^ a[9]  ^ a[14] ^ a[19] ^ a[24];

        d[0] = c[4] ^ ROT64(c[1], 1);
        d[1] = c[0] ^ ROT64(c[2], 1);
        d[2] = c[1] ^ ROT64(c[3], 1);
        d[3] = c[2] ^ ROT64(c[4], 1);
        d[4] = c[3] ^ ROT64(c[0], 1);

        a[0]^=d[0]; a[1]^=d[1]; a[2]^=d[2]; a[3]^=d[3]; a[4]^=d[4];
        a[5]^=d[0]; a[6]^=d[1]; a[7]^=d[2]; a[8]^=d[3]; a[9]^=d[4];
        a[10]^=d[0];a[11]^=d[1];a[12]^=d[2];a[13]^=d[3];a[14]^=d[4];
        a[15]^=d[0];a[16]^=d[1];a[17]^=d[2];a[18]^=d[3];a[19]^=d[4];
        a[20]^=d[0];a[21]^=d[1];a[22]^=d[2];a[23]^=d[3];a[24]^=d[4];

        /* Rho + Pi: B[y][2x+3y mod 5] = ROT(a[x][y], rho[x][y]) */
        {
            int x, y;
            for (y = 0; y < 5; y++)
                for (x = 0; x < 5; x++)
                    kf_B[5 * ((2*x + 3*y) % 5) + y] =
                        ROT64(a[5*y + x], RHO[5*y + x]);
        }

        /* Chi */
        {
            int j;
            for (j = 0; j < 25; j += 5) {
                a[j+0] = kf_B[j+0] ^ (~kf_B[j+1] & kf_B[j+2]);
                a[j+1] = kf_B[j+1] ^ (~kf_B[j+2] & kf_B[j+3]);
                a[j+2] = kf_B[j+2] ^ (~kf_B[j+3] & kf_B[j+4]);
                a[j+3] = kf_B[j+3] ^ (~kf_B[j+4] & kf_B[j+0]);
                a[j+4] = kf_B[j+4] ^ (~kf_B[j+0] & kf_B[j+1]);
            }
        }

        /* Iota */
        a[0] ^= RC[i];
    }
}

/* ------------------------------------------------------------------ */
/*  SHAKE256 API                                                        */
/* ------------------------------------------------------------------ */

shake256_ctx g_shake;

void shake256_init(shake256_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void shake256_absorb(shake256_ctx *ctx, const uint8_t *in, size_t len)
{
    uint8_t *st = (uint8_t *)ctx->state;
    size_t i;
    for (i = 0; i < len; i++) {
        st[ctx->buf_pos++] ^= in[i];
        if (ctx->buf_pos == SHAKE256_RATE) {
            keccak_f1600(ctx->state);
            ctx->buf_pos = 0;
        }
    }
}

void shake256_finalize(shake256_ctx *ctx)
{
    uint8_t *st = (uint8_t *)ctx->state;
    st[ctx->buf_pos]          ^= 0x1F; /* SHAKE256 domain suffix */
    st[SHAKE256_RATE - 1]     ^= 0x80;
    keccak_f1600(ctx->state);
    ctx->buf_pos   = 0;
    ctx->squeezing = 1;
}

void shake256_squeeze(shake256_ctx *ctx, uint8_t *out, size_t len)
{
    uint8_t *st = (uint8_t *)ctx->state;
    size_t i;
    for (i = 0; i < len; i++) {
        if (ctx->buf_pos == SHAKE256_RATE) {
            keccak_f1600(ctx->state);
            ctx->buf_pos = 0;
        }
        out[i] = st[ctx->buf_pos++];
    }
}

void shake256_multi(
    const uint8_t *a, size_t alen,
    const uint8_t *b, size_t blen,
    const uint8_t *c, size_t clen,
    const uint8_t *d, size_t dlen,
    uint8_t *out, size_t outlen)
{
    shake256_init(&g_shake);
    if (a && alen) shake256_absorb(&g_shake, a, alen);
    if (b && blen) shake256_absorb(&g_shake, b, blen);
    if (c && clen) shake256_absorb(&g_shake, c, clen);
    if (d && dlen) shake256_absorb(&g_shake, d, dlen);
    shake256_finalize(&g_shake);
    shake256_squeeze(&g_shake, out, outlen);
}
