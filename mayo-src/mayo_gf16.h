#ifndef MAYO_GF16_H
#define MAYO_GF16_H

#include <stdint.h>
#include "mayo_params.h"

/*
 * GF(16) = GF(2^4)  with irreducible polynomial  x^4 + x + 1.
 * Elements: 4-bit nibbles 0x0 .. 0xF.
 * Addition: bitwise XOR (characteristic 2).
 * Multiplication: lookup table (256 bytes in flash).
 */

/* 16x16 multiplication table: GF16_MUL[a*16 + b] = a*b */
extern const uint8_t GF16_MUL[256];

static inline uint8_t gf16_mul(uint8_t a, uint8_t b)
{
    return GF16_MUL[((a & 0xF) << 4) | (b & 0xF)];
}

static inline uint8_t gf16_add(uint8_t a, uint8_t b)
{
    return (a ^ b) & 0xF;
}

/* a^(q-2) = a^14 via repeated squaring  (q=16) */
static inline uint8_t gf16_inv(uint8_t a)
{
    if (a == 0) return 0;
    uint8_t a2  = gf16_mul(a,  a);
    uint8_t a4  = gf16_mul(a2, a2);
    uint8_t a8  = gf16_mul(a4, a4);
    uint8_t a12 = gf16_mul(a8, a4);
    return            gf16_mul(a12, a2);   /* a^14 */
}

/* ---------- nibble-packed array helpers ----------
 *
 * A nibble array of N elements occupies ceil(N/2) bytes.
 * Element at logical index idx:
 *   even idx -> low  nibble of byte idx/2
 *   odd  idx -> high nibble of byte idx/2
 */

static inline uint8_t nibble_get(const uint8_t *arr, int idx)
{
    return (idx & 1) ? (arr[idx >> 1] >> 4) : (arr[idx >> 1] & 0xF);
}

static inline void nibble_set(uint8_t *arr, int idx, uint8_t val)
{
    if (idx & 1)
        arr[idx >> 1] = (arr[idx >> 1] & 0x0F) | ((val & 0xF) << 4);
    else
        arr[idx >> 1] = (arr[idx >> 1] & 0xF0) | (val & 0xF);
}

/* arr[idx] ^= val  (GF16 in-place add) */
static inline void nibble_add(uint8_t *arr, int idx, uint8_t val)
{
    if (idx & 1)
        arr[idx >> 1] ^= (val & 0xF) << 4;
    else
        arr[idx >> 1] ^= (val & 0xF);
}

/*
 * Decode an 8-byte bitsliced vector (m=16 GF16 elements) to a plain
 * 16-nibble array. Layout per spec Algorithm 4:
 *   bytes [0..1]  = bit-plane 0  (element 15 at MSB of byte 0, element 0 at LSB of byte 1)
 *   bytes [2..3]  = bit-plane 1
 *   bytes [4..5]  = bit-plane 2
 *   bytes [6..7]  = bit-plane 3
 */
static inline void decode_bs8(const uint8_t *bs, uint8_t out[16])
{
    for (int a = 0; a < 16; a++) {
        int bi = a / 8;           /* byte index within plane */
        int bb = 7 - (a % 8);    /* bit position (MSB=element 0 within that byte) */
        uint8_t b0 = (bs[0 * 2 + bi] >> bb) & 1;
        uint8_t b1 = (bs[1 * 2 + bi] >> bb) & 1;
        uint8_t b2 = (bs[2 * 2 + bi] >> bb) & 1;
        uint8_t b3 = (bs[3 * 2 + bi] >> bb) & 1;
        out[a] = b0 | (b1 << 1) | (b2 << 2) | (b3 << 3);
    }
}

#endif /* MAYO_GF16_H */
