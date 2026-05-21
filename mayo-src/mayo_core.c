#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mayo_params.h"
#include "mayo_gf16.h"
#include "mayo_shake.h"
#include "mayo_core.h"

/* ================================================================== */
/*  GF(16) multiplication table — 256 bytes in flash (.rodata)        */
/* ================================================================== */

const uint8_t GF16_MUL[256] = {
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
    0x0,0x2,0x4,0x6,0x8,0xA,0xC,0xE,0x3,0x1,0x7,0x5,0xB,0x9,0xF,0xD,
    0x0,0x3,0x6,0x5,0xC,0xF,0xA,0x9,0xB,0x8,0xD,0xE,0x7,0x4,0x1,0x2,
    0x0,0x4,0x8,0xC,0x3,0x7,0xB,0xF,0x6,0x2,0xE,0xA,0x5,0x1,0xD,0x9,
    0x0,0x5,0xA,0xF,0x7,0x2,0xD,0x8,0xE,0xB,0x4,0x1,0x9,0xC,0x3,0x6,
    0x0,0x6,0xC,0xA,0xB,0xD,0x7,0x1,0x5,0x3,0x9,0xF,0xE,0x8,0x2,0x4,
    0x0,0x7,0xE,0x9,0xF,0x8,0x1,0x6,0xD,0xA,0x3,0x4,0x2,0x5,0xC,0xB,
    0x0,0x8,0x3,0xB,0x6,0xE,0x5,0xD,0xC,0x4,0xF,0x7,0xA,0x2,0x9,0x1,
    0x0,0x9,0x1,0x8,0x2,0xB,0x3,0xA,0x4,0xD,0x5,0xC,0x6,0xF,0x7,0xE,
    0x0,0xA,0x7,0xD,0xE,0x4,0x9,0x3,0xF,0x5,0x8,0x2,0x1,0xB,0x6,0xC,
    0x0,0xB,0x5,0xE,0xA,0x1,0xF,0x4,0x7,0xC,0x2,0x9,0xD,0x6,0x8,0x3,
    0x0,0xC,0xB,0x7,0x5,0x9,0xE,0x2,0xA,0x6,0x1,0xD,0xF,0x3,0x4,0x8,
    0x0,0xD,0x9,0x4,0x1,0xC,0x8,0x5,0x2,0xF,0xB,0x6,0x3,0xE,0xA,0x7,
    0x0,0xE,0xF,0x1,0xD,0x3,0x2,0xC,0x9,0x7,0x6,0x8,0x4,0xA,0xB,0x5,
    0x0,0xF,0xD,0x2,0x9,0x6,0x4,0xB,0x1,0xE,0xC,0x3,0x8,0x7,0x5,0xA,
};

/* ================================================================== */
/*  Global RAM buffers (all in .bss, counted against 4 KB budget)     */
/* ================================================================== */

uint8_t g_mayo_esk[MAYO_ESK_B];          /* 576 B: seedsk|seedpk|O|L  */

/* Work buffers shared between calls — large enough for signing */
static uint8_t g_A[MAYO_M * MAYO_KO / 2];  /* 160 B: system matrix A   */
static uint8_t g_Mi[MAYO_K][MAYO_M * MAYO_O / 2]; /* 160 B: all Mi     */

/* ================================================================== */
/*  Key expansion: mayo_expand_sk()                                    */
/* ================================================================== */

void mayo_expand_sk(const uint8_t seedsk[MAYO_SKSEED_B])
{
    uint8_t  shake_out[MAYO_PKSEED_B + MAYO_O_B]; /* 48 bytes on stack */
    uint8_t  decoded[16];                           /* one bitsliced pos */
    uint8_t  bs8[8];                                /* one bitsliced vec  */
    int r, s, d, a;

    /* --- 1. SHAKE256(seedsk) → seedpk (16B) || O_encoded (32B) --- */
    shake256_multi(seedsk, MAYO_SKSEED_B,
                   NULL, 0, NULL, 0, NULL, 0,
                   shake_out, sizeof(shake_out));

    /* Store seedsk, seedpk, O into ESK */
    memcpy(g_mayo_esk + MAYO_ESK_SEEDSK_OFF, seedsk,          MAYO_SKSEED_B);
    memcpy(g_mayo_esk + MAYO_ESK_SEEDPK_OFF, shake_out,       MAYO_PKSEED_B);
    memcpy(g_mayo_esk + MAYO_ESK_O_OFF,      shake_out + MAYO_PKSEED_B, MAYO_O_B);

    /* --- 2. Zero L --- */
    memset(g_mayo_esk + MAYO_ESK_L_OFF, 0, MAYO_L_B);

    /* --- 3. SHAKE256(seedpk) stream: compute L = (P1+P1^T)*O + P2 --- */
    shake256_init(&g_shake);
    shake256_absorb(&g_shake, shake_out /* seedpk */, MAYO_PKSEED_B);
    shake256_finalize(&g_shake);

    /* P1: upper-triangular positions (r, s) with r <= s, r in [V], s in [V] */
    for (r = 0; r < MAYO_V; r++) {
        for (s = r; s < MAYO_V; s++) {
            shake256_squeeze(&g_shake, bs8, 8);
            if (r == s) continue; /* diagonal: (P1+P1^T)[r,r] = 2*P1[r,r] = 0 */

            decode_bs8(bs8, decoded); /* decoded[a] = P1_a[r,s] for a in [M] */

            for (d = 0; d < MAYO_O; d++) {
                uint8_t O_s_d = nibble_get(g_mayo_esk + MAYO_ESK_O_OFF, s * MAYO_O + d);
                uint8_t O_r_d = nibble_get(g_mayo_esk + MAYO_ESK_O_OFF, r * MAYO_O + d);
                for (a = 0; a < MAYO_M; a++) {
                    /* L[r,d,a] ^= P1_a[r,s] * O[s,d]  (upper part of P1+P1^T) */
                    nibble_add(g_mayo_esk + MAYO_ESK_L_OFF,
                               (r * MAYO_O + d) * MAYO_M + a,
                               gf16_mul(decoded[a], O_s_d));
                    /* L[s,d,a] ^= P1_a[r,s] * O[r,d]  (lower part of P1+P1^T) */
                    nibble_add(g_mayo_esk + MAYO_ESK_L_OFF,
                               (s * MAYO_O + d) * MAYO_M + a,
                               gf16_mul(decoded[a], O_r_d));
                }
            }
        }
    }

    /* P2: all (r, d) positions, r in [V], d in [O] */
    for (r = 0; r < MAYO_V; r++) {
        for (d = 0; d < MAYO_O; d++) {
            shake256_squeeze(&g_shake, bs8, 8);
            decode_bs8(bs8, decoded); /* decoded[a] = P2_a[r,d] */
            for (a = 0; a < MAYO_M; a++) {
                nibble_add(g_mayo_esk + MAYO_ESK_L_OFF,
                           (r * MAYO_O + d) * MAYO_M + a,
                           decoded[a]);
            }
        }
    }
}

/* ================================================================== */
/*  Signing helpers                                                     */
/* ================================================================== */

/*
 * Compute Mi[eq*O + d] = sum_r  vi[r] * L[r,d,eq]
 * Mi and vi are nibble-packed arrays.
 */
static void compute_Mi(uint8_t *Mi, const uint8_t *vi, const uint8_t *L)
{
    int r, d, eq;
    memset(Mi, 0, MAYO_M * MAYO_O / 2);
    for (r = 0; r < MAYO_V; r++) {
        uint8_t vr = nibble_get(vi, r);
        if (vr == 0) continue;
        for (d = 0; d < MAYO_O; d++) {
            for (eq = 0; eq < MAYO_M; eq++) {
                uint8_t l_val = nibble_get(L, (r * MAYO_O + d) * MAYO_M + eq);
                nibble_add(Mi, eq * MAYO_O + d, gf16_mul(vr, l_val));
            }
        }
    }
}

/*
 * y[eq] ^= (E^ell * u)[eq]  where E^ell is cyclic right rotation by ell.
 * (E^ell * u)_eq = u[(eq - ell + M) % M]
 */
static void subtract_El_u(uint8_t *y, const uint8_t *u, int ell)
{
    int eq;
    for (eq = 0; eq < MAYO_M; eq++) {
        int src = (eq - ell + MAYO_M) % MAYO_M;
        nibble_add(y, eq, nibble_get(u, src));
    }
}

/*
 * A[:, block*O : (block+1)*O] ^= E^ell * M
 * (E^ell * M)_{eq, d} = M_{(eq-ell+M)%M, d}
 */
static void add_El_M_to_A(uint8_t *A, const uint8_t *M, int block, int ell)
{
    int eq, d;
    for (eq = 0; eq < MAYO_M; eq++) {
        int src_eq = (eq - ell + MAYO_M) % MAYO_M;
        for (d = 0; d < MAYO_O; d++) {
            nibble_add(A, eq * MAYO_KO + block * MAYO_O + d,
                       nibble_get(M, src_eq * MAYO_O + d));
        }
    }
}

/*
 * Gaussian elimination over GF(16): put (A | y) in row-echelon form.
 * A:   m x ko  nibble array (modified in-place)
 * aug: m       nibble array (the augmented column, modified in-place)
 * Returns the pivot rank (should be MAYO_M for a full-rank system).
 */
static int gauss_elim(uint8_t *A, uint8_t *aug)
{
    int pr = 0, pc = 0; /* pivot row, pivot column */
    int i, c;

    while (pr < MAYO_M && pc < MAYO_KO) {
        /* Find pivot in column pc from row pr downward */
        int next = -1;
        for (i = pr; i < MAYO_M; i++) {
            if (nibble_get(A, i * MAYO_KO + pc) != 0) { next = i; break; }
        }
        if (next < 0) { pc++; continue; }

        /* Swap rows pr and next */
        if (next != pr) {
            for (c = 0; c < MAYO_KO; c++) {
                uint8_t tmp = nibble_get(A, pr * MAYO_KO + c);
                nibble_set(A, pr * MAYO_KO + c,
                           nibble_get(A, next * MAYO_KO + c));
                nibble_set(A, next * MAYO_KO + c, tmp);
            }
            uint8_t tmp = nibble_get(aug, pr);
            nibble_set(aug, pr, nibble_get(aug, next));
            nibble_set(aug, next, tmp);
        }

        /* Scale pivot row so leading entry = 1 */
        uint8_t piv = nibble_get(A, pr * MAYO_KO + pc);
        uint8_t inv = gf16_inv(piv);
        for (c = pc; c < MAYO_KO; c++) {
            nibble_set(A, pr * MAYO_KO + c,
                       gf16_mul(nibble_get(A, pr * MAYO_KO + c), inv));
        }
        nibble_set(aug, pr, gf16_mul(nibble_get(aug, pr), inv));

        /* Eliminate all other rows in column pc */
        for (i = 0; i < MAYO_M; i++) {
            if (i == pr) continue;
            uint8_t factor = nibble_get(A, i * MAYO_KO + pc);
            if (factor == 0) continue;
            for (c = pc; c < MAYO_KO; c++) {
                nibble_add(A, i * MAYO_KO + c,
                           gf16_mul(factor, nibble_get(A, pr * MAYO_KO + c)));
            }
            nibble_add(aug, i, gf16_mul(factor, nibble_get(aug, pr)));
        }

        pr++; pc++;
    }
    return pr;
}

/*
 * SampleSolution: given system A*x = y and randomness r,
 * find x = r + particular_solution.
 * x_out: ko nibbles.  Returns 0 on success, -1 if rank < m.
 */
static int sample_solution(uint8_t *x_out,
                            const uint8_t *r_nibbles,
                            uint8_t *A,   /* modified in-place */
                            uint8_t *y)   /* modified in-place */
{
    int col, eq;

    /* x ← r */
    memcpy(x_out, r_nibbles, (MAYO_KO + 1) / 2);

    /* y ← y - A*r */
    for (eq = 0; eq < MAYO_M; eq++) {
        uint8_t t = 0;
        for (col = 0; col < MAYO_KO; col++)
            t ^= gf16_mul(nibble_get(A, eq * MAYO_KO + col),
                          nibble_get(r_nibbles, col));
        nibble_add(y, eq, t);
    }

    /* Row-reduce (A | y) */
    int rank = gauss_elim(A, y);
    if (rank < MAYO_M) return -1;

    /* Back-substitute: for each leading-1 row, read off free variable */
    /* After full RREF the pivot columns hold the solution directly    */
    for (eq = 0; eq < MAYO_M; eq++) {
        /* find pivot column of row eq */
        for (col = 0; col < MAYO_KO; col++) {
            if (nibble_get(A, eq * MAYO_KO + col) == 1) {
                /* check it's really a pivot (all others in col are 0) */
                int is_pivot = 1;
                int i;
                for (i = 0; i < MAYO_M; i++) {
                    if (i != eq && nibble_get(A, i * MAYO_KO + col) != 0) {
                        is_pivot = 0; break;
                    }
                }
                if (is_pivot) {
                    nibble_add(x_out, col, nibble_get(y, eq));
                    break;
                }
            }
        }
    }

    return 0;
}

/* ================================================================== */
/*  mayo_sign()                                                         */
/* ================================================================== */

int mayo_sign(const uint8_t *msg, uint8_t msg_len,
              uint8_t sig[MAYO_SIG_B])
{
    const uint8_t *seedsk = g_mayo_esk + MAYO_ESK_SEEDSK_OFF;
    const uint8_t *L      = g_mayo_esk + MAYO_ESK_L_OFF;
    const uint8_t *O      = g_mayo_esk + MAYO_ESK_O_OFF;

    /* Buffers on stack — sized for MAYO-micro */
    uint8_t M_digest[MAYO_DIGEST_B];
    uint8_t salt[MAYO_SALT_B];
    uint8_t t[MAYO_M / 2];           /* target t in F16^m,  8 bytes */
    uint8_t y[MAYO_M / 2];           /* running y = t - vinegar sum */

    /* V buffer: k vinegar vectors + randomness r (nibble-packed) */
    uint8_t V_buf[MAYO_K * MAYO_V_B + (MAYO_KO + 1) / 2]; /* 50 B */
    uint8_t *r_nibbles = V_buf + MAYO_K * MAYO_V_B;        /* last 10 B */

    /* u_all[ell]: vinegar-vinegar contributions, one per pair */
    uint8_t u_all[MAYO_NPAIRS][MAYO_M / 2]; /* 15 * 8 = 120 B */

    uint8_t bs8[8];
    uint8_t decoded[16];

    int i, j, d, a, eq, ell, ctr;

    /* -------------------------------------------------------------- */
    /* 1. Hash message                                                  */
    /* -------------------------------------------------------------- */
    shake256_multi(msg, msg_len,
                   NULL, 0, NULL, 0, NULL, 0,
                   M_digest, MAYO_DIGEST_B);

    /* -------------------------------------------------------------- */
    /* 2. Derive salt                                                   */
    /* -------------------------------------------------------------- */
    {
        static const uint8_t zeros[MAYO_SKSEED_B]; /* R = 0^{sk_seed_b} */
        shake256_multi(M_digest, MAYO_DIGEST_B,
                       zeros,    MAYO_SKSEED_B,
                       seedsk,   MAYO_SKSEED_B,
                       NULL, 0,
                       salt, MAYO_SALT_B);
    }

    /* -------------------------------------------------------------- */
    /* 3. Derive target t                                               */
    /* -------------------------------------------------------------- */
    shake256_multi(M_digest, MAYO_DIGEST_B,
                   salt,     MAYO_SALT_B,
                   NULL, 0, NULL, 0,
                   t, (MAYO_M + 1) / 2);

    /* -------------------------------------------------------------- */
    /* Signing loop (ctr = 0..255)                                     */
    /* -------------------------------------------------------------- */
    for (ctr = 0; ctr <= 255; ctr++) {
        uint8_t ctr_byte = (uint8_t)ctr;

        /* ---------------------------------------------------------- */
        /* 4. Derive vinegar vectors and randomness r                  */
        /* ---------------------------------------------------------- */
        shake256_multi(M_digest, MAYO_DIGEST_B,
                       salt,     MAYO_SALT_B,
                       seedsk,   MAYO_SKSEED_B,
                       &ctr_byte, 1,
                       V_buf, sizeof(V_buf));

        /* Decode nibble-packed vi vectors (already nibble-packed)     */
        /* V_buf[i*V_B .. (i+1)*V_B - 1] = nibble-packed vi           */

        /* ---------------------------------------------------------- */
        /* 5. Compute all Mi  (from L and vi)                         */
        /* ---------------------------------------------------------- */
        for (i = 0; i < MAYO_K; i++) {
            compute_Mi(g_Mi[i],
                       V_buf + i * MAYO_V_B,
                       L);
        }

        /* ---------------------------------------------------------- */
        /* 6. Single-pass P1 stream: compute u_all[ell] for all pairs */
        /* ---------------------------------------------------------- */
        memset(u_all, 0, sizeof(u_all));

        /* Re-init SHAKE256 with seedpk for P1 stream */
        shake256_init(&g_shake);
        shake256_absorb(&g_shake, g_mayo_esk + MAYO_ESK_SEEDPK_OFF, MAYO_PKSEED_B);
        shake256_finalize(&g_shake);

        {
            int r_idx, s_idx;
            for (r_idx = 0; r_idx < MAYO_V; r_idx++) {
                for (s_idx = r_idx; s_idx < MAYO_V; s_idx++) {
                    shake256_squeeze(&g_shake, bs8, 8);

                    /* Skip diagonal (cancelled in P1+P1^T anyway) */
                    if (r_idx == s_idx) continue;

                    decode_bs8(bs8, decoded); /* decoded[a] = P1_a[r,s] */

                    ell = 0;
                    for (i = 0; i < MAYO_K; i++) {
                        for (j = MAYO_K - 1; j >= i; j--) {
                            /* coeff = vi[r]*vj[s] + vj[r]*vi[s]  */
                            uint8_t vir = nibble_get(V_buf + i * MAYO_V_B, r_idx);
                            uint8_t vis = nibble_get(V_buf + i * MAYO_V_B, s_idx);
                            uint8_t vjr = nibble_get(V_buf + j * MAYO_V_B, r_idx);
                            uint8_t vjs = nibble_get(V_buf + j * MAYO_V_B, s_idx);
                            uint8_t coeff;
                            if (i == j) {
                                coeff = gf16_mul(vir, vis); /* vi[r]*vi[s] */
                            } else {
                                coeff = gf16_mul(vir, vjs) ^ gf16_mul(vjr, vis);
                            }
                            if (coeff != 0) {
                                for (a = 0; a < MAYO_M; a++) {
                                    nibble_add(u_all[ell], a,
                                               gf16_mul(coeff, decoded[a]));
                                }
                            }
                            ell++;
                        }
                    }
                }
            }
        }
        /* Consume the rest of P1 stream (diagonal positions) without
         * using them — keeps AES counter in sync if needed.
         * (For diagonal r=s we already called aes_ctr_read8 above.)  */

        /* ---------------------------------------------------------- */
        /* 7. Build A and y                                            */
        /* ---------------------------------------------------------- */
        memset(g_A, 0, sizeof(g_A));
        memcpy(y, t, sizeof(t));

        ell = 0;
        for (i = 0; i < MAYO_K; i++) {
            for (j = MAYO_K - 1; j >= i; j--) {
                /* y -= E^ell * u_all[ell] */
                subtract_El_u(y, u_all[ell], ell);

                /* A[:,i*O:(i+1)*O] += E^ell * Mj */
                add_El_M_to_A(g_A, g_Mi[j], i, ell);

                if (i != j) {
                    /* A[:,j*O:(j+1)*O] += E^ell * Mi */
                    add_El_M_to_A(g_A, g_Mi[i], j, ell);
                }
                ell++;
            }
        }

        /* ---------------------------------------------------------- */
        /* 8. Solve: A * x = y   (with randomisation from r)          */
        /* ---------------------------------------------------------- */
        {
            /* Work on a copy of A and y since gauss_elim is destructive */
            static uint8_t A_copy[MAYO_M * MAYO_KO / 2];
            static uint8_t y_copy[MAYO_M / 2];
            uint8_t x[( MAYO_KO + 1) / 2];

            memcpy(A_copy, g_A, sizeof(g_A));
            memcpy(y_copy, y,   sizeof(y));

            if (sample_solution(x, r_nibbles, A_copy, y_copy) == 0) {
                /* -------------------------------------------------- */
                /* 9. Build final signature vectors s_i = vi + O*xi   */
                /* -------------------------------------------------- */
                memset(sig, 0, MAYO_SIG_B);

                for (i = 0; i < MAYO_K; i++) {
                    /* oil vars for this block: x[i*O .. (i+1)*O - 1] */
                    for (eq = 0; eq < MAYO_N; eq++) {
                        uint8_t s_eq;
                        if (eq < MAYO_V) {
                            /* vinegar part: vi[eq] + (O*xi)[eq] */
                            s_eq = nibble_get(V_buf + i * MAYO_V_B, eq);
                            for (d = 0; d < MAYO_O; d++) {
                                uint8_t xi_d = nibble_get(x, i * MAYO_O + d);
                                s_eq ^= gf16_mul(nibble_get(O, eq * MAYO_O + d),
                                                 xi_d);
                            }
                        } else {
                            /* oil part: xi[eq - V] */
                            s_eq = nibble_get(x, i * MAYO_O + (eq - MAYO_V));
                        }
                        /* Write s_eq into sig at nibble index i*N + eq */
                        nibble_add(sig, i * MAYO_N + eq, s_eq);
                    }
                }

                /* Append salt */
                memcpy(sig + (MAYO_K * MAYO_N + 1) / 2, salt, MAYO_SALT_B);
                return 0;
            }
        }
    }

    return -1; /* all 256 attempts failed */
}
