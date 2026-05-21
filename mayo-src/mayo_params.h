#ifndef MAYO_PARAMS_H
#define MAYO_PARAMS_H

/*
 * MAYO-micro: toy parameter set for STM32F030F4P6 SCA study
 * n=20, m=16, o=4, k=5, q=16
 *
 * NOT cryptographically secure — hardware assessment use only.
 * ko=20 > m=16 ensures the signing system is solvable.
 */

#define MAYO_N          20
#define MAYO_M          16
#define MAYO_O          4
#define MAYO_K          5
#define MAYO_Q          16

#define MAYO_V          (MAYO_N - MAYO_O)           /* 16 vinegar variables */
#define MAYO_KO         (MAYO_K * MAYO_O)           /* 20 whipped oil vars  */
#define MAYO_NPAIRS     ((MAYO_K * (MAYO_K + 1)) / 2) /* 15 (i,j) pairs     */

/* Seed / hash sizes in bytes */
#define MAYO_SKSEED_B   16
#define MAYO_PKSEED_B   16
#define MAYO_SALT_B     16
#define MAYO_DIGEST_B   16

/*
 * Matrix sizes (nibble-packed bytes, 2 GF16 elems per byte).
 * Bitsliced encoding for m=16: m/2 = 8 bytes per "position".
 */
#define MAYO_V_B        ((MAYO_V + 1) / 2)                      /*   8 */
#define MAYO_O_B        ((MAYO_V * MAYO_O + 1) / 2)             /*  32 */
#define MAYO_P1_B       (MAYO_M * MAYO_V * (MAYO_V + 1) / 4)   /* 1088 */
#define MAYO_P2_B       (MAYO_M * MAYO_V * MAYO_O / 2)          /*  512 */
#define MAYO_P3_B       (MAYO_M * MAYO_O * (MAYO_O + 1) / 4)   /*   80 */
#define MAYO_L_B        MAYO_P2_B                               /*  512 */

/* Compact key sizes */
#define MAYO_CSK_B      MAYO_SKSEED_B                           /*  16 */
#define MAYO_CPK_B      (MAYO_PKSEED_B + MAYO_P3_B)            /*  96 */

/* Signature: ceil(n*k/2) + salt = 50 + 16 */
#define MAYO_SIG_B      ((MAYO_N * MAYO_K + 1) / 2 + MAYO_SALT_B) /* 66 */

/*
 * Device expanded secret key stored in RAM:
 *   seedsk (16) | seedpk (16) | O (32) | L (512) = 576 bytes
 */
#define MAYO_ESK_B  (MAYO_SKSEED_B + MAYO_PKSEED_B + MAYO_O_B + MAYO_L_B)

/* Offsets inside device ESK buffer */
#define MAYO_ESK_SEEDSK_OFF  0
#define MAYO_ESK_SEEDPK_OFF  MAYO_SKSEED_B
#define MAYO_ESK_O_OFF       (MAYO_SKSEED_B + MAYO_PKSEED_B)
#define MAYO_ESK_L_OFF       (MAYO_SKSEED_B + MAYO_PKSEED_B + MAYO_O_B)

/*
 * L is stored as a 3-D nibble-packed array:
 *   L[r][d][a]  r in [V], d in [O], a in [M]
 *   Flat nibble index: (r*O + d)*M + a
 *   Byte: that / 2, nibble: that % 2
 */

#endif /* MAYO_PARAMS_H */
