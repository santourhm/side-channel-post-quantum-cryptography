#ifndef MAYO_CORE_H
#define MAYO_CORE_H

#include <stdint.h>
#include "mayo_params.h"

/*
 * Device expanded secret key: seedsk | seedpk | O | L
 * Populated once by mayo_expand_sk(); re-used for every signing call.
 */
extern uint8_t g_mayo_esk[MAYO_ESK_B];

/*
 * Expand the 16-byte compact secret key (seedsk) into the device ESK.
 * This streams P1+P2 through AES-128-CTR to compute L = (P1+P1^T)*O + P2.
 * Call once after receiving the 'k' command.
 */
void mayo_expand_sk(const uint8_t seedsk[MAYO_SKSEED_B]);

/*
 * Produce a MAYO signature for the given message.
 * esk must have been populated by mayo_expand_sk().
 * sig must point to a buffer of at least MAYO_SIG_B bytes.
 * Returns 0 on success, -1 on failure (>256 ctr attempts exhausted).
 */
int mayo_sign(const uint8_t *msg, uint8_t msg_len,
              uint8_t sig[MAYO_SIG_B]);

#endif /* MAYO_CORE_H */
