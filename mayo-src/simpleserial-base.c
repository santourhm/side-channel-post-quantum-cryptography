#include "hal.h"
#include <stdint.h>
#include <string.h>
#include "simpleserial.h"
#include "mayo_params.h"
#include "mayo_core.h"

/*
 * SimpleSerial command map:
 *
 *   'k'  16 bytes  seedsk  → expand secret key into g_mayo_esk (no trigger)
 *   'p'  16 bytes  message → trigger_high, mayo_sign(), trigger_low, send sig
 *   'x'   0 bytes          → soft reset (zero ESK)
 *
 * Signature response ('r'): MAYO_SIG_B = 66 bytes.
 *
 * For power / EM capture in ChipWhisperer:
 *   - trigger rises at the start of mayo_sign() (after hashing the message)
 *   - trigger falls when the signing loop exits
 *   The entire quadratic-form + linear-solve core is inside the trigger window.
 */

static uint8_t sig_buf[MAYO_SIG_B];
static uint8_t esk_loaded = 0;

/* ------------------------------------------------------------------ */

uint8_t cmd_load_key(uint8_t *k, uint8_t len)
{
    (void)len;
    mayo_expand_sk(k);    /* derive O, L and store in g_mayo_esk */
    esk_loaded = 1;
    return 0x01;
}

uint8_t cmd_sign(uint8_t *msg, uint8_t len)
{
    if (!esk_loaded) {
        /* No key yet — echo the message back as a no-op */
        simpleserial_put('r', len, msg);
        return 0x01;
    }

    trigger_high();
    int ret = mayo_sign(msg, len, sig_buf);
    trigger_low();

    if (ret == 0) {
        simpleserial_put('r', MAYO_SIG_B, sig_buf);
    } else {
        /* Sign failed (extremely unlikely with these parameters) */
        simpleserial_put('e', 1, (uint8_t *)"\xFF");
    }
    return 0x00;
}

uint8_t cmd_reset(uint8_t *x, uint8_t len)
{
    (void)x; (void)len;
    memset(g_mayo_esk, 0, sizeof(g_mayo_esk));
    esk_loaded = 0;
    return 0x00;
}

/* ------------------------------------------------------------------ */

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    simpleserial_init();
    simpleserial_addcmd('k', MAYO_CSK_B,  cmd_load_key);
    simpleserial_addcmd('p', MAYO_DIGEST_B, cmd_sign);
    simpleserial_addcmd('x', 0,           cmd_reset);

    while (1)
        simpleserial_get();
}
