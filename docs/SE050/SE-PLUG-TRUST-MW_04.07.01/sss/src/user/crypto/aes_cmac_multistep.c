/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_USER

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "aes.h"
#include "aes_cmac.h"
#include "aes_cmac_multistep.h"

static void pad_data(uint8_t *block, int len);

void aes_cmac_update(
    aes_ctx_t *context, uint8_t *input, uint8_t *IV, unsigned long length, uint8_t *key, uint8_t *mac_value)
{
    uint8_t previous_block_ciphertext[AES_BLOCKSIZE] = {0};
    uint8_t temp[AES_BLOCKSIZE];
    memcpy(previous_block_ciphertext, IV, AES_BLOCKSIZE);
    block_xor_triple(input, previous_block_ciphertext, temp);
    AES_user_encrypt(context, temp, mac_value);
}

void aes_cmac_finish(
    aes_ctx_t *context, uint8_t *input, uint8_t *IV, unsigned long length, uint8_t *key, uint8_t *mac_value)
{
    uint8_t subkey_1[AES_BLOCKSIZE];
    uint8_t subkey_2[AES_BLOCKSIZE];
    uint8_t previous_block_ciphertext[AES_BLOCKSIZE] = {0};
    uint8_t temp[AES_BLOCKSIZE];
    uint8_t flagblockAligned = 0;

    memcpy(previous_block_ciphertext, IV, AES_BLOCKSIZE);

    gen_subkey(context, key, subkey_1, subkey_2);

    if ((length % AES_BLOCKSIZE) == 0) {
        flagblockAligned = 1;
    }
    else {
        flagblockAligned = 0;
    }
    memcpy(temp, input, length);

    if (flagblockAligned == 0) {
        pad_data(temp, length);
        block_xor_triple(temp, subkey_2, temp);
    }
    else {
        block_xor_triple(temp, subkey_1, temp);
    }

    block_xor_triple(temp, previous_block_ciphertext, temp);
    AES_user_encrypt(context, temp, mac_value);
}

static void pad_data(uint8_t *block, int len)
{
    uint16_t bytesToPad = 0;

    block[len] = 0x80;
    len += 1;
    bytesToPad = (AES_BLOCKSIZE - (len % AES_BLOCKSIZE)) % AES_BLOCKSIZE;

    while (bytesToPad > 0) {
        block[len] = 0x00;
        len += 1;
        bytesToPad--;
    }
    return;
}
#endif //#if SSS_HAVE_HOSTCRYPTO_USER
