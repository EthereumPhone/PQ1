/*--------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                                  */
/*                                                                          */
/* NXP Confidential. This software is owned or controlled by NXP and may    */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms. If you do not agree to be bound by the applicable license */
/* terms, then you may not retain, install, activate or otherwise use the   */
/* software.                                                                */
/*--------------------------------------------------------------------------*/

/** @file  gcm_alt.c
 *  @brief alternative implementation of AES GCM with ELS IP
 */

#include "gcm_alt.h"

#if defined(MBEDTLS_MCUX_ELS_AES_GCM)

#include "mbedtls/aes.h"
#include "mbedtls/error.h"
#include <platform_hw_ip.h>
#include "mbedtls/platform.h"
#include <mcuxClMemory.h>
#include <mcuxClEls.h>

#include <string.h>

#if !defined(MBEDTLS_AES_GCM_SETKEY_ALT) || !defined(MBEDTLS_AES_GCM_STARTS_ALT) || \
    !defined(MBEDTLS_AES_GCM_UPDATE_ALT) || !defined(MBEDTLS_AES_GCM_FINISH_ALT) || !defined(MBEDTLS_AES_CTX_ALT)
#error the 5 alternative implementations shall be enabled together
#elif defined(MBEDTLS_AES_GCM_SETKEY_ALT) && defined(MBEDTLS_AES_GCM_STARTS_ALT) && \
    defined(MBEDTLS_AES_GCM_UPDATE_ALT) && defined(MBEDTLS_AES_GCM_FINISH_ALT) && defined(MBEDTLS_AES_CTX_ALT)

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#include "els_pkc_mbedtls.h"
#endif

int mbedtls_aes_gcm_setkey_alt(mbedtls_gcm_context *ctx,
                               mbedtls_cipher_id_t cipher,
                               const unsigned char *key,
                               unsigned int keybits)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_cipher_info_t *cipher_info;

    cipher_info = mbedtls_cipher_info_from_values(cipher, (int)keybits, MBEDTLS_MODE_ECB);
    if (cipher_info == NULL)
    {
        return (MBEDTLS_ERR_GCM_BAD_INPUT);
    }

    if (cipher_info->block_size != 16u)
    {
        return (MBEDTLS_ERR_GCM_BAD_INPUT);
    }

    mbedtls_cipher_free(&ctx->cipher_ctx);

    if ((ret = mbedtls_cipher_setup(&ctx->cipher_ctx, cipher_info)) != 0)
    {
        return (ret);
    }

    if ((ret = mbedtls_cipher_setkey(&ctx->cipher_ctx, key, (int)keybits, MBEDTLS_ENCRYPT)) != 0)
    {
        return (ret);
    }
    // Generation of multiplicaton table is not needed for AES

    return (0);
}

/*
 * GCM key schedule , alternative implementation
 */
int mbedtls_gcm_setkey(mbedtls_gcm_context *ctx,
                       mbedtls_cipher_id_t cipher,
                       const unsigned char *key,
                       unsigned int keybits)
{
    return mbedtls_aes_gcm_setkey_alt(ctx, cipher, key, keybits);
}

int mbedtls_aes_gcm_starts_alt(mbedtls_gcm_context *ctx,
                               int mode,
                               const unsigned char *iv,
                               size_t iv_len,
                               const unsigned char *add,
                               size_t add_len)
{

#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    int return_code = 0;
    ctx->mode       = mode;
    ctx->len        = 0;
    ctx->add_len    = add_len;

    (void)memset((void *)ctx->HL, 0x00, MCUXCLELS_AEAD_CONTEXT_SIZE);

    mcuxClEls_AeadOption_t options = {0};
    options.bits.extkey            = MCUXCLELS_AEAD_EXTERN_KEY;
    options.bits.dcrpt             = (mode == MBEDTLS_GCM_DECRYPT) ? MCUXCLELS_AEAD_DECRYPT : MCUXCLELS_AEAD_ENCRYPT;

    mbedtls_aes_context *aes_ctx = (mbedtls_aes_context *)ctx->cipher_ctx.cipher_ctx;
    uint8_t *pKey                = (uint8_t *)aes_ctx->pKey;
    size_t key_length            = aes_ctx->keyLength;

    /* Initialize hardware accelerator */
    int ret_hw_init = mbedtls_hw_init();
    if (0 != ret_hw_init)
    {
        return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    /* process the IV */
    if (iv_len == 12u)
    {
        /* pad the IV according to NIST SP 800-38D */
        (void)memset((void *)ctx->HH, 0x00, 16);
        (void)memcpy((void *)ctx->HH, (void const *)iv, iv_len);
        ((uint8_t *)ctx->HH)[15] = 0x01u;
        /* call mcuxClEls_Aead_Init_Async */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(
            resultInit, tokenInit,
            mcuxClEls_Aead_Init_Async(options, 0, /* keyIdx is ignored */
                                      pKey, key_length, (uint8_t *)ctx->HH, 16u, (uint8_t *)ctx->HL));

        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_Init_Async) != tokenInit) ||
            (MCUXCLELS_STATUS_OK_WAIT != resultInit))
        {
            return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
            goto cleanup;
        }

        /* wait for mcuxClEls_Aead_Init_Async. */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retWaitInit, tokenWaitInit,
                                             mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenWaitInit) ||
            (MCUXCLELS_STATUS_OK != retWaitInit))
        {
            return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
            goto cleanup;
        }
    }
    else
    {
        size_t nr_full_iv_blocks = iv_len / 16u;
        size_t len_last_iv_block = iv_len - (nr_full_iv_blocks * 16u);
        if (len_last_iv_block == 0u)
        {
            // last block of IV must contain more than 0 bytes to ensure proper ELS init
            len_last_iv_block = 16u;
            nr_full_iv_blocks -= 1u;
        }

        /* process the first part (full blocks) of the IV */
        if (nr_full_iv_blocks > 0u)
        {
            options.bits.acpsie   = MCUXCLELS_AEAD_STATE_IN_DISABLE;
            options.bits.lastinit = MCUXCLELS_AEAD_LASTINIT_FALSE;
            /* call mcuxClEls_Aead_PartialInit_Async */
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(
                resultPartialInitFull, tokenPartialInitFull,
                mcuxClEls_Aead_PartialInit_Async(options, 0, /* keyIdx is ignored */
                                                 pKey, key_length, (uint8_t const *)iv, (nr_full_iv_blocks * 16u),
                                                 (uint8_t *)ctx->HL));

            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_PartialInit_Async) != tokenPartialInitFull) ||
                (MCUXCLELS_STATUS_OK_WAIT != resultPartialInitFull))
            {
                return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
                goto cleanup;
            }

            /* wait for mcuxClEls_Aead_PartialInit_Async. */
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retWaitPartialInitFull, tokenWaitPartialInitFull,
                                                 mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenWaitPartialInitFull) ||
                (MCUXCLELS_STATUS_OK != retWaitPartialInitFull))
            {
                return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
                goto cleanup;
            }
            iv += (nr_full_iv_blocks * 16u);
        }

        /* process the second part (remaining bytes, between 1 and 16) of the IV */
        /* pad the IV according to NIST SP 800-38D */
        (void)memset((void *)ctx->HH, 0x00, 32);
        (void)memcpy((void *)ctx->HH, (void const *)iv, len_last_iv_block);
        size_t iv_len_bits = iv_len * 8u;
        mcuxClMemory_StoreBigEndian32(((uint8_t *)ctx->HH + 28), iv_len_bits);

        options.bits.acpsie = (nr_full_iv_blocks > 0u) ?
                                  MCUXCLELS_AEAD_STATE_IN_ENABLE /* second call to PartialInit */
                                  :
                                  MCUXCLELS_AEAD_STATE_IN_DISABLE; /* first call to PartialInit */
        options.bits.lastinit = MCUXCLELS_AEAD_LASTINIT_TRUE;
        /* call mcuxClEls_Aead_PartialInit_Async */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(
            resultPartialInitLast, tokenPartialInitLast,
            mcuxClEls_Aead_PartialInit_Async(options, 0, /* keyIdx is ignored */
                                             pKey, key_length, (uint8_t *)ctx->HH, 32u, (uint8_t *)ctx->HL));

        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_PartialInit_Async) != tokenPartialInitLast) ||
            (MCUXCLELS_STATUS_OK_WAIT != resultPartialInitLast))
        {
            return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
            goto cleanup;
        }

        /* wait for mcuxClEls_Aead_PartialInit_Async. */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retWaitPartialInitLast, tokenWaitPartialInitLast,
                                             mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenWaitPartialInitLast) ||
            (MCUXCLELS_STATUS_OK != retWaitPartialInitLast))
        {
            return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
            goto cleanup;
        }
    }

    /* process the authenticated data */
    size_t nr_full_add_blocks = add_len / 16u;
    size_t len_last_add_block = add_len - (nr_full_add_blocks * 16u);

    if (nr_full_add_blocks > 0u)
    {
        /* call mcuxClEls_Aead_UpdateAad_Async */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(
            resultUpdateFull, tokenUpdateFull,
            mcuxClEls_Aead_UpdateAad_Async(options, 0, /* keyIdx is ignored */
                                           pKey, key_length, (uint8_t const *)add, (nr_full_add_blocks * 16u),
                                           (uint8_t *)ctx->HL));

        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_UpdateAad_Async) != tokenUpdateFull) ||
            (MCUXCLELS_STATUS_OK_WAIT != resultUpdateFull))
        {
            return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
            goto cleanup;
        }

        /* wait for mcuxClEls_Aead_UpdateAad_Async. */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retWaitUpdateFull, tokenWaitUpdateFull,
                                             mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenWaitUpdateFull) ||
            (MCUXCLELS_STATUS_OK != retWaitUpdateFull))
        {
            return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
            goto cleanup;
        }
        add += (nr_full_add_blocks * 16u);
    }

    if (len_last_add_block > 0u)
    {
        /* pad the AAD according to NIST SP 800-38D */
        (void)memset((void *)ctx->HH, 0x00, 16);
        (void)memcpy((void *)ctx->HH, (void const *)add, len_last_add_block);
        /* call mcuxClEls_Aead_UpdateAad_Async */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(
            resultUpdateLast, tokenUpdateLast,
            mcuxClEls_Aead_UpdateAad_Async(options, 0, /* keyIdx is ignored */
                                           pKey, key_length, (uint8_t *)ctx->HH, 16u, (uint8_t *)ctx->HL));

        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_UpdateAad_Async) != tokenUpdateLast) ||
            (MCUXCLELS_STATUS_OK_WAIT != resultUpdateLast))
        {
            return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
            goto cleanup;
        }

        /* wait for mcuxClEls_Aead_UpdateAad_Async. */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retWaitUpdateLast, tokenWaitUpdateLast,
                                             mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenWaitUpdateLast) ||
            (MCUXCLELS_STATUS_OK != retWaitUpdateLast))
        {
            return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
            goto cleanup;
        }
    }

    return_code = 0;
    goto exit;

cleanup:
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

exit:
    return return_code;
}

int mbedtls_gcm_starts(mbedtls_gcm_context *ctx,
                       int mode,
                       const unsigned char *iv,
                       size_t iv_len,
                       const unsigned char *add,
                       size_t add_len)
{
    return mbedtls_aes_gcm_starts_alt(ctx, mode, iv, iv_len, add, add_len);
}

int mbedtls_aes_gcm_update_alt(mbedtls_gcm_context *ctx,
                               size_t length,
                               const unsigned char *input,
                               unsigned char *output)
{
    int return_code                                              = 0;
    unsigned char output_buffer[MCUXCLELS_CIPHER_BLOCK_SIZE_AES] = {0};

#if defined(MBEDTLS_THREADING_C)
    int ret                                                      = 0;
#endif

    ctx->len += length;

    mcuxClEls_AeadOption_t options = {0};
    options.bits.extkey            = MCUXCLELS_AEAD_EXTERN_KEY;
    options.bits.dcrpt = (ctx->mode == MBEDTLS_GCM_DECRYPT) ? MCUXCLELS_AEAD_DECRYPT : MCUXCLELS_AEAD_ENCRYPT;

    mbedtls_aes_context *aes_ctx = (mbedtls_aes_context *)ctx->cipher_ctx.cipher_ctx;
    uint8_t *pKey                = (uint8_t *)aes_ctx->pKey;
    size_t key_length            = aes_ctx->keyLength;

    /* Initialize hardware accelerator */
    int ret_hw_init = mbedtls_hw_init();
    if (0 != ret_hw_init)
    {
        return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    size_t nr_full_msg_blocks = length / 16u;
    size_t len_last_msg_block = length - (nr_full_msg_blocks * 16u);

    if (nr_full_msg_blocks > 0u)
    {
        /* call mcuxClEls_Aead_UpdateData_Async */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(
            resultUpdateFull, tokenUpdateFull,
            mcuxClEls_Aead_UpdateData_Async(options, 0, /* keyIdx is ignored */
                                            pKey, key_length, (uint8_t const *)input, (nr_full_msg_blocks * 16u),
                                            (uint8_t *)output, (uint8_t *)ctx->HL));

        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_UpdateData_Async) != tokenUpdateFull) ||
            (MCUXCLELS_STATUS_OK_WAIT != resultUpdateFull))
        {
            return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
            goto cleanup;
        }

        /* wait for mcuxClEls_Aead_UpdateData_Async. */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retWaitUpdateFull, tokenWaitUpdateFull,
                                             mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenWaitUpdateFull) ||
            (MCUXCLELS_STATUS_OK != retWaitUpdateFull))
        {
            return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
            goto cleanup;
        }

        input += (nr_full_msg_blocks * 16u);
        output += (nr_full_msg_blocks * 16u);
    }

    if (len_last_msg_block > 0u)
    {
        // pad the input msg according to NIST SP 800-38D
        (void)memset((void *)ctx->HH, 0x00, 16);
        (void)memcpy((void *)ctx->HH, (void const *)input, len_last_msg_block);

        options.bits.msgendw = len_last_msg_block;

        /* call mcuxClEls_Aead_UpdateData_Async */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(
            resultUpdateLast, tokenUpdateLast,
            mcuxClEls_Aead_UpdateData_Async(options, 0, /* keyIdx is ignored */
                                            pKey, key_length, (uint8_t *)ctx->HH, 16u, (uint8_t *)output_buffer,
                                            (uint8_t *)ctx->HL));

        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_UpdateData_Async) != tokenUpdateLast) ||
            (MCUXCLELS_STATUS_OK_WAIT != resultUpdateLast))
        {
            return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
            goto cleanup;
        }

        /* wait for mcuxClEls_Aead_UpdateData_Async. */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retWaitUpdateLast, tokenWaitUpdateLast,
                                             mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenWaitUpdateLast) ||
            (MCUXCLELS_STATUS_OK != retWaitUpdateLast))
        {
            return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
            goto cleanup;
        }
    }

    (void)memcpy((void *)output, (void const *)output_buffer, len_last_msg_block);
    return_code = 0;
    goto exit;

cleanup:
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

exit:
    return return_code;
}

int mbedtls_gcm_update(mbedtls_gcm_context *ctx, size_t length, const unsigned char *input, unsigned char *output)
{
    return mbedtls_aes_gcm_update_alt(ctx, length, input, output);
}

int mbedtls_aes_gcm_finish_alt(mbedtls_gcm_context *ctx, unsigned char *tag, size_t tag_len)
{
    int return_code                = 0;
    mcuxClEls_AeadOption_t options = {0};

#if defined(MBEDTLS_THREADING_C)
    int ret                        = 0;
#endif

    options.bits.extkey  = MCUXCLELS_AEAD_EXTERN_KEY;
    options.bits.dcrpt   = (ctx->mode == MBEDTLS_GCM_DECRYPT) ? MCUXCLELS_AEAD_DECRYPT : MCUXCLELS_AEAD_ENCRYPT;
    options.bits.msgendw = (uint32_t)ctx->len % 16u;

    mbedtls_aes_context *aes_ctx = (mbedtls_aes_context *)ctx->cipher_ctx.cipher_ctx;
    uint8_t *pKey                = (uint8_t *)aes_ctx->pKey;
    size_t key_length            = aes_ctx->keyLength;

    /* Initialize hardware accelerator */
    int ret_hw_init = mbedtls_hw_init();
    if (0 != ret_hw_init)
    {
        return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    /* Intermediate buffer for saving the tag if tag_len < 16 */
    uint8_t pTag[16u];

    /* call mcuxClEls_Aead_Finalize_Async */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(
        resultFinalize, tokenFinalize,
        mcuxClEls_Aead_Finalize_Async(options, 0, /* keyIdx is ignored */
                                      pKey, key_length, (size_t)ctx->add_len, (size_t)ctx->len,
                                      tag_len < 16u ? (uint8_t *)pTag : (uint8_t *)tag, (uint8_t *)ctx->HL));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_Finalize_Async) != tokenFinalize) ||
        (MCUXCLELS_STATUS_OK_WAIT != resultFinalize))
    {
        return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    /* wait for mcuxClEls_Aead_Finalize_Async. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retWaitFinalize, tokenWaitFinalize,
                                         mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenWaitFinalize) ||
        (MCUXCLELS_STATUS_OK != retWaitFinalize))
    {
        return_code = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    /* Copy result from pTag to tag if tag_len < 16 */
    if (tag_len < 16u)
    {
        (void)memcpy((void *)tag, (void const *)pTag, tag_len);
    }

    return_code = 0;
cleanup:
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    return return_code;
}

int mbedtls_gcm_finish(mbedtls_gcm_context *ctx, unsigned char *tag, size_t tag_len)
{
    return mbedtls_aes_gcm_finish_alt(ctx, tag, tag_len);
}

#endif /* MBEDTLS_AES_GCM_ALT && MBEDTLS_AES_CTX_ALT */

#endif /* defined(MBEDTLS_MCUX_ELS_AES_GCM) */
