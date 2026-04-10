/*--------------------------------------------------------------------------*/
/* Copyright 2021 NXP                                                       */
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

/** @file  aes_alt.c
 *  @brief alternative AES implementation with CSS IP
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdint.h>
#include <mcuxClCss.h>
#include <mcuxClMemory.h>
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <platform_hw_ip.h>
#include <mbedtls/aes.h>
#include <aes_alt.h>


#if defined(MBEDTLS_AES_SETKEY_ENC_ALT) && defined(MBEDTLS_AES_SETKEY_DEC_ALT) && \
    defined(MBEDTLS_AES_ENCRYPT_ALT) && defined(MBEDTLS_AES_DECRYPT_ALT) && \
    defined(MBEDTLS_AES_CTX_ALT)
#define MBEDTLS_AES_CORE_ALT
#elif defined(MBEDTLS_AES_SETKEY_ENC_ALT) || defined(MBEDTLS_AES_SETKEY_DEC_ALT) || \
    defined(MBEDTLS_AES_ENCRYPT_ALT) || defined(MBEDTLS_AES_DECRYPT_ALT) || \
    defined(MBEDTLS_AES_CTX_ALT)
#error \
    the 5 alternative implementations (setkey_enc/dec, en/decrypt and ctx) shall be enabled together.
#endif \
    /* MBEDTLS_AES_SETKEY_ENC_ALT && MBEDTLS_AES_SETKEY_DEC_ALT && MBEDTLS_AES_ENCRYPT_ALT && MBEDTLS_AES_DECRYPT_ALT && MBEDTLS_AES_CTX_ALT */


#if defined(MBEDTLS_AES_CORE_ALT)
/*
 * AES key schedule, alternative implementation
 */
static int mbedtls_aes_setkey_alt(mbedtls_aes_context *ctx,
                                  const unsigned char *key,
                                  unsigned int keybits)
{
    int retCode = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((NULL == ctx) || (NULL == key)) {
        retCode = MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    } else if (((MCUXCLCSS_CIPHER_KEY_SIZE_AES_128 * 8u) != keybits)
               && ((MCUXCLCSS_CIPHER_KEY_SIZE_AES_192 * 8u) != keybits)
               && ((MCUXCLCSS_CIPHER_KEY_SIZE_AES_256 * 8u) != keybits)) {
        retCode = MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    } else {
        uint32_t keyByteLen = (uint32_t) keybits / 8u;
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retMemCpy, tokenMemCpy,
                                             mcuxClMemory_copy((uint8_t *) ctx->pKey, key,
                                                               keyByteLen, keyByteLen));

        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) == tokenMemCpy)
            && (0u == retMemCpy)) {
            ctx->keyLength = keyByteLen;
            retCode = 0;
        }
    }

    return retCode;
}


/*
 * AES key schedule (encryption), alternative implementation
 */
int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx,
                           const unsigned char *key,
                           unsigned int keybits)
{
    return mbedtls_aes_setkey_alt(ctx, key, keybits);
}


/*
 * AES key schedule (decryption), alternative implementation
 */
int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx,
                           const unsigned char *key,
                           unsigned int keybits)
{
    return mbedtls_aes_setkey_alt(ctx, key, keybits);
}


/*
 * AES-ECB block en/decryption with CSS
 */
static int mbedtls_internal_aes_css(mbedtls_aes_context *ctx,
                                    const unsigned char *pInput,
                                    unsigned char *pOutput,
                                    mcuxClCss_CipherOption_t cssCipherOption,
                                    unsigned char *pIv,
                                    size_t length)
{
    /* Call Css to process one block. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssCipherAsync, tokenCssCipherAsync,
                                         mcuxClCss_Cipher_Async(cssCipherOption,
                                                                0u, /* keyIdx is ignored. */
                                                                (const uint8_t *) ctx->pKey,
                                                                ctx->keyLength,
                                                                pInput,
                                                                length,
                                                                pIv,
                                                                pOutput));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cipher_Async) != tokenCssCipherAsync)
        || (MCUXCLCSS_STATUS_OK_WAIT != retCssCipherAsync)) {
        /* _Cipher_Async shall not return _SW_CANNOT_INTERRUPT after successfully returning from _WaitForOperation. */
        /* _Cipher_Async shall not return _SW_INVALID_PARAM if parameters are set properly. */
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    /* Wait for mcuxClCss_Cipher_Async. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssWaitCipher, tokenCssWaitCipher,
                                         mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != tokenCssWaitCipher) {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (MCUXCLCSS_STATUS_OK != retCssWaitCipher) {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    return 0;
}


/*
 * AES-ECB block encryption, alternative implementation
 */
int mbedtls_internal_aes_encrypt(mbedtls_aes_context *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16])
{
    mcuxClCss_CipherOption_t cipherOption = (mcuxClCss_CipherOption_t) {
        .bits.dcrpt  = MCUXCLCSS_CIPHER_ENCRYPT,
        .bits.cphmde = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_ECB,
        .bits.cphsoe = MCUXCLCSS_CIPHER_STATE_OUT_DISABLE,
        .bits.cphsie = MCUXCLCSS_CIPHER_STATE_IN_DISABLE,
        .bits.extkey = MCUXCLCSS_CIPHER_EXTERNAL_KEY
    };

    /* Initialize CSS */
    int ret_hw_init = mbedtls_hw_init();
    if (0 != ret_hw_init) {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    return mbedtls_internal_aes_css(ctx, input, output, cipherOption, NULL, 16u);
}


/*
 * AES-ECB block decryption, alternative implementation
 */
int mbedtls_internal_aes_decrypt(mbedtls_aes_context *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16])
{
    mcuxClCss_CipherOption_t cipherOption = (mcuxClCss_CipherOption_t) {
        .bits.dcrpt  = MCUXCLCSS_CIPHER_DECRYPT,
        .bits.cphmde = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_ECB,
        .bits.cphsoe = MCUXCLCSS_CIPHER_STATE_OUT_DISABLE,
        .bits.cphsie = MCUXCLCSS_CIPHER_STATE_IN_DISABLE,
        .bits.extkey = MCUXCLCSS_CIPHER_EXTERNAL_KEY
    };

    /* Initialize CSS */
    int ret_hw_init = mbedtls_hw_init();
    if (0 != ret_hw_init) {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    return mbedtls_internal_aes_css(ctx, input, output, cipherOption, NULL, 16u);
}


#if defined(MBEDTLS_CIPHER_MODE_CBC) && defined(MBEDTLS_AES_CBC_ALT)
/*
 * AES-CBC buffer encryption/decryption, alternative implementation
 */
int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx,
                          int mode,
                          size_t length,
                          unsigned char iv[16],
                          const unsigned char *input,
                          unsigned char *output)
{
    uint32_t temp[4];

    if ((NULL == ctx) || (NULL == iv) || (NULL == input) || (NULL == output)
        || ((MBEDTLS_AES_ENCRYPT != mode) && (MBEDTLS_AES_DECRYPT != mode))) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    } else if (0u != (length % 16u)) {
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    } else {
        const uint8_t *pNewIv;
        mcuxClCss_CipherOption_t cipherOption;
        if (MBEDTLS_AES_ENCRYPT == mode) {
            pNewIv = output;
            cipherOption = (mcuxClCss_CipherOption_t) {
                .bits.dcrpt = MCUXCLCSS_CIPHER_ENCRYPT,
                .bits.cphmde = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_CBC,
                .bits.extkey = MCUXCLCSS_CIPHER_EXTERNAL_KEY
            };
        } else {
            pNewIv = (uint8_t *) temp;
            cipherOption = (mcuxClCss_CipherOption_t) {
                .bits.dcrpt  = MCUXCLCSS_CIPHER_DECRYPT,
                .bits.cphmde = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_CBC,
                .bits.extkey = MCUXCLCSS_CIPHER_EXTERNAL_KEY
            };

            /* Backup input[] as the next IV (ps, input[] will be overwritten if result in-place). */
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retMemCpy0,
                                                 tokenMemCpy,
                                                 mcuxClMemory_copy((uint8_t *) temp, input, 16u,
                                                                   16u));
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) != tokenMemCpy)
                || (0u != retMemCpy0)) {
                return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
            }
        }

        /* Initialize CSS */
        int ret_hw_init = mbedtls_hw_init();
        if (0 != ret_hw_init) {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        int retCode = mbedtls_internal_aes_css(ctx, input, output, cipherOption, iv, length);
        if (0 != retCode) {
            return retCode;
        }

        /* Copy new IV to iv[]. */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retMemCpy1, tokenMemCpy,
                                             mcuxClMemory_copy(iv, pNewIv, 16u, 16u));
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) != tokenMemCpy)
            || (0u != retMemCpy1)) {
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        }
    }

    return 0;
}
#endif  /* MBEDTLS_CIPHER_MODE_CBC && MBEDTLS_AES_CBC_ALT */


#if defined(MBEDTLS_CIPHER_MODE_CTR) && defined(MBEDTLS_AES_CTR_ALT)
/*
 * AES-CTR buffer encryption/decryption, alternative implementation
 */
int mbedtls_aes_crypt_ctr(mbedtls_aes_context *ctx,
                          size_t length,
                          size_t *nc_off,
                          unsigned char nonce_counter[16],
                          unsigned char stream_block[16],
                          const unsigned char *input,
                          unsigned char *output)
{
    if ((NULL == ctx) || (NULL == nc_off)
        || (NULL == nonce_counter) || (NULL == stream_block)
        || (NULL == input) || (NULL == output)) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    } else if (15u < *nc_off) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    } else {
        uint32_t offset = *nc_off;
        uint32_t remainLength = length;
        const uint8_t *pInput = input;
        uint8_t *pOutput = output;

        /* En/decrypt by XORing with remaining byte(s) in stream_block[]. */
        while ((0u < remainLength) && (0u != (offset & 15u))) {
            *pOutput = *pInput ^ stream_block[offset];
            pInput++;
            pOutput++;
            remainLength--;
            offset++;
        }

        /* Here, offset = 0,    if starting with a new block (*nc_off = 0);   */
        /*       offset = 1~15, if there is unused byte(s) in stream_block[]; */
        /*       offset = 16,   if all bytes in stream_block[] are used.      */

        mcuxClCss_CipherOption_t cipherOption = (mcuxClCss_CipherOption_t) {
            .bits.dcrpt  = MCUXCLCSS_CIPHER_ENCRYPT,
            .bits.cphmde = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_CTR,
            .bits.cphsoe = MCUXCLCSS_CIPHER_STATE_OUT_ENABLE,
            .bits.cphsie = MCUXCLCSS_CIPHER_STATE_IN_ENABLE,
            .bits.extkey = MCUXCLCSS_CIPHER_EXTERNAL_KEY
        };

        /* Initialize CSS */
        int ret_hw_init = mbedtls_hw_init();
        if (0 != ret_hw_init) {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        /* En/decrypt full block(s) with CSS. */
        uint32_t remainLengthFullBlock = remainLength & (~(uint32_t) 15u);
        if (0u != remainLengthFullBlock) {
            int retCode = mbedtls_internal_aes_css(ctx,
                                                   pInput,
                                                   pOutput,
                                                   cipherOption,
                                                   nonce_counter,
                                                   remainLengthFullBlock);
            if (0 != retCode) {
                /* unexpected error. */
                return retCode;
            }
        }

        pInput += remainLengthFullBlock;
        pOutput += remainLengthFullBlock;
        remainLength &= 15u;

        /* En/decrypt the last incomplete block (if exists). */
        if (0u != remainLength) {
            /* Prepare the last incomplete block in temp buffer (stream_block[]). */
            uint32_t i = 0u;
            do {
                stream_block[i] = pInput[i];
                i++;
            } while (i < remainLength);
            do {
                stream_block[i] = 0u;
                i++;
            } while (i < 16u);

            /* En/decrypt the last block. */
            int retCode = mbedtls_internal_aes_css(ctx,
                                                   stream_block,
                                                   stream_block,
                                                   cipherOption,
                                                   nonce_counter,
                                                   16u);
            if (0 != retCode) {
                /* unexpected error. */
                return retCode;
            }

            /* Move result to output buffer. */
            i = 0u;
            do {
                pOutput[i] = stream_block[i];
                stream_block[i] = 0u;
                i++;
            } while (i < remainLength);

            offset = remainLength;
        } else {
            /* If there is no incomplete last block, clean up used byte(s) in stream_block[]. */
            for (uint32_t j = *nc_off; j < offset; j++) {
                stream_block[j] = 0u;
            }
        }

        *nc_off = offset & 15u;
    }

    return 0;
}
#endif /* MBEDTLS_CIPHER_MODE_CTR && MBEDTLS_AES_CTR_ALT */


#endif  /* MBEDTLS_AES_CORE_ALT */
