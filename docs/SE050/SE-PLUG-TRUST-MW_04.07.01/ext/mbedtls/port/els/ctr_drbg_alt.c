/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2023 NXP                                                 */
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

/** @file  ctr_drbg_alt.c
 *  @brief alternative CTR DRBG implementation with ELS IP
 */

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include <platform_hw_ip.h>
#include <mcuxClEls.h>
#include <mcuxClMemory.h>

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#include "els_pkc_mbedtls.h"
#endif

#if defined(MBEDTLS_CTR_DRBG_ALT)

void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context *ctx)
{
#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex) != 0)
        return;
#endif
    mcuxClMemory_set((uint8_t *)ctx, 0u, sizeof(mbedtls_ctr_drbg_context), sizeof(mbedtls_ctr_drbg_context));
#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex) != 0)
        return;
#endif
}

void mbedtls_ctr_drbg_free(mbedtls_ctr_drbg_context *ctx)
{
#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex) != 0)
        return;
#endif
    mcuxClMemory_set((uint8_t *)ctx, 0u, sizeof(mbedtls_ctr_drbg_context), sizeof(mbedtls_ctr_drbg_context));
#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex) != 0)
        return;
#endif
}

void mbedtls_ctr_drbg_set_prediction_resistance(mbedtls_ctr_drbg_context *ctx, int resistance)
{
    ctx->prediction_resistance = resistance;
}

void mbedtls_ctr_drbg_set_entropy_len(mbedtls_ctr_drbg_context *ctx, size_t len)
{
}

void mbedtls_ctr_drbg_set_reseed_interval(mbedtls_ctr_drbg_context *ctx, int interval)
{
}

int mbedtls_ctr_drbg_set_nonce_len(mbedtls_ctr_drbg_context *ctx, size_t len)
{
    return 0;
}

int mbedtls_ctr_drbg_reseed(mbedtls_ctr_drbg_context *ctx, const unsigned char *additional, size_t len)
{
    return 0;
}

int mbedtls_ctr_drbg_update_ret(mbedtls_ctr_drbg_context *ctx, const unsigned char *additional, size_t add_len)
{
    return 0;
}

int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context *ctx,
                          int (*f_entropy)(void *, unsigned char *, size_t),
                          void *p_entropy,
                          const unsigned char *custom,
                          size_t len)
{
    return 0;
}

int mbedtls_ctr_drbg_random(void *p_rng, unsigned char *output, size_t output_len)
{
    int return_code               = 0;
    mbedtls_ctr_drbg_context *ctx = (mbedtls_ctr_drbg_context *)p_rng;

    if (0 != ctx->prediction_resistance)
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    /* Initialize ELS */
    int ret_hw_init = mbedtls_hw_init();
    if (0 != ret_hw_init)
    {
        return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    size_t output_wordLen = output_len & (~(size_t)3u);
    if (0u != output_wordLen)
    {
        /* Call mcuxClEls_Rng_DrbgRequest_Async */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retDrbgRequestAsync, tokenDrbgRequestAsync,
                                             mcuxClEls_Rng_DrbgRequest_Async(output, output_wordLen));
        if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Rng_DrbgRequest_Async) != tokenDrbgRequestAsync)
        {
            return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
            goto cleanup;
        }
        if (MCUXCLELS_STATUS_OK_WAIT != retDrbgRequestAsync)
        {
            return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
            goto cleanup;
        }

        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retElsWait, tokenElsWait,
                                             mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
        if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenElsWait)
        {
            return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
            goto cleanup;
        }
        if (MCUXCLELS_STATUS_OK != retElsWait)
        {
            return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
            goto cleanup;
        }
    }

    size_t remain_len = output_len & 0x3u;
    if (0u != remain_len)
    {
        uint32_t rngTempStack;

        /* Call mcuxClEls_Rng_DrbgRequest_Async */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retDrbgRequestAsync, tokenDrbgRequestAsync,
                                             mcuxClEls_Rng_DrbgRequest_Async((uint8_t *)&rngTempStack, 4u));
        if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Rng_DrbgRequest_Async) != tokenDrbgRequestAsync)
        {
            return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
            goto cleanup;
        }
        if (MCUXCLELS_STATUS_OK_WAIT != retDrbgRequestAsync)
        {
            return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
            goto cleanup;
        }

        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retElsWait, tokenElsWait,
                                             mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
        if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenElsWait)
        {
            return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
            goto cleanup;
        }
        if (MCUXCLELS_STATUS_OK != retElsWait)
        {
            return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
            goto cleanup;
        }

        uint32_t rngTemp    = rngTempStack; /* avoid writing rng back to stack. */
        uint8_t *outputTail = &output[output_wordLen];
        do
        {
            *outputTail = (uint8_t)(rngTemp & 0xFFu);
            rngTemp >>= 8u;
            outputTail++;
            remain_len--;
        } while (0u < remain_len);
    }
    return_code = 0;
cleanup:
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    return return_code;
}

int mbedtls_ctr_drbg_random_with_add(
    void *p_rng, unsigned char *output, size_t output_len, const unsigned char *additional, size_t add_len)
{
    return mbedtls_ctr_drbg_random(p_rng, output, output_len);
}

#endif /* MBEDTLS_CTR_DRBG_ALT */
