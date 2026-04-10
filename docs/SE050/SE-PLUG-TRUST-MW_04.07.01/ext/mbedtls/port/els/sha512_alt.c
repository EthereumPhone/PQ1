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

/** @file  sha512_alt.c
 *  @brief alternative SHA-384/512 implementation with ELS IP
 */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MCUX_ELS_SHA512) 

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#include "els_pkc_mbedtls.h"
#endif

#include <sha512_alt.h>
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <platform_hw_ip.h>
#include <mbedtls/sha512.h>
#include <mcuxClEls.h>
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <mcuxClSession.h>

#if !defined(MBEDTLS_SHA512_CTX_ALT) || !defined(MBEDTLS_SHA512_STARTS_ALT) || !defined(MBEDTLS_SHA512_UPDATE_ALT) || \
    !defined(MBEDTLS_SHA512_FINISH_ALT) || !defined(MBEDTLS_SHA512_FULL_ALT)
#error the alternative implementations shall be enabled together.
#elif defined(MBEDTLS_SHA512_CTX_ALT) && defined(MBEDTLS_SHA512_STARTS_ALT) && defined(MBEDTLS_SHA512_UPDATE_ALT) && \
    defined(MBEDTLS_SHA512_FINISH_ALT) && defined(MBEDTLS_SHA512_FULL_ALT)

#define MCUXCLHASH_WA_SIZE_MAX MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_MAX

#define SHA512_VALIDATE_RET(cond) MBEDTLS_INTERNAL_VALIDATE_RET(cond, MBEDTLS_ERR_SHA512_BAD_INPUT_DATA)
#define SHA512_VALIDATE(cond)     MBEDTLS_INTERNAL_VALIDATE(cond)

int mbedtls_sha512_starts_ret(mbedtls_sha512_context *ctx, int is384)
{
    int return_code = 0;
    if (ctx == NULL)
    {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }

#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

    /* Initialize ELS */
    status_t ret_hw_init = mbedtls_hw_init();
    if (kStatus_Success != ret_hw_init)
    {
        return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    mcuxClSession_Descriptor_t session_descriptor;
    const mcuxClHash_Algo_t *pHash_algo;
    mcuxClHash_Context_t pContext = (mcuxClHash_Context_t)ctx->context;

    mcuxClSession_Handle_t session = &session_descriptor;

    if (0 == is384)
    {
        pHash_algo = &mcuxClHash_Algorithm_Sha512; //&mcuxClHash_AlgoSHA512;
    }
    else
    {
        pHash_algo = &mcuxClHash_Algorithm_Sha384; //&mcuxClHash_AlgoSHA384;
    }

#define MCUXCLHASH_WA_SIZE_MAX MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_MAX
    uint32_t workarea[MCUXCLHASH_WA_SIZE_MAX / sizeof(uint32_t)];

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(restSessionInit, tokenSessionInit,
                                         mcuxClSession_init(session, workarea, sizeof(workarea), NULL, 0U));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInit)
    {
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (MCUXCLSESSION_STATUS_OK != restSessionInit)
    {
        return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retInit, tokenInit, mcuxClHash_init(session, pContext, *pHash_algo));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_init) != tokenInit)
    {
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (MCUXCLHASH_STATUS_OK != retInit)
    {
        return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    return_code = 0;
cleanup:
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    return return_code;
}

int mbedtls_sha512_update_ret(mbedtls_sha512_context *ctx, const unsigned char *input, size_t ilen)
{
    int return_code = 0;
    if (ctx == NULL || (input == NULL && ilen != 0u))
    {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }

    mcuxClSession_Descriptor_t session_descriptor;
    mcuxClSession_Handle_t session = &session_descriptor;
    mcuxClHash_Context_t pContext  = (mcuxClHash_Context_t)ctx->context;

#define MCUXCLHASH_WA_SIZE_MAX MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_MAX
    uint32_t workarea[MCUXCLHASH_WA_SIZE_MAX / sizeof(uint32_t)];

#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(restSessionInit, tokenSessionInit,
                                         mcuxClSession_init(session, workarea, sizeof(workarea), NULL, 0U));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInit)
    {
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (MCUXCLSESSION_STATUS_OK != restSessionInit)
    {
        return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    //*context = &ctx->context;

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retUpdate, tokenUpdate, mcuxClHash_process(session, pContext, input, ilen));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process) != tokenUpdate)
    {
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (MCUXCLHASH_STATUS_OK != retUpdate)
    {
        return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    return_code = 0;
cleanup:
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    return return_code;
}

int mbedtls_sha512_finish_ret(mbedtls_sha512_context *ctx, unsigned char output[64])
{
    int return_code     = 0;
    uint32_t outputSize = 0;
    if (ctx == NULL || output == NULL)
    {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }

    mcuxClSession_Descriptor_t session_descriptor;
    mcuxClSession_Handle_t session = &session_descriptor;
    mcuxClHash_Context_t pContext  = (mcuxClHash_Context_t)ctx->context;

#define MCUXCLHASH_WA_SIZE_MAX MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_MAX
    uint32_t workarea[MCUXCLHASH_WA_SIZE_MAX / sizeof(uint32_t)];
#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(restSessionInit, tokenSessionInit,
                                         mcuxClSession_init(session, workarea, sizeof(workarea), NULL, 0U));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInit)
    {
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (MCUXCLSESSION_STATUS_OK != restSessionInit)
    {
        return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retFinish, tokenFinish,
                                         mcuxClHash_finish(session, pContext, output, &outputSize));

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCleanup, tokenCleanup, mcuxClSession_cleanup(session));
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retDestroy, toeknDestroy, mcuxClSession_destroy(session));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_finish) != tokenFinish ||
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != tokenCleanup ||
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != toeknDestroy)
    {
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (MCUXCLHASH_STATUS_OK != retFinish || MCUXCLSESSION_STATUS_OK != retCleanup ||
        MCUXCLSESSION_STATUS_OK != retDestroy)
    {
        return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        goto cleanup;
    }
    return_code = 0;
cleanup:
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    return return_code;
}

int mbedtls_sha512_ret(const unsigned char *input, size_t ilen, unsigned char output[64], int is384)
{
    int return_code     = 0;
    uint32_t outputSize = 0;
    if (input == NULL || output == NULL)
    {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }

    mcuxClSession_Descriptor_t session_descriptor;
    mcuxClSession_Handle_t session = &session_descriptor;

    const mcuxClHash_Algo_t *pHash_algo;

    if (0 == is384)
    {
        pHash_algo = &mcuxClHash_Algorithm_Sha512; //&mcuxClHash_AlgoSHA512;
    }
    else
    {
        pHash_algo = &mcuxClHash_Algorithm_Sha384; //&mcuxClHash_AlgoSHA384;
    }

    uint32_t workarea[MCUXCLHASH_WA_SIZE_MAX / sizeof(uint32_t)];
#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(restSessionInit, tokenSessionInit,
                                         mcuxClSession_init(session, workarea, sizeof(workarea), NULL, 0U));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInit)
    {
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (MCUXCLSESSION_STATUS_OK != restSessionInit)
    {
        return_code = MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
        goto cleanup;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCopmute, tokenCompute,
                                         mcuxClHash_compute(session, *pHash_algo, input, ilen, output, &outputSize));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute) != tokenCompute)
    {
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (MCUXCLHASH_STATUS_OK != retCopmute)
    {
        return_code = MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
        goto cleanup;
    }
    return_code = 0;
cleanup:
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    return return_code;
}

int mbedtls_internal_sha512_process(mbedtls_sha512_context *ctx, const unsigned char data[128])
{
    return 0;
}

#endif /* defined(MBEDTLS_SHA512_CTX_ALT) && defined(MBEDTLS_SHA512_STARTS_ALT) && defined(MBEDTLS_SHA512_UPDATE_ALT) \
          && defined(MBEDTLS_SHA512_FINISH_ALT) && defined(MBEDTLS_SHA512_FULL_ALT) */

#endif /* defined(MBEDTLS_MCUX_ELS_SHA512) */
