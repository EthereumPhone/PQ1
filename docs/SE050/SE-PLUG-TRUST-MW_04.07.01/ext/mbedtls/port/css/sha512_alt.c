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

/** @file  sha512_alt.c
 *  @brief alternative SHA-384/512 implementation with CSS IP
 */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <sha512_alt.h>
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <platform_hw_ip.h>
#include <mbedtls/sha512.h>
#include <mcuxClCss.h>
#include <mcuxClHash.h>
#include <mcuxClSession.h>

#if !defined(MBEDTLS_SHA512_CTX_ALT) || !defined(MBEDTLS_SHA512_STARTS_ALT) || \
    !defined(MBEDTLS_SHA512_UPDATE_ALT) || !defined(MBEDTLS_SHA512_FINISH_ALT) || \
    !defined(MBEDTLS_SHA512_FULL_ALT)
#error the alternative implementations shall be enabled together.
#elif defined(MBEDTLS_SHA512_CTX_ALT) && defined(MBEDTLS_SHA512_STARTS_ALT) && \
    defined(MBEDTLS_SHA512_UPDATE_ALT) && defined(MBEDTLS_SHA512_FINISH_ALT) && \
    defined(MBEDTLS_SHA512_FULL_ALT)


int mbedtls_sha512_starts_ret(mbedtls_sha512_context *ctx, int is384)
{
    if (ctx == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }

    /* Initialize CSS */
    int ret_hw_init = mbedtls_hw_init();
    if (0 != ret_hw_init) {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    mcuxClSession_Descriptor_t session_descriptor;
    const mcuxClHash_Algo_t *pHash_algo;

    mcuxClHash_Context_t *pContext = &ctx->context;

    mcuxClSession_Handle_t session = &session_descriptor;

    if (0u == is384) {
        pHash_algo = &mcuxClHash_AlgoSHA512;
    } else {
        pHash_algo = &mcuxClHash_AlgoSHA384;
    }

    uint32_t workarea[MCUXCLHASH_WA_SIZE_MAX/sizeof(uint32_t)];

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(restSessionInit, tokenSessionInit, mcuxClSession_init(
                                             session,
                                             workarea,
                                             sizeof(workarea),
                                             NULL,
                                             NULL));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInit) {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (MCUXCLSESSION_STATUS_OK != restSessionInit) {
        return MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retInit, tokenInit,
                                         mcuxClHash_init(session, pContext, pHash_algo));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_init) != tokenInit) {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (MCUXCLHASH_STATUS_OK != retInit) {
        return MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
    }

    return 0;
}

int mbedtls_sha512_update_ret(mbedtls_sha512_context *ctx,
                              const unsigned char *input,
                              size_t ilen)
{
    if (ctx == NULL || input == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }

    mcuxClSession_Descriptor_t session_descriptor;
    mcuxClSession_Handle_t session = &session_descriptor;

    uint32_t workarea[MCUXCLHASH_WA_SIZE_MAX/sizeof(uint32_t)];

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(restSessionInit, tokenSessionInit, mcuxClSession_init(
                                             session,
                                             workarea,
                                             sizeof(workarea),
                                             NULL,
                                             NULL));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInit) {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (MCUXCLSESSION_STATUS_OK != restSessionInit) {
        return MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
    }

    mcuxClHash_Context_t *pContext = &ctx->context;

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retUpdate, tokenUpdate,
                                         mcuxClHash_update(session, pContext, input, ilen));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_update) != tokenUpdate) {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (MCUXCLHASH_STATUS_OK != retUpdate) {
        return MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
    }

    return 0;
}

int mbedtls_sha512_finish_ret(mbedtls_sha512_context *ctx,
                              unsigned char output[64])
{
    if (ctx == NULL || output == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }

    mcuxClSession_Descriptor_t session_descriptor;
    mcuxClSession_Handle_t session = &session_descriptor;

    uint32_t workarea[MCUXCLHASH_WA_SIZE_MAX/sizeof(uint32_t)];

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(restSessionInit, tokenSessionInit, mcuxClSession_init(
                                             session,
                                             workarea,
                                             sizeof(workarea),
                                             NULL,
                                             NULL));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInit) {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (MCUXCLSESSION_STATUS_OK != restSessionInit) {
        return MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
    }
    mcuxClHash_Context_t *pContext = &ctx->context;

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retFinish, tokenFinish,
                                         mcuxClHash_finish(session, pContext, output, NULL));

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCleanup, tokenCleanup, mcuxClSession_cleanup(session));
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retDestroy, toeknDestroy, mcuxClSession_destroy(session));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_finish) != tokenFinish ||
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != tokenCleanup ||
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != toeknDestroy) {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (MCUXCLHASH_STATUS_OK != retFinish || MCUXCLSESSION_STATUS_OK != retCleanup ||
        MCUXCLSESSION_STATUS_OK != retDestroy) {
        return MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
    }

    return 0;
}

int mbedtls_sha512_ret(const unsigned char *input,
                       size_t ilen,
                       unsigned char output[64],
                       int is384)
{
    if (input == NULL || output == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }

    mcuxClSession_Descriptor_t session_descriptor;
    mcuxClSession_Handle_t session = &session_descriptor;

    const mcuxClHash_Algo_t *pHash_algo;

    if (0u == is384) {
        pHash_algo = &mcuxClHash_AlgoSHA512;
    } else {
        pHash_algo = &mcuxClHash_AlgoSHA384;
    }

    uint32_t workarea[MCUXCLHASH_WA_SIZE_MAX/sizeof(uint32_t)];

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(restSessionInit, tokenSessionInit, mcuxClSession_init(
                                             session,
                                             workarea,
                                             sizeof(workarea),
                                             NULL,
                                             NULL));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInit) {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (MCUXCLSESSION_STATUS_OK != restSessionInit) {
        return MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCopmute, tokenCompute,
                                         mcuxClHash_compute(session, pHash_algo, input, ilen,
                                                            output, NULL));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute) != tokenCompute) {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (MCUXCLHASH_STATUS_OK != retCopmute) {
        return MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
    }

    return 0;
}

int mbedtls_internal_sha512_process(mbedtls_sha512_context *ctx,
                                    const unsigned char data[64])
{
    return 0;
}

#endif \
    /* defined(MBEDTLS_SHA512_CTX_ALT) && defined(MBEDTLS_SHA512_STARTS_ALT) && defined(MBEDTLS_SHA512_UPDATE_ALT) && defined(MBEDTLS_SHA512_FINISH_ALT) && defined(MBEDTLS_SHA512_FULL_ALT) */
