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

/** @file  ecdsa_alt.c
 *  @brief Alternative ECDSA implementation
 */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MCUX_PKC_ECDSA)

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#include "els_pkc_mbedtls.h"
#endif

#include <stdint.h>
#include <mcuxClEls.h>
#include <mcuxClPkc.h>
#include <mcuxClEcc.h>
#include <mcuxClMemory.h>
#include <mcuxClHash_MemoryConsumption.h>
#include <mcuxClRsa.h>
#if defined(MBEDTLS_MCUX_ELS_PKC_API)
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#endif /* MBEDTLS_MCUX_ELS_PKC_API */
#include <mbedtls/ccm.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <platform_hw_ip.h>
#include <mbedtls/ctr_drbg.h>
#include <ecc_alt.h>
#include <mbedtls/ecdh.h>

/* Definition of maximum lengths of key for RSA in bits */
#define MCUX_PKC_RSA_KEY_SIZE_MAX (4096u)

/* Definition of maximum lengths of base point order n in bytes */
#define MCUX_PKC_ECC_N_SIZE_MAX (256u / 8u) // only secp256r1 supported for now
/* Definition of maximum lengths of prime modulus in bytes */
#define MCUX_PKC_ECC_P_SIZE_MAX (256u / 8u) // only secp256r1 supported for now

/* Macro determining maximum size of CPU workarea size for MCUX_PKC_ecdsa_sign/verify functions */
#define MCUX_PKC_MAX(a, b) ((a) > (b) ? (a) : (b))

/* Macro determining minimum size of two values */
#define MCUX_PKC_MIN(a, b) ((a) < (b) ? (a) : (b))

#define MCUX_PKC_SIGN_BY_ALT_RSA_PLAIN_WACPU_SIZE_MAX                                              \
    MCUX_PKC_MAX(MCUXCLRSA_SIGN_PLAIN_PSSENCODE_WACPU_SIZE(MCUX_PKC_RSA_KEY_SIZE_MAX),             \
                        MCUXCLRSA_SIGN_PLAIN_PKCS1V15ENCODE_WACPU_SIZE(MCUX_PKC_RSA_KEY_SIZE_MAX))

#define MCUX_PKC_SIGN_BY_ALT_RSA_CRT_WACPU_SIZE_MAX                                                \
    MCUX_PKC_MAX(MCUXCLRSA_SIGN_CRT_PSSENCODE_WACPU_SIZE(MCUX_PKC_RSA_KEY_SIZE_MAX),               \
                        MCUXCLRSA_SIGN_CRT_PKCS1V15ENCODE_WACPU_SIZE(MCUX_PKC_RSA_KEY_SIZE_MAX))

#define MCUX_PKC_SIGN_BY_ALT_RSA_WACPU_SIZE_MAX                                                    \
    MCUX_PKC_MAX(MCUX_PKC_SIGN_BY_ALT_RSA_PLAIN_WACPU_SIZE_MAX,                                    \
                        MCUX_PKC_SIGN_BY_ALT_RSA_CRT_WACPU_SIZE_MAX)

#define MCUX_PKC_SIGN_BY_ALT_WACPU_SIZE_MAX                                                       \
    MCUX_PKC_MAX(MCUXCLRANDOMMODES_INIT_WACPU_SIZE,                                               \
          MCUX_PKC_MAX(MCUX_PKC_MAX(MCUX_PKC_SIGN_BY_ALT_RSA_WACPU_SIZE_MAX,                      \
                                            MCUXCLECC_SIGN_WACPU_SIZE(MCUX_PKC_ECC_N_SIZE_MAX)),  \
                        MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_MAX))

/* Macro determining maximum size of CPU workarea size for MCUX_PKC verify */
#define MCUX_PKC_VERIFY_BY_ALT_RSA_WACPU_SIZE_MAX                                                \
    MCUX_PKC_MAX(MCUXCLRSA_VERIFY_PSSVERIFY_WACPU_SIZE,               \
                        MCUXCLRSA_VERIFY_PKCS1V15VERIFY_WACPU_SIZE)

#define MCUX_PKC_VERIFY_BY_ALT_WACPU_SIZE_MAX                                                    \
    MCUX_PKC_MAX(MCUXCLRANDOMMODES_INIT_WACPU_SIZE,                                               \
        MCUX_PKC_MAX(MCUX_PKC_MAX(MCUX_PKC_VERIFY_BY_ALT_RSA_WACPU_SIZE_MAX, MCUXCLECC_VERIFY_WACPU_SIZE),    \
        MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_MAX))

/* Macro determining maximum size of PKC workarea size for MCUX_PKC Signature calculation */
#define MCUX_PKC_SIGN_BY_ALT_WAPKC_SIZE_MAX                                                     \
    MCUX_PKC_MAX(MCUXCLRSA_SIGN_CRT_WAPKC_SIZE(MCUX_PKC_RSA_KEY_SIZE_MAX),                      \
                        MCUXCLECC_SIGN_WACPU_SIZE(MCUX_PKC_ECC_N_SIZE_MAX))

/* Macro determining maximum size of PKC workarea size for MCUX_PKC verify */
#define MCUX_PKC_VERIFY_BY_ALT_WAPKC_SIZE_MAX                                                   \
    MCUX_PKC_MAX(MCUXCLRSA_VERIFY_WAPKC_SIZE(MCUX_PKC_RSA_KEY_SIZE_MAX), MCUXCLECC_VERIFY_WACPU_SIZE)


#if (!defined(MBEDTLS_ECDSA_VERIFY_ALT) || !defined(MBEDTLS_ECDSA_SIGN_ALT) || !defined(MBEDTLS_ECDSA_GENKEY_ALT))
#error This implmenetation requires that all 3 alternative implementation options are enabled together.
#else

/* Parameter validation macros based on platform_util.h */
#define ECDSA_VALIDATE_RET(cond) MBEDTLS_INTERNAL_VALIDATE_RET(cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA)
#define ECDSA_VALIDATE(cond)     MBEDTLS_INTERNAL_VALIDATE(cond)

static void mbedtls_ecp_free_ecdsa(mcuxClEcc_DomainParam_t *pDomainParams,
                                   mcuxClEcc_PointMult_Param_t *pPointMultParams,
                                   mcuxClEcc_Verify_Param_t *pVerifyParams,
                                   mcuxClEcc_Sign_Param_t *pSignParams)
{
    /* Avoid accessing a NULL pointer. Freeing a NULL pointer is fine. */
    if (pDomainParams != NULL)
    {
        mbedtls_free((void *)pDomainParams->pA);
        mbedtls_free((void *)pDomainParams->pB);
        mbedtls_free((void *)pDomainParams->pP);
        mbedtls_free((void *)pDomainParams->pG);
        mbedtls_free((void *)pDomainParams->pN);
    }

    /* Avoid accessing a NULL pointer. Freeing a NULL pointer is fine. */
    if (pPointMultParams != NULL)
    {
        mbedtls_free((void *)pPointMultParams->pScalar);
        mbedtls_free((void *)pPointMultParams->pResult);
    }

    /* Avoid accessing a NULL pointer. Freeing a NULL pointer is fine. */
    if (pVerifyParams != NULL)
    {
        mbedtls_free((void *)pVerifyParams->pSignature);
        mbedtls_free((void *)pVerifyParams->pPublicKey);
        mbedtls_free((void *)pVerifyParams->pOutputR);
    }

    /* Avoid accessing a NULL pointer. Freeing a NULL pointer is fine. */
    if (pSignParams != NULL)
    {
        mbedtls_free((void *)pSignParams->pPrivateKey);
        mbedtls_free((void *)pSignParams->pSignature);
    }
}

/*
 * Compute ECDSA signature of a hashed message
 */
int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp,
                       mbedtls_mpi *r,
                       mbedtls_mpi *s,
                       const mbedtls_mpi *d,
                       const unsigned char *buf,
                       size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng)
{
    int return_code = 0;
    /* Check input parameters. */
    ECDSA_VALIDATE_RET(grp != NULL);
    ECDSA_VALIDATE_RET(r != NULL);
    ECDSA_VALIDATE_RET(s != NULL);
    ECDSA_VALIDATE_RET(d != NULL);
    ECDSA_VALIDATE_RET(f_rng != NULL);
    ECDSA_VALIDATE_RET(buf != NULL || blen == 0);

#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
        return ret;
#endif

    /* Initialize Hardware */
    int ret_hw_init = mbedtls_hw_init();
    if (0 != ret_hw_init)
    {
        return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        goto cleanup;
    }
    /* Byte-length of prime p. */
    const uint32_t pByteLength = (grp->pbits + 7u) / 8u;
    /* Byte-length of group-order n. */
    const uint32_t nByteLength = (grp->nbits + 7u) / 8u;

    /* Setup session */
    mcuxClSession_Descriptor_t session;

    /* Buffer for the CPU workarea in memory. */
    uint32_t cpuWaBuffer[MCUX_PKC_SIGN_BY_ALT_WACPU_SIZE_MAX / sizeof(uint32_t)];
    uint32_t cpuWaSize = sizeof(cpuWaBuffer) / sizeof(cpuWaBuffer[0]);

    /* PKC buffer and size */
    uint8_t *pPkcRam         = (uint8_t *)MCUXCLPKC_RAM_START_ADDRESS;
    const uint32_t pkcWaSize = MCUXCLECC_SIGN_WAPKC_SIZE(pByteLength, nByteLength);

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(restSessionInit, tokenSessionInit,
                                         mcuxClSession_init(
                                             /* mcuxClSession_Handle_t session:     */ &session,
                                             /* uint32_t * const cpuWaBuffer:       */ cpuWaBuffer,
                                             /* uint32_t cpuWaSize:                 */ cpuWaSize,
                                             /* uint32_t * const pkcWaBuffer:       */ (uint32_t *)pPkcRam,
                                             /* uint32_t pkcWaSize:                 */ pkcWaSize));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInit)
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    if (MCUXCLSESSION_STATUS_OK != restSessionInit)
    {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    /* Set up domain parameters. */
    mcuxClEcc_DomainParam_t pDomainParams = {.pA   = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
                                             .pB   = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
                                             .pP   = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
                                             .pG   = mbedtls_calloc(pByteLength * 2u, sizeof(uint8_t)),
                                             .pN   = mbedtls_calloc(nByteLength, sizeof(uint8_t)),
                                             .misc = 0};
    if (0u != mbedtls_ecp_setupDomainParams(grp, &pDomainParams))
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, NULL);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }

    /* Set up ECC sign parameters. */
    uint8_t *pPrivateKey = mbedtls_calloc(nByteLength, sizeof(uint8_t));

    if (0 != mbedtls_mpi_write_binary(d, (unsigned char *)pPrivateKey, nByteLength))
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, NULL);
        mbedtls_free(pPrivateKey);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }

    uint8_t *pSignature = mbedtls_calloc(nByteLength * 2u, sizeof(uint8_t));

    mcuxClEcc_Sign_Param_t paramSign = {.curveParam  = pDomainParams,
                                        .pHash       = buf,
                                        .pPrivateKey = pPrivateKey,
                                        .pSignature  = pSignature,
                                        .optLen      = mcuxClEcc_Sign_Param_optLen_Pack(blen)};

    /* The code is added as per documentation of CL usage, where it specifies following:
    mcuxClEcc_Sign function uses DRBG and PRNG. Caller needs to check if DRBG and PRNG are ready.*/
    
    /* Initialize the RNG context, with maximum size */
#ifdef MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_256    
    uint32_t rng_ctx[MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE_IN_WORDS] = {0u};
#else // MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_256
    uint32_t rng_ctx[16] = {0u};
#endif

    mcuxClRandom_Mode_t randomMode = mcuxClRandomModes_Mode_ELS_Drbg ;
    
#ifdef MCUXCL_FEATURE_ECC_STRENGTH_CHECK    

    uint32_t value = (uint32_t)MCUX_PKC_MIN((nByteLength * 8u) / 2u,256u);

    if(value <= 128u)  /* 128-bit security strength */
    {
      randomMode = mcuxClRandomModes_Mode_ELS_Drbg;
    }
    else  /* 256-bit security strength */
    {
      randomMode = mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3;
    }
#endif /* MCUXCL_FEATURE_ECC_STRENGTH_CHECK */

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(randomInit_result, randomInit_token,
                                     mcuxClRandom_init(&session, (mcuxClRandom_Context_t)rng_ctx, randomMode));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != randomInit_token) ||
        (MCUXCLRANDOM_STATUS_OK != randomInit_result))
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, &paramSign);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    /* Call ECC sign. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retEccSign, tokenEccSign, mcuxClEcc_Sign(&session, &paramSign));

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Sign) != tokenEccSign)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, &paramSign);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (MCUXCLECC_STATUS_INVALID_PARAMS == retEccSign)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, &paramSign);
        return_code = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
    else if (MCUXCLECC_STATUS_RNG_ERROR == retEccSign)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, &paramSign);
        return_code = MBEDTLS_ERR_ECP_RANDOM_FAILED;
        goto cleanup;
    }
    else if (MCUXCLECC_STATUS_OK != retEccSign)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, &paramSign);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    else /* MCUXCLECC_STATUS_OK */
    {
        /* Convert signature from big-endian representation to mbedtls_mpi. */
        (void)mbedtls_mpi_read_binary(r, paramSign.pSignature, nByteLength);
        (void)mbedtls_mpi_read_binary(s, paramSign.pSignature + nByteLength, nByteLength);
        /* Free allocated memory */
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, &paramSign);
        /* Clean session. */
        (void)mcuxClSession_cleanup(&session);
        (void)mcuxClSession_destroy(&session);
        return_code = 0;
    }

cleanup:
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
        return ret;
#endif
    return return_code;
}

/*
 * Verify ECDSA signature of hashed message
 */
int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                         const unsigned char *buf,
                         size_t blen,
                         const mbedtls_ecp_point *Q,
                         const mbedtls_mpi *r,
                         const mbedtls_mpi *s)
{
    int return_code = 0;
    /* Check input parameters. */
    ECDSA_VALIDATE_RET(grp != NULL);
    ECDSA_VALIDATE_RET(Q != NULL);
    ECDSA_VALIDATE_RET(r != NULL);
    ECDSA_VALIDATE_RET(s != NULL);
    ECDSA_VALIDATE_RET(buf != NULL || blen == 0);

#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
        return ret;
#endif
    /* Initialize Hardware */
    int ret_hw_init = mbedtls_hw_init();
    if (0 != ret_hw_init)
    {
        return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    /* Byte-length of prime p. */
    const uint32_t pByteLength = (grp->pbits + 7u) / 8u;
    /* Byte-length of group-order n. */
    const uint32_t nByteLength = (grp->nbits + 7u) / 8u;

    /* Setup session */
    mcuxClSession_Descriptor_t session;

    /* Buffer for the CPU workarea in memory. */
    uint32_t cpuWaBuffer[MCUX_PKC_VERIFY_BY_ALT_WACPU_SIZE_MAX / sizeof(uint32_t)];
    uint32_t cpuWaSize = sizeof(cpuWaBuffer) / sizeof(cpuWaBuffer[0]);

    /* PKC buffer and size */
    uint8_t *pPkcRam         = (uint8_t *)MCUXCLPKC_RAM_START_ADDRESS;
    const uint32_t pkcWaSize = MCUXCLECC_VERIFY_WAPKC_SIZE(pByteLength, nByteLength);

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(restSessionInit, tokenSessionInit,
                                         mcuxClSession_init(
                                             /* mcuxClSession_Handle_t session:     */ &session,
                                             /* uint32_t * const cpuWaBuffer:       */ cpuWaBuffer,
                                             /* uint32_t cpuWaSize:                 */ cpuWaSize,
                                             /* uint32_t * const pkcWaBuffer:       */ (uint32_t *)pPkcRam,
                                             /* uint32_t pkcWaSize:                 */ pkcWaSize));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInit)
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    if (MCUXCLSESSION_STATUS_OK != restSessionInit)
    {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    /* Set up domain parameters. */
    mcuxClEcc_DomainParam_t pDomainParams = {.pA   = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
                                             .pB   = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
                                             .pP   = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
                                             .pG   = mbedtls_calloc(pByteLength * 2u, sizeof(uint8_t)),
                                             .pN   = mbedtls_calloc(nByteLength, sizeof(uint8_t)),
                                             .misc = 0};
    if (0u != mbedtls_ecp_setupDomainParams(grp, &pDomainParams))
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, NULL);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }

    /* Prepare the scalar to compute PrecG. The formula for the scalar is: 2 ^ (4 * nByteLength). */
    uint8_t *pScalarPrecG = mbedtls_calloc(nByteLength, sizeof(uint8_t));

    uint32_t scalarBitIndex                                = 4u * nByteLength;
    pScalarPrecG[nByteLength - 1u - (scalarBitIndex / 8u)] = (uint8_t)1u << (scalarBitIndex & 7u);

    /* Set up ECC point multiplication parameters for the precomputed point PrecG required by mcuxClEcc_Verify. */
    uint8_t *pResult                            = mbedtls_calloc(pByteLength * 2u, sizeof(uint8_t));
    mcuxClEcc_PointMult_Param_t pointMultParams = {.curveParam = pDomainParams,
                                                   .pScalar    = pScalarPrecG,
                                                   .pPoint     = pDomainParams.pG,
                                                   .pResult    = pResult,
                                                   .optLen     = 0u};

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

    /* Call ECC point multiplication. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retEccPointMult, tokenEccPointMult,
                                         mcuxClEcc_PointMult(&session, &pointMultParams));

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointMult) != tokenEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (MCUXCLECC_STATUS_INVALID_PARAMS == retEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
        return_code = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
    else if (MCUXCLECC_STATUS_OK != retEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    else /* MCUXCLECC_STATUS_OK */
    {
        /* Set up ECC verify parameters. */
        uint8_t *pSignature = mbedtls_calloc(nByteLength * 2u, sizeof(uint8_t));
        if (0 != mbedtls_mpi_write_binary(r, (unsigned char *)pSignature, nByteLength))
        {
            mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
            mbedtls_free(pSignature);
            return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
            goto cleanup;
        }
        if (0 != mbedtls_mpi_write_binary(s, (unsigned char *)pSignature + nByteLength, nByteLength))
        {
            mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
            mbedtls_free(pSignature);
            return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
            goto cleanup;
        }

        uint8_t *pPublicKey = mbedtls_calloc(pByteLength * 2u, sizeof(uint8_t));
        if (0 != mbedtls_mpi_write_binary(&Q->X, (unsigned char *)pPublicKey, pByteLength))
        {
            mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
            mbedtls_free(pSignature);
            mbedtls_free(pPublicKey);
            return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
            goto cleanup;
        }
        if (0 != mbedtls_mpi_write_binary(&Q->Y, (unsigned char *)pPublicKey + pByteLength, pByteLength))
        {
            mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
            mbedtls_free(pSignature);
            mbedtls_free(pPublicKey);
            return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
            goto cleanup;
        }

        uint8_t *pOutputR                    = mbedtls_calloc(nByteLength, sizeof(uint8_t));
        mcuxClEcc_Verify_Param_t paramVerify = {.curveParam = pDomainParams,
                                                .pPrecG     = pResult,
                                                .pHash      = (const uint8_t *)buf,
                                                .pSignature = pSignature,
                                                .pPublicKey = pPublicKey,
                                                .pOutputR   = pOutputR,
                                                .optLen     = mcuxClEcc_Verify_Param_optLen_Pack(blen)};

        /* Call ECC verify. */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retEccVerify, tokenEccVerify, mcuxClEcc_Verify(&session, &paramVerify));
        /* Note: according to mbedtls headers, the return code at failure is indeed MBEDTLS_ERR_ECP_BAD_INPUT_DATA and
         * not MBEDTLS_ERR_ECP_VERIFY_FAILED. */
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Verify) != tokenEccVerify) ||
            (MCUXCLECC_STATUS_OK != retEccVerify))
        {
            mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, &paramVerify, NULL);
            return_code = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            goto cleanup;
        }

        /* Free allocated memory */
        mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, &paramVerify, NULL);

        /* Note: mcuxClEcc_Verify outputs the calculated signature R if verification is successful, but mbedtls has no
         * such output, so it is dropped. */

        /* Clean session. */
        (void)mcuxClSession_cleanup(&session);
        (void)mcuxClSession_destroy(&session);
        return_code = 0;
    }
cleanup:
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
        return ret;
#endif
    return return_code;
}

/*
 * Generate key pair
 */
int mbedtls_ecdsa_genkey(mbedtls_ecdsa_context *ctx,
                         mbedtls_ecp_group_id gid,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng)
{
    int return_code = 0;
    /* Check input parameters. */
    ECDSA_VALIDATE_RET(ctx != NULL);
    ECDSA_VALIDATE_RET(f_rng != NULL);

    /* Set up the group context from the given gid. */
    int ret = mbedtls_ecp_group_load(&ctx->grp, gid);
    if (ret != 0)
    {
        return (ret);
    }
#if defined(MBEDTLS_THREADING_C)
    int thread_ret;
    if ((thread_ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
        return thread_ret;
#endif
    /* Initialize Hardware */
    int ret_hw_init = mbedtls_hw_init();
    if (0 != ret_hw_init)
    {
        return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    /* Byte-length of prime p. */
    const uint32_t pByteLength = (ctx->grp.pbits + 7u) / 8u;
    /* Byte-length of group-order n. */
    const uint32_t nByteLength = (ctx->grp.nbits + 7u) / 8u;

    /* Setup session */
    mcuxClSession_Descriptor_t session;

    /* Buffer for the CPU workarea in memory. */
    uint32_t cpuWaBuffer[MCUX_PKC_SIGN_BY_ALT_WACPU_SIZE_MAX / sizeof(uint32_t)];
    uint32_t cpuWaSize = sizeof(cpuWaBuffer) / sizeof(cpuWaBuffer[0]);

    /* PKC buffer and size */
    uint8_t *pPkcRam         = (uint8_t *)MCUXCLPKC_RAM_START_ADDRESS;
    const uint32_t pkcWaSize = MCUXCLECC_KEYGEN_WAPKC_SIZE(pByteLength, nByteLength);

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(restSessionInit, tokenSessionInit,
                                         mcuxClSession_init(
                                             /* mcuxClSession_Handle_t session:     */ &session,
                                             /* uint32_t * const cpuWaBuffer:       */ cpuWaBuffer,
                                             /* uint32_t cpuWaSize:                 */ cpuWaSize,
                                             /* uint32_t * const pkcWaBuffer:       */ (uint32_t *)pPkcRam,
                                             /* uint32_t pkcWaSize:                 */ pkcWaSize));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInit)
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    if (MCUXCLSESSION_STATUS_OK != restSessionInit)
    {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    /* Set up domain parameters. */
    mcuxClEcc_DomainParam_t pDomainParams = {.pA   = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
                                             .pB   = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
                                             .pP   = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
                                             .pG   = mbedtls_calloc(pByteLength * 2u, sizeof(uint8_t)),
                                             .pN   = mbedtls_calloc(nByteLength, sizeof(uint8_t)),
                                             .misc = 0};
    if (0u != mbedtls_ecp_setupDomainParams(&ctx->grp, &pDomainParams))
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, NULL);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }

    /* Set up ECC point multiplication parameters. */
    mbedtls_ctr_drbg_context rng_ctx;
    rng_ctx.prediction_resistance = 0;
    uint8_t *pScalar              = mbedtls_calloc(nByteLength, sizeof(uint8_t));

    if (0u != f_rng(&rng_ctx, pScalar, nByteLength))
    {
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }

    uint8_t *pResult                            = mbedtls_calloc(pByteLength * 2u, sizeof(uint8_t));
    mcuxClEcc_PointMult_Param_t PointMultParams = {
        .curveParam = pDomainParams, .pScalar = pScalar, .pPoint = pDomainParams.pG, .pResult = pResult, .optLen = 0u};

#if defined(MBEDTLS_THREADING_C)
    if ((thread_ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return thread_ret;
#endif

    /* Call ECC point multiplication. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retEccPointMult, tokenEccPointMult,
                                         mcuxClEcc_PointMult(&session, &PointMultParams));

#if defined(MBEDTLS_THREADING_C)
    if ((thread_ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return thread_ret;
#endif

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointMult) != tokenEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &PointMultParams, NULL, NULL);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (MCUXCLECC_STATUS_INVALID_PARAMS == retEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &PointMultParams, NULL, NULL);
        return_code = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
    else if (MCUXCLECC_STATUS_RNG_ERROR == retEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &PointMultParams, NULL, NULL);
        return_code = MBEDTLS_ERR_ECP_RANDOM_FAILED;
        goto cleanup;
    }
    else if (MCUXCLECC_STATUS_OK != retEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &PointMultParams, NULL, NULL);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    else
    {
        /* Convert generated point from big-endian representation to mbedtls_mpi. */
        mbedtls_mpi_read_binary(&ctx->d, pScalar, nByteLength);
        mbedtls_mpi_read_binary(&ctx->Q.X, PointMultParams.pResult, pByteLength);
        mbedtls_mpi_read_binary(&ctx->Q.Y, PointMultParams.pResult + pByteLength, pByteLength);

        /* Free allocated memory */
        mbedtls_ecp_free_ecdsa(&pDomainParams, &PointMultParams, NULL, NULL);

        /* Clean session. */
        (void)mcuxClSession_cleanup(&session);
        (void)mcuxClSession_destroy(&session);
    }
    return_code = 0;
cleanup:
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
        return ret;
#endif
    return return_code;
}

#endif /* (!defined(MBEDTLS_ECDSA_VERIFY_ALT) || !defined(MBEDTLS_ECDSA_SIGN_ALT) || \
          !defined(MBEDTLS_ECDSA_GENKEY_ALT)) */

#endif /* defined(MBEDTLS_MCUX_PKC_ECDSA) */
