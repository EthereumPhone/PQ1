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

/** @file  ecdh_alt.c
 *  @brief Alternative ECDH implementation
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MCUX_PKC_ECDH)

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
#include <mcuxClRandomModes.h>
#endif /* MBEDTLS_MCUX_ELS_PKC_API */
#include <mbedtls/ccm.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ecp.h>
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <platform_hw_ip.h>
#include <mbedtls/ctr_drbg.h>
#include <ecc_alt.h>

/* Definition of maximum lengths of key for RSA in bits */
#define MCUX_PKC_RSA_KEY_SIZE_MAX (4096u)

/* Definition of maximum lengths of base point order n in bytes */
#define MCUX_PKC_ECC_N_SIZE_MAX (256u / 8u) // only secp256r1 supported for now
/* Definition of maximum lengths of prime modulus in bytes */
#define MCUX_PKC_ECC_P_SIZE_MAX (256u / 8u) // only secp256r1 supported for now

/* Macro determining maximum size of CPU workarea size for MCUX_PKC_ecdsa_sign/verify functions */
#define MCUX_PKC_MAX(a, b) ((a) > (b) ? (a) : (b))

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

#if (!defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT) || !defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT) || \
     !defined(MBEDTLS_ECDH_CANDO_ALT) || defined(MBEDTLS_ECP_RESTARTABLE))
#error The 3 alternative implementations shall be enabled together, and the feature to restart the operation has to be disabled.
#elif defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT) && defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT) && \
    defined(MBEDTLS_ECDH_CANDO_ALT) && !defined(MBEDTLS_ECP_RESTARTABLE)

/* Parameter validation macros based on platform_util.h */
#define ECDH_VALIDATE_RET(cond) MBEDTLS_INTERNAL_VALIDATE_RET(cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA)
#define ECDH_VALIDATE(cond)     MBEDTLS_INTERNAL_VALIDATE(cond)

static void mbedtls_ecp_free_ecdh(mcuxClEcc_DomainParam_t *pDomainParams, mcuxClEcc_PointMult_Param_t *pPointMultParams)
{
    /* Avoid double free in mbedtls_ecdh_gen_public */
    if (pDomainParams != NULL && pPointMultParams != NULL)
    {
        if (pDomainParams->pG != pPointMultParams->pPoint)
        {
            mbedtls_free((void *)pPointMultParams->pPoint);
        }
    }

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
}

int mbedtls_ecdh_gen_public(mbedtls_ecp_group *grp,
                            mbedtls_mpi *d,
                            mbedtls_ecp_point *Q,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    int return_code = 0;
    /* Check input parameters. */
    ECDH_VALIDATE_RET(grp != NULL);
    ECDH_VALIDATE_RET(d != NULL);
    ECDH_VALIDATE_RET(Q != NULL);
    ECDH_VALIDATE_RET(f_rng != NULL);

#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
        return ret;
#endif

    /* Initialize ELS */
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

    /*Setup session. */
    mcuxClSession_Descriptor_t session;

    /* Buffer for the CPU workarea in memory. */
    uint32_t cpuWaBuffer[MCUX_PKC_SIGN_BY_ALT_WACPU_SIZE_MAX / sizeof(uint32_t)];
    uint32_t cpuWaSize = sizeof(cpuWaBuffer) / sizeof(cpuWaBuffer[0]);

    /* PKC buffer and size */
    uint8_t *pPkcRam         = (uint8_t *)MCUXCLPKC_RAM_START_ADDRESS;
    const uint32_t pkcWaSize = MCUXCLECC_POINTMULT_WAPKC_SIZE(pByteLength, nByteLength);

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
        mbedtls_ecp_free_ecdh(&pDomainParams, NULL);
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
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

    /* Call ECC point multiplication. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retEccPointMult, tokenEccPointMult,
                                         mcuxClEcc_PointMult(&session, &PointMultParams));

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointMult) != tokenEccPointMult)
    {
        mbedtls_ecp_free_ecdh(&pDomainParams, &PointMultParams);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (MCUXCLECC_STATUS_INVALID_PARAMS == retEccPointMult)
    {
        mbedtls_ecp_free_ecdh(&pDomainParams, &PointMultParams);
        return_code = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
    else if (MCUXCLECC_STATUS_RNG_ERROR == retEccPointMult)
    {
        mbedtls_ecp_free_ecdh(&pDomainParams, &PointMultParams);
        return_code = MBEDTLS_ERR_ECP_RANDOM_FAILED;
        goto cleanup;
    }
    else if (MCUXCLECC_STATUS_OK != retEccPointMult)
    {
        mbedtls_ecp_free_ecdh(&pDomainParams, &PointMultParams);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    else
    {
        /* Convert generated point from big-endian representation to mbedtls_mpi. */
        mbedtls_mpi_read_binary(d, pScalar, nByteLength);
        mbedtls_mpi_read_binary(&Q->X, PointMultParams.pResult, pByteLength);
        mbedtls_mpi_read_binary(&Q->Y, PointMultParams.pResult + pByteLength, pByteLength);

        mbedtls_mpi_lset(&Q->Z, 1);

        /* Free allocated memory */
        mbedtls_ecp_free_ecdh(&pDomainParams, &PointMultParams);

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

int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp,
                                mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q,
                                const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
    int return_code = 0;
    /* Check input parameters. */
    ECDH_VALIDATE_RET(grp != NULL);
    ECDH_VALIDATE_RET(Q != NULL);
    ECDH_VALIDATE_RET(d != NULL);
    ECDH_VALIDATE_RET(z != NULL);

#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
        return ret;
#endif
    /* Initialize ELS */
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

    /*Setup session. */
    mcuxClSession_Descriptor_t session;

    /* Buffer for the CPU workarea in memory. */
    uint32_t cpuWaBuffer[MCUX_PKC_SIGN_BY_ALT_WACPU_SIZE_MAX / sizeof(uint32_t)];
    uint32_t cpuWaSize = sizeof(cpuWaBuffer) / sizeof(cpuWaBuffer[0]);

    /* PKC buffer and size */
    uint8_t *pPkcRam         = (uint8_t *)MCUXCLPKC_RAM_START_ADDRESS;
    const uint32_t pkcWaSize = MCUXCLECC_POINTMULT_WAPKC_SIZE(pByteLength, nByteLength);

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
        mbedtls_ecp_free_ecdh(&pDomainParams, NULL);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }

    /* Set up ECC point multiplication parameters. */
    uint8_t *pResult                            = mbedtls_calloc(pByteLength * 2u, sizeof(uint8_t));
    mcuxClEcc_PointMult_Param_t PointMultParams = {.curveParam = pDomainParams,
                                                   .pScalar    = mbedtls_calloc(nByteLength, sizeof(uint8_t)),
                                                   .pPoint     = mbedtls_calloc(pByteLength * 2, sizeof(uint8_t)),
                                                   .pResult    = pResult,
                                                   .optLen     = 0u};
    if (0u != mbedtls_mpi_write_binary(&Q->X, (unsigned char *)PointMultParams.pPoint, pByteLength))
    {
        mbedtls_ecp_free_ecdh(&pDomainParams, &PointMultParams);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (0u != mbedtls_mpi_write_binary(&Q->Y, (unsigned char *)PointMultParams.pPoint + pByteLength, pByteLength))
    {
        mbedtls_ecp_free_ecdh(&pDomainParams, &PointMultParams);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (0u != mbedtls_mpi_write_binary(d, (unsigned char *)PointMultParams.pScalar, nByteLength))
    {
        mbedtls_ecp_free_ecdh(&pDomainParams, &PointMultParams);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

    /* Call ECC point multiplication. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retEccPointMult, tokenEccPointMult,
                                         mcuxClEcc_PointMult(&session, &PointMultParams));

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointMult) != tokenEccPointMult)
    {
        mbedtls_ecp_free_ecdh(&pDomainParams, &PointMultParams);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    if (MCUXCLECC_STATUS_INVALID_PARAMS == retEccPointMult)
    {
        mbedtls_ecp_free_ecdh(&pDomainParams, &PointMultParams);
        return_code = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
    else if (MCUXCLECC_STATUS_RNG_ERROR == retEccPointMult)
    {
        mbedtls_ecp_free_ecdh(&pDomainParams, &PointMultParams);
        return_code = MBEDTLS_ERR_ECP_RANDOM_FAILED;
        goto cleanup;
    }
    else if (MCUXCLECC_STATUS_OK != retEccPointMult)
    {
        mbedtls_ecp_free_ecdh(&pDomainParams, &PointMultParams);
        return_code = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        goto cleanup;
    }
    else
    {
        /* Convert shared secret from big-endian representation to mbedtls_mpi. */
        mbedtls_mpi_read_binary(z, PointMultParams.pResult, pByteLength);

        /* Free allocated memory */
        mbedtls_ecp_free_ecdh(&pDomainParams, &PointMultParams);

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

int mbedtls_ecdh_can_do(mbedtls_ecp_group_id gid)
{
    /* MBEDTLS_ECP_DP_CURVE25519 and MBEDTLS_ECP_DP_CURVE448 not supported by alternative implementation. */
    if ((MBEDTLS_ECP_DP_CURVE25519 == gid) || (MBEDTLS_ECP_DP_CURVE448 == gid))
        return (0);
    else
        return (1);
}

#endif /* MBEDTLS_ECDH_GEN_PUBLIC_ALT && MBEDTLS_ECDH_COMPUTE_SHARED_ALT && MBEDTLS_ECDH_CANDO_ALT && \
          !MBEDTLS_ECP_RESTARTABLE */

#endif /* defined(MBEDTLS_MCUX_PKC_ECDH) */
