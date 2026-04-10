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

/** @file  rsa_alt.c
 *  @brief alternative RSA implementation with ELS and PKC IPs
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MCUX_PKC_RSA)

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#include "els_pkc_mbedtls.h"
#endif

#include <stdint.h>
#include <mcuxClSession.h>          // Interface to the entire mcuxClSession component
#include <mcuxCsslFlowProtection.h> // Code flow protection
#include <mcuxClPkc.h>              // Interface to the entire mcuxClPkc component
#include <mcuxClRsa.h>              // Interface to the entire mcuxClRsa component
#include <mcuxClMemory.h>
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <platform_hw_ip.h>
#include <mbedtls/rsa.h>
#include <rsa_alt.h>
#include "mbedtls/platform_util.h"


#if !defined(MBEDTLS_RSA_CTX_ALT) || !defined(MBEDTLS_RSA_PUBLIC_ALT) || !defined(MBEDTLS_RSA_PRIVATE_ALT)
#error This implementation requires that all 3 alternative implementation options are enabled together.
#else

/* Parameter validation macros */
#define RSA_VALIDATE_RET( cond )                                       \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_RSA_BAD_INPUT_DATA )
#define RSA_VALIDATE( cond )                                           \
    MBEDTLS_INTERNAL_VALIDATE( cond )

   
static void mbedlts_rsa_free(uint8_t *buf, mcuxClRsa_KeyEntry_t *kP, mcuxClRsa_KeyEntry_t *kQ, mcuxClRsa_KeyEntry_t *kQ_inv,
                             mcuxClRsa_KeyEntry_t *kDP, mcuxClRsa_KeyEntry_t *kDQ, mcuxClRsa_KeyEntry_t *kE )
{
    /* Avoid accessing a NULL pointer. Freeing a NULL pointer is fine. */
    if(kP != NULL)
    {
        mbedtls_free((void*)kP->pKeyEntryData);
    }
    
    if(kQ != NULL)
    {
        mbedtls_free((void*)kQ->pKeyEntryData);
    }
         
    if(kQ_inv != NULL)
    {
        mbedtls_free((void*)kQ_inv->pKeyEntryData);
    }
    
    if(kDP != NULL)
    {
        mbedtls_free((void*)kDP->pKeyEntryData);
    }
    
    if(kDQ != NULL)
    {
        mbedtls_free((void*)kDQ->pKeyEntryData);
    }
    
    if(kE != NULL)
    {
        mbedtls_free((void*)kE->pKeyEntryData);
    }
    
    if(buf != NULL)
    {
        mbedtls_free((void*)buf);
    }

}
/*
 * Do an RSA public key operation
 */
int mbedtls_rsa_public( mbedtls_rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    int return_code =  MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    uint8_t *pBuf = NULL;
    RSA_VALIDATE_RET( ctx != NULL );
    RSA_VALIDATE_RET( input != NULL );
    RSA_VALIDATE_RET( output != NULL );

    if( rsa_check_context( ctx, 0 /* public */, 0 /* no blinding */ ) )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/
#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
        return ret;
#endif
    
    /* Initialize Hardware */
    int ret_hw_init = mbedtls_hw_init();
    if(0!=ret_hw_init)
    {
        return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    /* Create session handle to be used by verify function */

    /* Get the byte-length of modulus n */
    const uint32_t nByteLength = ctx->len;

    /* CPU buffer */
    uint32_t cpuWaBuffer[MCUXCLRSA_VERIFY_NOVERIFY_WACPU_SIZE / sizeof(uint32_t)];

    /* PKC buffer and size */
    uint8_t *pPkcRam = (uint8_t *) MCUXCLPKC_RAM_START_ADDRESS;

    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;
	
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(si_status, si_token, mcuxClSession_init(
                /* mcuxClSession_Handle_t session:      */ session,
                /* uint32_t * const cpuWaBuffer:       */ cpuWaBuffer,
                /* uint32_t cpuWaSize:                 */ MCUXCLRSA_VERIFY_NOVERIFY_WACPU_SIZE,
                /* uint32_t * const pkcWaBuffer:       */ (uint32_t *) pPkcRam,
                /* uint32_t pkcWaSize:                 */ MCUXCLRSA_VERIFY_WAPKC_SIZE(nByteLength * 8u)
                ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != si_token) || (MCUXCLSESSION_STATUS_OK != si_status))
    {
        return_code = MBEDTLS_ERR_RSA_PUBLIC_FAILED;
        goto cleanup;
    }

    
    /* Get actual parameter lengths */
    size_t modByteLength = (mbedtls_mpi_bitlen(&ctx->N) + 7u) / 8u;
    size_t expByteLength = (mbedtls_mpi_bitlen(&ctx->E) + 7u) / 8u;

    mcuxClRsa_KeyEntry_t kMod = {0};
    mcuxClRsa_KeyEntry_t kExp = {0};
    
    pBuf = mbedtls_calloc(nByteLength, sizeof(uint8_t));
    if (pBuf == NULL)
      goto cleanup;
    
    kMod.pKeyEntryData = mbedtls_calloc(modByteLength, sizeof(uint8_t));
    if (kMod.pKeyEntryData == NULL)
      goto cleanup;
    
    kExp.pKeyEntryData = mbedtls_calloc(expByteLength, sizeof(uint8_t));
    if (kExp.pKeyEntryData == NULL)
      goto cleanup;
    /* Create key struct of type MCUXCLRSA_KEY_PUBLIC */

    /* Check actual length with length given in the context. */
    if( nByteLength != modByteLength )
    {
        return_code = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto cleanup;
    }

    /* Use mbedtls function to extract key parameters in big-endian order */
    mbedtls_mpi_write_binary(&ctx->N, kMod.pKeyEntryData, modByteLength);
    mbedtls_mpi_write_binary(&ctx->E, kExp.pKeyEntryData, expByteLength);

    kMod.keyEntryLength = (uint32_t) modByteLength;
    kExp.keyEntryLength = (uint32_t) expByteLength;

    const mcuxClRsa_Key public_key = {
                                     .keytype = MCUXCLRSA_KEY_PUBLIC,
                                     .pMod1 = (mcuxClRsa_KeyEntry_t *)&kMod,
                                     .pMod2 = NULL,
                                     .pQInv = NULL,
                                     .pExp1 = (mcuxClRsa_KeyEntry_t *)&kExp,
                                     .pExp2 = NULL,
                                     .pExp3 = NULL };

    ctx->rsa_key = public_key;

    /**************************************************************************/
    /* RSA verify call                                                        */
    /**************************************************************************/

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(verify_result, verify_token, mcuxClRsa_verify(
                /* mcuxClSession_Handle_t           pSession: */           session,
                /* const mcuxClRsa_Key * const      pKey: */               &public_key,
                /* const uint8_t * const           pMessageOrDigest: */   NULL,
                /* const uint32_t                  messageLength: */      0u,
                /* uint8_t * const                 pSignature: */         (uint8_t *)input,
                /* const mcuxClRsa_SignVerifyMode   pVerifyMode: */        (mcuxClRsa_SignVerifyMode_t *)&mcuxClRsa_Mode_Verify_NoVerify,
                /* const uint32_t                  saltLength: */         0u,
                /* uint32_t                        options: */            0u,
                /* uint8_t * const                 pOutput: */            (uint8_t *)pBuf));

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_verify) != verify_token) || (MCUXCLRSA_STATUS_VERIFYPRIMITIVE_OK != verify_result))
    {
        return_code = MBEDTLS_ERR_RSA_PUBLIC_FAILED;
        goto cleanup;
    }   

    /* Copy result buffer to output */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retMemCpy, tokenMemCpy,
            mcuxClMemory_copy((uint8_t *) output, pBuf, nByteLength, nByteLength) );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) != tokenMemCpy) && (0u != retMemCpy) )
    {
        return_code = MBEDTLS_ERR_RSA_PUBLIC_FAILED;
        goto cleanup;
    }

    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(cleanup_result, cleanup_token, mcuxClSession_cleanup(
                /* mcuxClSession_Handle_t           pSession: */           session));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != cleanup_token) || (MCUXCLSESSION_STATUS_OK != cleanup_result))
    {
        return_code = MBEDTLS_ERR_RSA_PUBLIC_FAILED;
        goto cleanup;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(destroy_result, destroy_token, mcuxClSession_destroy(
                /* mcuxClSession_Handle_t           pSession: */           session));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != destroy_token) || (MCUXCLSESSION_STATUS_OK != destroy_result))
    {
        return_code = MBEDTLS_ERR_RSA_PUBLIC_FAILED;
        goto cleanup;
    }

    return_code = 0;
cleanup:
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
        return ret;
#endif
    mbedlts_rsa_free(pBuf, &kMod, NULL, NULL, &kExp, NULL, NULL );
    return return_code; 
}

/*
 * Do an RSA private key operation
 */
int mbedtls_rsa_private( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output )
{
    int return_code = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    uint8_t *pBuf = NULL;
    RSA_VALIDATE_RET( ctx != NULL );
    RSA_VALIDATE_RET( input != NULL );
    RSA_VALIDATE_RET( output != NULL );

    if( rsa_check_context( ctx, 1 /* private */, 1 /* blinding */ ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/


#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
        return ret;
#endif

    /* Initialize Hardware */
    int ret_hw_init = mbedtls_hw_init();
    if(0!=ret_hw_init)
    {
        return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    /* Create session handle to be used by sign function */

    /* Get the byte-length of modulus n */
    const uint32_t nByteLength = ctx->len;
    const uint32_t pqByteLength = (nByteLength+1u) / 2u;

    /* CPU buffer */
    uint32_t cpuWaBuffer[MCUXCLRSA_SIGN_CRT_NOENCODE_4096_WACPU_SIZE / sizeof(uint32_t)];
    uint32_t cpuWaSize = MCUXCLRSA_SIGN_CRT_NOENCODE_4096_WACPU_SIZE;
    
    /* PKC buffer and size */   
    uint8_t *pPkcRam = (uint8_t *) MCUXCLPKC_RAM_START_ADDRESS;

    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(si_status, si_token, mcuxClSession_init(
                /* mcuxClSession_Handle_t session:      */ session,
                /* uint32_t * const cpuWaBuffer:       */ cpuWaBuffer,
                /* uint32_t cpuWaSize:                 */ cpuWaSize,
                /* uint32_t * const pkcWaBuffer:       */ (uint32_t *) pPkcRam,
                /* uint32_t pkcWaSize:                 */ MCUXCLRSA_SIGN_CRT_WAPKC_SIZE(nByteLength * 8u)
                ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != si_token) || (MCUXCLSESSION_STATUS_OK != si_status))
    {
        return_code = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
        goto cleanup;
    }

    /* Get actual parameter lengths */
    size_t pByteLength     = (mbedtls_mpi_bitlen(&ctx->P) + 7u) / 8u;
    size_t qByteLength     = (mbedtls_mpi_bitlen(&ctx->Q) + 7u) / 8u;
    size_t q_invByteLength = (mbedtls_mpi_bitlen(&ctx->QP) + 7u) / 8u;
    size_t dpByteLength    = (mbedtls_mpi_bitlen(&ctx->DP) + 7u) / 8u;
    size_t dqByteLength    = (mbedtls_mpi_bitlen(&ctx->DQ) + 7u) / 8u;
    size_t eByteLength     = (mbedtls_mpi_bitlen(&ctx->E) + 7u) / 8u;
    
    mcuxClRsa_KeyEntry_t kP = {0};
    mcuxClRsa_KeyEntry_t kQ = {0};
    mcuxClRsa_KeyEntry_t kQ_inv = {0};
    mcuxClRsa_KeyEntry_t kDP = {0};
    mcuxClRsa_KeyEntry_t kDQ = {0};
    mcuxClRsa_KeyEntry_t kE = {0};
    
    pBuf = mbedtls_calloc(nByteLength, sizeof(uint8_t));
    if (pBuf == NULL)
      goto cleanup;
    
    kP.pKeyEntryData = mbedtls_calloc(pByteLength, sizeof(uint8_t));
    if (kP.pKeyEntryData == NULL)
      goto cleanup;
    
    kQ.pKeyEntryData = mbedtls_calloc(qByteLength, sizeof(uint8_t));
    if (kQ.pKeyEntryData == NULL)
      goto cleanup;
    
    kQ_inv.pKeyEntryData = mbedtls_calloc(q_invByteLength, sizeof(uint8_t));
    if (kQ_inv.pKeyEntryData == NULL)
      goto cleanup;
    
    kDP.pKeyEntryData = mbedtls_calloc(dpByteLength, sizeof(uint8_t));
    if (kDP.pKeyEntryData == NULL)
      goto cleanup;
    
    kDQ.pKeyEntryData = mbedtls_calloc(dqByteLength, sizeof(uint8_t));
    if (kDQ.pKeyEntryData == NULL)
      goto cleanup;
    
    kE.pKeyEntryData = mbedtls_calloc(eByteLength, sizeof(uint8_t));
    if (kE.pKeyEntryData == NULL)
      goto cleanup;
    
    
    /* Create key struct of type MCUXCLRSA_KEY_PRIVATECRT */

    /* Check actual length with length given in the context. */
    if( (pqByteLength != pByteLength) || (pqByteLength != qByteLength) )
    {
        return_code = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto cleanup;
    }
    
    /* Use mbedtls function to extract key parameters in big-endian order */
    mbedtls_mpi_write_binary(&ctx->P, kP.pKeyEntryData, pByteLength);
    mbedtls_mpi_write_binary(&ctx->Q, kQ.pKeyEntryData, qByteLength);
    mbedtls_mpi_write_binary(&ctx->QP, kQ_inv.pKeyEntryData, q_invByteLength);
    mbedtls_mpi_write_binary(&ctx->DP, kDP.pKeyEntryData, dpByteLength);
    mbedtls_mpi_write_binary(&ctx->DQ, kDQ.pKeyEntryData, dqByteLength);
    mbedtls_mpi_write_binary(&ctx->E, kE.pKeyEntryData, eByteLength);
    
    kP.keyEntryLength = (uint32_t) pByteLength;
    kQ.keyEntryLength = (uint32_t) qByteLength;
    kQ_inv.keyEntryLength = (uint32_t) q_invByteLength;
    kDP.keyEntryLength = (uint32_t) dpByteLength; 
    kDQ.keyEntryLength = (uint32_t) dqByteLength;
    kE.keyEntryLength = (uint32_t) eByteLength;
  
    const mcuxClRsa_Key private_key = {
                                     .keytype = MCUXCLRSA_KEY_PRIVATECRT,
                                     .pMod1 = (mcuxClRsa_KeyEntry_t *)&kP,
                                     .pMod2 = (mcuxClRsa_KeyEntry_t *)&kQ,
                                     .pQInv = (mcuxClRsa_KeyEntry_t *)&kQ_inv,
                                     .pExp1 = (mcuxClRsa_KeyEntry_t *)&kDP,
                                     .pExp2 = (mcuxClRsa_KeyEntry_t *)&kDQ,
                                     .pExp3 = (mcuxClRsa_KeyEntry_t *)&kE };

    ctx->rsa_key = private_key;

    /**************************************************************************/
    /* RSA sign call                                                          */
    /**************************************************************************/

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(sign_result, sign_token, mcuxClRsa_sign(
                /*  mcuxClSession_Handle_t           pSession,  */           session,
                /*  const mcuxClRsa_Key * const      pKey,  */               &private_key,
                /*  const uint8_t * const           pMessageOrDigest,  */   (uint8_t *)input,
                /*  const uint32_t                  messageLength,  */      0u,
                /*  const mcuxClRsa_SignVerifyMode   pPaddingMode,  */       (mcuxClRsa_SignVerifyMode_t *)&mcuxClRsa_Mode_Sign_NoEncode,
                /*  const uint32_t                  saltLength,  */         0u,
                /*  const uint32_t                  options,  */            0u,
                /*  uint8_t * const                 pSignature)  */         (uint8_t *)pBuf));

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_sign) != sign_token) || (MCUXCLRSA_STATUS_SIGN_OK != sign_result))
    {
        if (MCUXCLRSA_STATUS_INVALID_INPUT == sign_result)
        {
            return_code = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
            goto cleanup;
        }
        else
        {
            return_code = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
            goto cleanup;
        }
    }

    /* Copy result buffer to output */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retMemCpy, tokenMemCpy,
            mcuxClMemory_copy((uint8_t *) output, pBuf, nByteLength, nByteLength) );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) != tokenMemCpy) && (0u != retMemCpy) )
    {
        return_code = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
        goto cleanup;
    }

    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(cleanup_result, cleanup_token, mcuxClSession_cleanup(
                /* mcuxClSession_Handle_t           pSession: */           session));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != cleanup_token) || (MCUXCLSESSION_STATUS_OK != cleanup_result))
    {
        return_code = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
        goto cleanup;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(destroy_result, destroy_token, mcuxClSession_destroy(
                /* mcuxClSession_Handle_t           pSession: */           session));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != destroy_token) || (MCUXCLSESSION_STATUS_OK != destroy_result))
    {
        return_code = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
        goto cleanup;
    }

    return_code = 0;
cleanup:
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
        return ret;
#endif
    mbedlts_rsa_free(pBuf, &kP, &kQ, &kQ_inv, &kDP, &kDQ, &kE );
    return return_code; 
}

#endif /* !defined(MBEDTLS_RSA_CTX_ALT) || !defined(MBEDTLS_RSA_PUBLIC_ALT) || !defined(MBEDTLS_RSA_PRIVATE_ALT) */

#endif /* defined(MBEDTLS_MCUX_PKC_RSA) */