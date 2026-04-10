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

/**
 * @file  cmac_alt.h
 * @brief header of alternative CMAC implementation
 */


#ifndef MBEDTLS_CMAC_ALT_H
#define MBEDTLS_CMAC_ALT_H

#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClMac.h>
#include <internal/mcuxClMac_internal.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif


#if defined(MBEDTLS_AES_CMAC_ALT)
/**
 * The AES CMAC context structure.
 */
typedef struct {
    mcuxClSession_Descriptor_t macSession;
    mcuxClKey_Descriptor_t     macKey;
    mcuxClMac_Context_t        macContext;
    uint32_t *macKeyDestination;
    uint32_t                  macCpuWa[(MCUXCLMAC_WA_SIZE_MAX + (sizeof(uint32_t)) - 1u) /
                                       (sizeof(uint32_t))];
} mbedtls_aes_cmac_context_t;

/**
 * \brief               This function sets the AES CMAC key, and prepares to
 *                      authenticate the input data.
 *                      This is an alternative implementation, and inputs are assumed
 *                      to be validated, thus this function may only be called from
 *                      the function mbedtls_cipher_cmac_starts.
 *
 * \param ctx           The cipher context used for the CMAC operation, initialized
 *                      as one of the following types: MBEDTLS_CIPHER_AES_128_ECB,
 *                      or MBEDTLS_CIPHER_AES_256_ECB.
 * \param key           The AES CMAC key.
 * \param keybits       The length of the AES CMAC key in bits.
 *                      Must be supported by the cipher.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED on error
 */
int mbedtls_cipher_aes_cmac_starts(mbedtls_cipher_context_t *ctx);

/**
 * \brief               This function feeds an input buffer into an ongoing AES CMAC
 *                      computation.
 *                      This is an alternative implementation, and inputs are assumed
 *                      to be validated, thus this function may only be called from
 *                      the function mbedtls_cipher_cmac_update.
 *
 * \param ctx           The cipher context used for the AES CMAC operation.
 * \param input         The buffer holding the input data.
 * \param ilen          The length of the input data.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED on CSS error
 * \return              #MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED on other error
 *
 */
int mbedtls_cipher_aes_cmac_update(mbedtls_cipher_context_t *ctx,
                                   const unsigned char *input,
                                   size_t ilen);

/**
 * \brief               This function finishes the AES CMAC operation, and writes
 *                      the result to the output buffer.
 *                      This is an alternative implementation, and inputs are assumed
 *                      to be validated, thus this function may only be called from
 *                      the function mbedtls_cipher_cmac_finish.
 *
 * \param ctx           The cipher context used for the AES CMAC operation.
 * \param output        The output buffer for the AES CMAC checksum result.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED on CSS error
 * \return              #MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED on other error
 *
 */
int mbedtls_cipher_aes_cmac_finish(mbedtls_cipher_context_t *ctx,
                                   unsigned char *output);
#endif  /* MBEDTLS_AES_CMAC_ALT */

#endif  /* MBEDTLS_CMAC_ALT_H */
