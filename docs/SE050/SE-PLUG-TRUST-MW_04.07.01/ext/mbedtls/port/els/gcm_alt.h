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

/** @file  gcm_alt.h
 *  @brief header of alternative AES GCM implementation with ELS IP
 */

#ifndef MBEDTLS_GCM_AES_ALT_H
#define MBEDTLS_GCM_AES_ALT_H

#include "mbedtls/gcm.h"
#include "mbedtls/cipher.h"
#include <stdint.h>

/**
 * \brief           This is an alternative implementation of the GCM key
 *                  setting function using AES GCM.
 *                  Inputs are assumed to be validated, thus this function
 *                  may only be called from the function
 *                  mbedtls_gcm_setkey().
 *
 * \param ctx       The GCM context. This must be initialized.
 * \param cipher    The 128-bit block cipher to use.
 * \param key       The encryption key. This must be a readable buffer of at
 *                  least \p keybits bits.
 * \param keybits   The key size in bits. Valid options are:
 *
 * \return          \c 0 on success.
 * \return          A cipher-specific error code on failure.
 */
int mbedtls_aes_gcm_setkey(mbedtls_gcm_context *ctx,
                           mbedtls_cipher_id_t cipher,
                           const unsigned char *key,
                           unsigned int keybits);

/**
 * \brief           This function peforms an AES GCM encryption or decryption
 *                  operation using the ELS driver.
 *                  Inputs are assumed to be validated, thus this function
 *                  may only be called from the function
 *                  mbedtls_gcm_starts().
 *
 * \param ctx       The GCM context. This must be initialized.
 * \param mode      The operation to perform: #MBEDTLS_GCM_ENCRYPT or
 *                  #MBEDTLS_GCM_DECRYPT.
 * \param iv        The initialization vector. This must be a readable buffer of
 *                  at least \p iv_len Bytes.
 * \param iv_len    The length of the IV.
 * \param add       The buffer holding the additional data, or \c NULL
 *                  if \p add_len is \c 0.
 * \param add_len   The length of the additional data. If \c 0,
 *                  \p add may be \c NULL.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_GCM_HW_ACCEL_FAILED in case of ELS error.
 */
int mbedtls_aes_gcm_starts(mbedtls_gcm_context *ctx,
                           int mode,
                           const unsigned char *iv,
                           size_t iv_len,
                           const unsigned char *add,
                           size_t add_len);

/**
 * \brief           This function feeds an input buffer into an ongoing AES GCM
 *                  encryption or decryption operation using the ELS driver.
 *                  Inputs are assumed to be validated, thus this function
 *                  may only be called from the function
 *                  mbedtls_gcm_update().
 *
 * \param ctx       The GCM context. This must be initialized.
 * \param length    The length of the input data.
 * \param input     The buffer holding the input data. If \p length is greater
 *                  than zero, this must be a readable buffer of at least that
 *                  size in Bytes.
 * \param output    The buffer for holding the output data. If \p length is
 *                  greater than zero, this must be a writable buffer of at
 *                  least that size in Bytes.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_GCM_HW_ACCEL_FAILED in case of ELS error.
 */
int mbedtls_aes_gcm_update(mbedtls_gcm_context *ctx, size_t length, const unsigned char *input, unsigned char *output);

/**
 * \brief           This function finishes the AES GCM operation and generates
 *                  the authentication tag using the ELS driver.
 *                  Inputs are assumed to be validated, thus this function
 *                  may only be called from the function
 *                  mbedtls_gcm_finish().
 *
 * \param ctx       The GCM context. This must be initialized.
 * \param tag       The buffer for holding the tag. This must be a writable
 *                  buffer of at least \p tag_len Bytes.
 * \param tag_len   The length of the tag to generate. This must be at least
 *                  four.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_GCM_HW_ACCEL_FAILED in case of ELS error.
 */
int mbedtls_aes_gcm_finish(mbedtls_gcm_context *ctx, unsigned char *tag, size_t tag_len);

#endif /* MBEDTLS_GCM_AES_ALT_H */
