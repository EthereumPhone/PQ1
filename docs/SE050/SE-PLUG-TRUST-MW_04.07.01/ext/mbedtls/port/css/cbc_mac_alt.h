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

/** @file  cbc_mac.h
 *  @brief header of alternative AES CBC-MAC with CSS IP
 */

#ifndef MBEDTLS_CBC_MAC_ALT_H
#define MBEDTLS_CBC_MAC_ALT_H

#include "mbedtls/aes.h"
#include "mbedtls/cipher.h"
#include <stdint.h>

/*
 * \brief           This function performs an AES CBC-MAC computation over the input data,
 *                  applying padding if the length is not a multiple of the AES block size.
 *                  It uses the CSS command CMAC in update mode to accelerate the CBC-MAC
 *                  computation.
 *
 * \param ctx       The aes context to use. It must be initialised and bound to a key.
 * \param length    The length of the input data.
 * \param iv        The iv/nonce that is used as the CMAC state.
 * \param pInput    The input data to be authenticated.
 *
 * \return
 */
int mbedtls_aes_cbc_mac(mbedtls_aes_context *ctx,
                        size_t length,
                        unsigned char *iv,
                        const unsigned char *pInput);

#endif /* MBEDTLS_CBC_MAC_ALT_H */
