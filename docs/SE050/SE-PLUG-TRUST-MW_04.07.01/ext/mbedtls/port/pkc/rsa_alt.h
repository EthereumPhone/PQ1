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

/** @file  rsa_alt.h
 *  @brief header of alternative RSA implementation with ELS and PKC IPs
 */

#ifndef MBEDTLS_RSA_ALT_H
#define MBEDTLS_RSA_ALT_H

#include <mcuxClSession.h> // Interface to the entire mcuxClSession component
#include <mcuxClRsa.h>     // Interface to the entire mcuxClRsa component

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/**
 * \brief   The RSA context structure.
 *
 * \note    Direct manipulation of the members of this structure
 *          is deprecated. All manipulation should instead be done through
 *          the public interface functions.
 */
typedef struct mbedtls_rsa_context
{
    int ver;    /*!<  Always 0.*/
    size_t len; /*!<  The size of \p N in Bytes. */

    mbedtls_mpi N; /*!<  The public modulus. */
    mbedtls_mpi E; /*!<  The public exponent. */

    mbedtls_mpi D; /*!<  The private exponent. */
    mbedtls_mpi P; /*!<  The first prime factor. */
    mbedtls_mpi Q; /*!<  The second prime factor. */

    mbedtls_mpi DP; /*!<  <code>D % (P - 1)</code>. */
    mbedtls_mpi DQ; /*!<  <code>D % (Q - 1)</code>. */
    mbedtls_mpi QP; /*!<  <code>1 / (Q % P)</code>. */

    mbedtls_mpi RN; /*!<  cached <code>R^2 mod N</code>. */

    mbedtls_mpi RP; /*!<  cached <code>R^2 mod P</code>. */
    mbedtls_mpi RQ; /*!<  cached <code>R^2 mod Q</code>. */

    mbedtls_mpi Vi; /*!<  The cached blinding value. */
    mbedtls_mpi Vf; /*!<  The cached un-blinding value. */

    int padding; /*!< Selects padding mode:
                      #MBEDTLS_RSA_PKCS_V15 for 1.5 padding and
                      #MBEDTLS_RSA_PKCS_V21 for OAEP or PSS. */
    int hash_id; /*!< Hash identifier of mbedtls_md_type_t type,
                      as specified in md.h for use in the MGF
                      mask generating function used in the
                      EME-OAEP and EMSA-PSS encodings. */

    mcuxClSession_Descriptor_t session_descriptor; /*!< Add a session to be able to introduce
                                                        caching of RSA key parameters in order
                                                        to improve performance. */
    mcuxClRsa_Key rsa_key;                         /*!< Internal RSA key type. */

#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t mutex; /*!<  Thread-safety mutex. */
#endif
} mbedtls_rsa_context;

extern int rsa_check_context(mbedtls_rsa_context const *ctx, int is_priv, int blinding_needed);

#endif /* MBEDTLS_RSA_ALT_H */
