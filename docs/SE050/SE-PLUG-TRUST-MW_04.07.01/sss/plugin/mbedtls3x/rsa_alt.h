/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef RSA_ALT_H
#define RSA_ALT_H
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if !defined(MBEDTLS_RSA_GEN_KEY_MIN_BITS)
#define MBEDTLS_RSA_GEN_KEY_MIN_BITS 1024
#elif MBEDTLS_RSA_GEN_KEY_MIN_BITS < 128
#error "MBEDTLS_RSA_GEN_KEY_MIN_BITS must be at least 128 bits"
#endif

#include "mbedtls/bignum.h"

#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(member) member
#endif

#if defined(MBEDTLS_RSA_ALT)

#include <fsl_sss_api.h>
/**
 * \brief   The RSA context structure.
 */
typedef struct mbedtls_rsa_context {
    int MBEDTLS_PRIVATE(ver);                    /*!<  Reserved for internal purposes.
                                                  *    Do not set this field in application
                                                  *    code. Its meaning might change without
                                                  *    notice. */
    size_t MBEDTLS_PRIVATE(len);                 /*!<  The size of \p N in Bytes. */

    mbedtls_mpi MBEDTLS_PRIVATE(N);              /*!<  The public modulus. */
    mbedtls_mpi MBEDTLS_PRIVATE(E);              /*!<  The public exponent. */

    mbedtls_mpi MBEDTLS_PRIVATE(D);              /*!<  The private exponent. */
    mbedtls_mpi MBEDTLS_PRIVATE(P);              /*!<  The first prime factor. */
    mbedtls_mpi MBEDTLS_PRIVATE(Q);              /*!<  The second prime factor. */

    mbedtls_mpi MBEDTLS_PRIVATE(DP);             /*!<  <code>D % (P - 1)</code>. */
    mbedtls_mpi MBEDTLS_PRIVATE(DQ);             /*!<  <code>D % (Q - 1)</code>. */
    mbedtls_mpi MBEDTLS_PRIVATE(QP);             /*!<  <code>1 / (Q % P)</code>. */

    mbedtls_mpi MBEDTLS_PRIVATE(RN);             /*!<  cached <code>R^2 mod N</code>. */

    mbedtls_mpi MBEDTLS_PRIVATE(RP);             /*!<  cached <code>R^2 mod P</code>. */
    mbedtls_mpi MBEDTLS_PRIVATE(RQ);             /*!<  cached <code>R^2 mod Q</code>. */

    mbedtls_mpi MBEDTLS_PRIVATE(Vi);             /*!<  The cached blinding value. */
    mbedtls_mpi MBEDTLS_PRIVATE(Vf);             /*!<  The cached un-blinding value. */

    int MBEDTLS_PRIVATE(padding);                /*!< Selects padding mode:
                                                  #MBEDTLS_RSA_PKCS_V15 for 1.5 padding and
                                                  #MBEDTLS_RSA_PKCS_V21 for OAEP or PSS. */
    int MBEDTLS_PRIVATE(hash_id);                /*!< Hash identifier of mbedtls_md_type_t type,
                                                    as specified in md.h for use in the MGF
                                                    mask generating function used in the
                                                    EME-OAEP and EMSA-PSS encodings. */
#if defined(MBEDTLS_THREADING_C)
    /* Invariant: the mutex is initialized iff ver != 0. */
    mbedtls_threading_mutex_t MBEDTLS_PRIVATE(mutex);    /*!<  Thread-safety mutex. */
#endif
}
mbedtls_rsa_context;


/* clang-format on */


/*
 *  Set sss keystore for rsa
 */
void sss_mbedtls_set_keystore_rsa(sss_key_store_t *ssskeystore);
#endif /* MBEDTLS_RSA_ALT */

#endif /* RSA_ALT_H */