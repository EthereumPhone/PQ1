/*
 * Copyright 2022 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "sss_crypto.h"

#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/pk.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

#include "mbedtls/platform_util.h"

/* Used as values s and n of mbedtls_mpi object to indicate that P contain pointer to key object. */
#define MBEDTLS_MPI_S_HAVE_OBJECT (155)
#define MBEDTLS_MPI_N_HAVE_OBJECT (1u)

typedef struct mbedtls_ecp_context {
    mbedtls_ecp_group grp; /*!<  Elliptic curve and base point     */
    mbedtls_mpi d;         /*!<  our secret value                  */
    mbedtls_ecp_point Q;   /*!<  our public value                  */
    sss_sscp_object_t key;
    bool isKeyInitialized;
} mbedtls_ecp_context;


#if defined(MBEDTLS_MPI_FREE_ALT)
/*
 * Unallocate one MPI
 */
void mbedtls_mpi_free(mbedtls_mpi *X)
{
    if (X == NULL) {
        return;
    }

    if ((X->s == MBEDTLS_MPI_S_HAVE_OBJECT) && (X->n == MBEDTLS_MPI_N_HAVE_OBJECT)) {
        SSS_KEY_OBJ_FREE((sss_sscp_object_t *) X->p);
        X->p = NULL;
    }
    if (X->p != NULL) {
        //mbedtls_mpi_zeroize( X->p, X->n );
        mbedtls_free(X->p);
    }

    X->s = 1;
    X->n = 0;
    X->p = NULL;
}
#endif /* MBEDTLS_MPI_FREE_ALT */

#if defined(MBEDTLS_ECP_GENKEY_ALT)
/*
 * Generate key pair
 */
int mbedtls_ecp_gen_key(mbedtls_ecp_group_id grp_id,
                        mbedtls_ecp_keypair *key,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng)
{
    int ret = 0;
    mbedtls_ecp_context *ctx = (mbedtls_ecp_context *) key;

    MBEDTLS_INTERNAL_VALIDATE_RET((key != NULL), MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
    ret = mbedtls_ecp_group_load(&key->grp, grp_id);
    if (ret != 0) {
        return ret;
    }
    size_t keyLen     = (key->grp.pbits + 7u) / 8u;
    size_t keyBitsLen = key->grp.pbits;

    size_t keySize    = SSS_ECP_KEY_SZ(keyLen);
    uint8_t *pubKey   = mbedtls_calloc(keySize, sizeof(uint8_t));
    MBEDTLS_INTERNAL_VALIDATE_RET((pubKey != NULL), MBEDTLS_ERR_ECP_ALLOC_FAILED);

    if (CRYPTO_InitHardware() != kStatus_Success) {
        mbedtls_free(pubKey);
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    if (ctx->isKeyInitialized == false) {
        if (sss_sscp_key_object_init(&ctx->key, &g_keyStore) != kStatus_SSS_Success) {
            mbedtls_free(pubKey);
            (void) SSS_KEY_OBJ_FREE(&ctx->key);
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }
        /* Allocate key handle */
        else if (sss_sscp_key_object_allocate_handle(&ctx->key,
                                                     0x0u,
                                                     kSSS_KeyPart_Pair,
                                                     kSSS_CipherType_EC_NIST_P,
                                                     3 * keyLen,
                                                     SSS_KEYPROP_OPERATION_KDF |
                                                     SSS_KEYPROP_OPERATION_ASYM) !=
                 kStatus_SSS_Success) {
            mbedtls_free(pubKey);
            (void) SSS_KEY_OBJ_FREE(&ctx->key);
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        } else {
            ctx->isKeyInitialized = true;
        }
    }
    if (SSS_ECP_GENERATE_KEY(&ctx->key, keyBitsLen) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (SSS_KEY_STORE_GET_PUBKEY(&ctx->key, pubKey, &keySize,
                                        &keyBitsLen) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else {
        ret = mbedtls_mpi_read_binary(&ctx->Q.X, pubKey, keyLen);
        ret += mbedtls_mpi_read_binary(&ctx->Q.Y, &pubKey[keyLen], keyLen);
        ret += mbedtls_mpi_lset(&ctx->Q.Z, 1);
    }

    if (ret == 0) {
        ctx->d.s = MBEDTLS_MPI_S_HAVE_OBJECT;
        ctx->d.n = MBEDTLS_MPI_N_HAVE_OBJECT;
        ctx->d.p = (mbedtls_mpi_uint *) (uintptr_t) &ctx->key;
    } else {
        (void) SSS_KEY_OBJ_FREE(&ctx->key);
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    mbedtls_platform_zeroize(pubKey, keySize);
    mbedtls_free(pubKey);
    return ret;
}
#endif /* MBEDTLS_ECP_GENKEY_ALT */

#if defined(MBEDTLS_PK_KEY_ALT)
int mbedtls_pk_write_key_der(mbedtls_pk_context *key, unsigned char *buf, size_t size)
{

    MBEDTLS_INTERNAL_VALIDATE_RET((key != NULL), MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
    MBEDTLS_INTERNAL_VALIDATE_RET((buf != NULL), MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    if (size == 0) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    size_t buffSize = size;
    size_t keyBlobLen;

    if (mbedtls_pk_get_type(key) == MBEDTLS_PK_ECKEY) {
        mbedtls_ecp_context *keyCtx = (mbedtls_ecp_context *) mbedtls_pk_ec(*key);
        /* private key is size of one coordinate and public key 2 + blob overhead of 24*/
        keyBlobLen = ((keyCtx->grp.pbits + 7u) / 8u) * 3 + 24;

        if (keyBlobLen > size) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }

        if (CRYPTO_InitHardware() != kStatus_Success) {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        if ((keyCtx->d.s != MBEDTLS_MPI_S_HAVE_OBJECT) ||
            (keyCtx->d.n != MBEDTLS_MPI_N_HAVE_OBJECT)) {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        if (sss_sscp_key_store_export_key(&g_keyStore, &keyCtx->key, buf, &keyBlobLen,
                                          kSSS_blobType_ELKE_blob) != kStatus_SSS_Success) {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        /* SW mbedtls function writes data at the end of buffer so to maintain compatibility we do the
           same here */
        memmove(buf + buffSize - keyBlobLen, buf, keyBlobLen);

    } else {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    return keyBlobLen;
}

int mbedtls_pk_parse_key(mbedtls_pk_context *pk,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *pwd, size_t pwdlen)
{
    int ret = 0;

    MBEDTLS_INTERNAL_VALIDATE_RET((pk != NULL), MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
    MBEDTLS_INTERNAL_VALIDATE_RET((key != NULL), MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    if (keylen == 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

    mbedtls_ecp_context *keyCtx = (mbedtls_ecp_context *) pk->pk_ctx;
    mbedtls_ecp_group_load(&keyCtx->grp, MBEDTLS_ECP_DP_SECP256R1);

    size_t keyLen = (keyCtx->grp.pbits + 7u) / 8u;
    size_t keyBitsLen = keyCtx->grp.pbits;

    size_t keySize    = SSS_ECP_KEY_SZ(keyLen);
    uint8_t pubKey[64];

    if (CRYPTO_InitHardware() != kStatus_Success) {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    if (sss_sscp_key_object_init(&keyCtx->key, &g_keyStore) != kStatus_SSS_Success) {
        (void) SSS_KEY_OBJ_FREE(&keyCtx->key);
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    /* Allocate key handle */
    else if (sss_sscp_key_object_allocate_handle(&keyCtx->key,
                                                 0x0u,
                                                 kSSS_KeyPart_Pair,
                                                 kSSS_CipherType_EC_NIST_P,
                                                 3* keyLen,
                                                 SSS_KEYPROP_OPERATION_ASYM) !=
             kStatus_SSS_Success) {
        (void) SSS_KEY_OBJ_FREE(&keyCtx->key);
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_key_store_import_key(&g_keyStore, &keyCtx->key, key, keylen,
                                             keyCtx->grp.pbits,
                                             kSSS_blobType_ELKE_blob) != kStatus_SSS_Success) {
        (void) SSS_KEY_OBJ_FREE(&keyCtx->key);
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else {
        if (SSS_KEY_STORE_GET_PUBKEY(&keyCtx->key, pubKey, &keySize,
                                     &keyBitsLen) != kStatus_SSS_Success) {
            ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        } else {
            ret = mbedtls_mpi_read_binary(&keyCtx->Q.X, pubKey, keyLen);
            ret += mbedtls_mpi_read_binary(&keyCtx->Q.Y, &pubKey[keyLen], keyLen);
            ret += mbedtls_mpi_lset(&keyCtx->Q.Z, 1);
        }

        if (ret == 0) {
            keyCtx->d.s = MBEDTLS_MPI_S_HAVE_OBJECT;
            keyCtx->d.n = MBEDTLS_MPI_N_HAVE_OBJECT;
            keyCtx->d.p = (mbedtls_mpi_uint *) (uintptr_t) &keyCtx->key;
            keyCtx->isKeyInitialized = true;
        } else {
            (void) SSS_KEY_OBJ_FREE(&keyCtx->key);
            ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }
    }
    return ret;
}
#endif /* MBEDTLS_PK_KEY_ALT */
