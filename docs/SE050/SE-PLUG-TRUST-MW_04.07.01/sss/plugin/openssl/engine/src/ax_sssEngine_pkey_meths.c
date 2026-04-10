/**
 * @file ax_sssEngine_pkey_meths.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Engine for NXP Embedded Secure Element over SSS API's
 *
 * The following operations are supported by this engine:
 * - Random number generation
 * - X25519 derive key
 * - X448 derive key
 *
 * When dealing with an EC key argument whose a public key is used:
 * - In case the key is a 'reference key' -> use the referenced public key
 * - In case the above does not apply; at compile time one can choose between two
 *   strategies:
 *   (1) return a fail
 *   (2) delegate the operation to the OpenSSL SW implementation
 *
 * When dealing with an EC key argument whose private key is used:
 * - In case the key is a 'reference key' -> use the referenced private key
 * - In case the above does not apply; at compile time one can choose between two
 *   strategies:
 *   (1) return a fail
 *   (2) delegate the operation to the OpenSSL SW implementation
 *
 * @note
 *   Compatible with:
 *   - OpenSSL 1.1.0
 *
 */

/*
 * This file contains source code form OpenSSL distribution that is covered
 * by the LICENSE-OpenSSL file to be found in the root of this source code
 * distribution tree.
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <ex_sss.h>
#include <stdlib.h>

#include "ax_api.h"
#include "ax_embSeEngine.h"
#include "ax_embSeEngine_Internal.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "sm_printf.h"

#if SSS_HAVE_ECC || (SSS_HAVE_APPLET_NONE && (SSS_HAVE_HOSTCRYPTO_OPENSSL || SSS_HAVE_HOSTCRYPTO_MBEDTLS))
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else

typedef struct
{
    unsigned char pubkey[57];
    unsigned char *privkey;
} ECX_KEY;

int supported_nid[] = {
    EVP_PKEY_X25519,
    EVP_PKEY_X448,
};
int supported_nid_cnt = 2;

char x25519_header[] = {
    0x30,
    0x2A,
    0x30,
    0x05,
    0x06,
    0x03,
    0x2B,
    0x65,
    0x6E,
    0x03,
    0x21,
    0x00,
};

char x448_header[] = {
    0x30,
    0x42,
    0x30,
    0x05,
    0x06,
    0x03,
    0x2b,
    0x65,
    0x6f,
    0x03,
    0x39,
    0x00,
};

static const EVP_PKEY_METHOD *default_x25519_pmethods = NULL;
static EVP_PKEY_METHOD *sss_x25519_pmeth = NULL;
static const EVP_PKEY_METHOD *default_x448_pmethods = NULL;
static EVP_PKEY_METHOD *sss_x448_pmeth = NULL;

static U16 getExKeyReference(unsigned char *private_key, size_t keyLen, uint32_t *keyId)
{
    U16 sw = ERR_PATTERN_COMPARE_FAILED;
    U8 Ident = 0;
    U8 Index = 0;
    U32 Coeff[2] = {0, 0};
    size_t i = 0;
    size_t j = 0;

    if (private_key == NULL) {
        return ERR_NO_PRIVATE_KEY;
    }

    *keyId = 0;

    if (keyLen < 2) {
        return ERR_GENERAL_ERROR;
    }
    Ident = private_key[keyLen - 2];
    Index = private_key[keyLen - 1];

    /* Get double ID string */
    if (keyLen < 14 /* Based on for loops below. 2 Magic numbers + key id */) {
        return ERR_PATTERN_COMPARE_FAILED;
    }
    for (j = 0; j < 2; j++) {
        for (i = 3; i < 7; i++) {
            Coeff[j] |= (U32)private_key[keyLen - i - (j * 4)] << 8 * (i - 3);
        }
    }

    if (((unsigned int)Coeff[0] == (unsigned int)EMBSE_REFKEY_ID) &&
        ((unsigned int)Coeff[1] == (unsigned int)EMBSE_REFKEY_ID)) {
        j = 2;
        for (i = 3; i < 7; i++) {
            *keyId |= (uint32_t)private_key[keyLen - i - (j * 4)] << 8 * (i - 3);
        }
        sw = SW_OK;
        EmbSe_Print(LOG_DBG_ON, "Using keyId=0x%08X\n", *keyId);
    }
    else {
        sw = ERR_PATTERN_COMPARE_FAILED;
    }

    return sw;
}

static sss_status_t EmbSe_derive_key(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen, int nid)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_session_t cpSession;
    sss_key_store_t cpKs;
    sss_object_t extPubkey;
    sss_object_t derivedKey;
    sss_object_t keyPair;
    uint32_t keyId_extPubKey = 0x7D000010;
    uint32_t keyId_derivedKey = 0x7D000011;
    size_t field_size_bits = 0;
    size_t maxSharedSecretByteCount = 66;
    uint8_t shSecBuf[64] = {
        0,
    };
    size_t shSecBufLen = sizeof(shSecBuf);
    size_t shSecBufLen_Bits = sizeof(shSecBuf) * 8;
    sss_derive_key_t deriveKeyContext;
    sss_cipher_type_t cipherType = kSSS_CipherType_NONE;
    uint8_t pubKeyDerBuf[256];
    size_t pubKeyDerBufLen = sizeof(pubKeyDerBuf);

    EVP_PKEY *evp_private_key = NULL;
    EVP_PKEY *evp_otherparty_key = NULL;
    const ECX_KEY *ecx_private_key;
    const ECX_KEY *ecx_otherparty_key;
    unsigned char *private_key = NULL;
    unsigned char *otherparty_key = NULL;
    int private_key_len = 0;
    int otherparty_key_len = 0;

    U16 sw = 0;
    uint32_t private_keyId = 0;
    int ret = 0;

    if (key == NULL) {
        /* EmbSe_derive_key function is invoked twice.
         * Once for getting key length and second time for key derivation.
         * For the first time, key parameter is passed as NULL and we set the key length and success is returned.
         */
        if (nid == EVP_PKEY_X25519) {
            *keylen = 32;
        }
        else if (nid == EVP_PKEY_X448) {
            *keylen = 56;
        }
        status = kStatus_SSS_Success;
        goto exit;
    }

    evp_private_key = EVP_PKEY_CTX_get0_pkey(ctx);
    if (evp_private_key == NULL) {
        goto exit;
    }
    evp_otherparty_key = EVP_PKEY_CTX_get0_peerkey(ctx);
    if (evp_otherparty_key == NULL) {
        goto exit;
    }

    ecx_private_key = (const ECX_KEY *)EVP_PKEY_get0((const EVP_PKEY *)evp_private_key);
    if (ecx_private_key == NULL) {
        goto exit;
    }
    ecx_otherparty_key = (const ECX_KEY *)EVP_PKEY_get0((const EVP_PKEY *)evp_otherparty_key);
    if (ecx_otherparty_key == NULL) {
        goto exit;
    }

    private_key_len = EVP_PKEY_size(evp_private_key);
    if (private_key_len < 0) {
        goto exit;
    }

    otherparty_key_len = EVP_PKEY_size(evp_otherparty_key);
    if (otherparty_key_len < 0) {
        goto exit;
    }

    private_key = ecx_private_key->privkey;
    if (private_key == NULL) {
        goto exit;
    }
    otherparty_key = (unsigned char *)&(ecx_otherparty_key->pubkey);
    if (otherparty_key == NULL) {
        goto exit;
    }

    sw = getExKeyReference(private_key, private_key_len, &private_keyId);

    if (sw == SW_OK) {
        if (nid == EVP_PKEY_X25519) {
            memcpy(pubKeyDerBuf, x25519_header, sizeof(x25519_header));
            pubKeyDerBufLen = sizeof(x25519_header);
            memcpy(pubKeyDerBuf + pubKeyDerBufLen, otherparty_key, otherparty_key_len);
            pubKeyDerBufLen += otherparty_key_len;
            field_size_bits = 256;
            cipherType = kSSS_CipherType_EC_MONTGOMERY;
        }
        else if (nid == EVP_PKEY_X448) {
            memcpy(pubKeyDerBuf, x448_header, sizeof(x448_header));
            pubKeyDerBufLen = sizeof(x448_header);
            memcpy(pubKeyDerBuf + pubKeyDerBufLen, otherparty_key, otherparty_key_len);
            pubKeyDerBufLen += otherparty_key_len;
            field_size_bits = 448;
            cipherType = kSSS_CipherType_EC_MONTGOMERY;
        }
        else {
            goto exit;
        }

        EmbSe_Print(LOG_FLOW_ON,
            "SSS based (X-DH) compute_key (keyId=0x%08X, pubKeyLen=%zu, shSecBufLen=%li)\n",
            private_keyId,
            otherparty_key_len,
            *keylen);

// Create OpenSSL context & keystore on the fly
// This is used to contain the public key and the calculated shared secret
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
        status = sss_session_open(&cpSession, kType_SSS_OpenSSL, 0, kSSS_ConnectionType_Plain, ".");
        EMBSE_ENSURE_OR_GO_EXIT_WITH_MSG(status == kStatus_SSS_Success, "X-DH: OpenSSL session open failed.\n")
#elif SSS_HAVE_HOSTCRYPTO_MBEDTLS
        status = sss_session_open(&cpSession, kType_SSS_mbedTLS, 0, kSSS_ConnectionType_Plain, ".");
        EMBSE_ENSURE_OR_GO_EXIT_WITH_MSG(status == kStatus_SSS_Success, "X-DH: Mbedtls session open failed.\n")
#endif

        status = sss_key_store_context_init(&cpKs, &cpSession);
        EMBSE_ENSURE_OR_GO_EXIT_WITH_MSG(status == kStatus_SSS_Success, "X-DH: sss_key_store_context_init failed.\n")

        status = sss_key_store_allocate(&cpKs, __LINE__);
        EMBSE_ENSURE_OR_GO_EXIT_WITH_MSG(status == kStatus_SSS_Success, "X-DH: sss_key_store_allocate failed.\n")

        // Set Public Key
        status = sss_key_object_init(&extPubkey, &cpKs);
        EMBSE_ENSURE_OR_GO_EXIT_WITH_MSG(
            status == kStatus_SSS_Success, "X-DH: sss_key_object_init failed (extPubkey).\n")

        status = sss_key_object_allocate_handle(
            &extPubkey, keyId_extPubKey, kSSS_KeyPart_Public, cipherType, pubKeyDerBufLen, kKeyObject_Mode_Transient);
        EMBSE_ENSURE_OR_GO_EXIT_WITH_MSG(
            status == kStatus_SSS_Success, "X-DH: sss_key_object_allocate_handle failed (extPubkey).\n")

        EmbSe_PrintPayload(LOG_DBG_ON, otherparty_key, (U16)otherparty_key_len, "otherparty_key");
        status = sss_key_store_set_key(&cpKs, &extPubkey, pubKeyDerBuf, pubKeyDerBufLen, field_size_bits, NULL, 0);
        EMBSE_ENSURE_OR_GO_EXIT_WITH_MSG(
            status == kStatus_SSS_Success, "X-DH: sss_key_store_set_key failed (extPubkey).\n")

        // Shared secret (Symmetric Key)
        status = sss_key_object_init(&derivedKey, &cpKs);
        EMBSE_ENSURE_OR_GO_EXIT_WITH_MSG(status == kStatus_SSS_Success, "c: sss_key_object_init failed (derivedKey).\n")

        status = sss_key_object_allocate_handle(&derivedKey,
            keyId_derivedKey,
            kSSS_KeyPart_Default,
            kSSS_CipherType_AES,
            maxSharedSecretByteCount,
            kKeyObject_Mode_Transient);
        EMBSE_ENSURE_OR_GO_EXIT_WITH_MSG(
            status == kStatus_SSS_Success, "X-DH: sss_key_object_allocate_handle failed (derivedKey).\n")

        // Keypair stored in secure element
        status = sss_key_object_init(&keyPair, &gpCtx->ks);
        EMBSE_ENSURE_OR_GO_EXIT_WITH_MSG(
            status == kStatus_SSS_Success, "ECDH: sss_key_object_init for keyPair failed\n")

        status = sss_key_object_get_handle(&keyPair, private_keyId);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "ECDH: sss_key_object_get_handle for pubKey failed\n");
            sss_key_object_free(&keyPair);
            goto exit;
        }

        status = sss_derive_key_context_init(
            &deriveKeyContext, &gpCtx->session, &keyPair, kAlgorithm_SSS_ECDH, kMode_SSS_ComputeSharedSecret);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "ECDH: sss_derive_key_context_init for kMode_SSS_ComputeSharedSecret failed\n");
            sss_key_object_free(&keyPair);
            goto exit;
        }

        EmbSe_Print(LOG_FLOW_ON, " After sss_derive_key_context_init.\n");

        status = sss_derive_key_dh(&deriveKeyContext, &extPubkey, &derivedKey);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "ECDH: sss_derive_key_dh failed\n");
            sss_key_object_free(&keyPair);
            goto exit;
        }

        // Retrieve the shared secret into shSecBuf
        status = sss_key_store_get_key(&cpKs, &derivedKey, shSecBuf, &shSecBufLen, &shSecBufLen_Bits);
        EMBSE_ENSURE_OR_GO_EXIT_WITH_MSG(status == kStatus_SSS_Success, "ECDH: sss_key_store_get_key failed.\n")

        if (key != NULL) {
            memcpy(key, shSecBuf, shSecBufLen);
            *keylen = shSecBufLen;
        }

        // What did we get? Don't print this to console!
        // EmbSe_Print(LOG_DBG_ON, "ECDH: shSecBufLen_Bits=%d\n", shSecBufLen_Bits);
        // EmbSe_PrintPayload(LOG_DBG_ON, shSecBuf, shSecBufLen, "shSecBuf");
    }
    else if (sw == ERR_NO_PRIVATE_KEY) {
        EmbSe_Print(LOG_ERR_ON, "Expecting private key (by value or reference): 0x%04X.\n", sw);
        goto exit;
    }
    else if (sw == ERR_PATTERN_COMPARE_FAILED) {
        /* software rollback */
        int (*openssl_derive_dh_key)(EVP_PKEY_CTX *, unsigned char *, size_t *) = NULL;

        if (nid == EVP_PKEY_X25519) {
            EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)default_x25519_pmethods, NULL, &openssl_derive_dh_key);
        }
        else if (nid == EVP_PKEY_X448) {
            EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)default_x448_pmethods, NULL, &openssl_derive_dh_key);
        }

        if (openssl_derive_dh_key == NULL) {
            EmbSe_Print(LOG_ERR_ON, "Error in getting default impl for derive method ");
            goto exit;
        }

        ret = (*openssl_derive_dh_key)(ctx, key, keylen);
        if (ret != 1) {
            EmbSe_Print(LOG_ERR_ON, "Error in sw roolback for x25519 derive dh key");
            goto exit;
        }
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

static int EmbSe_x448_derive_key(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
    sss_status_t status = kStatus_SSS_Fail;

    status = EmbSe_derive_key(ctx, key, keylen, EVP_PKEY_X448);
    if (status != kStatus_SSS_Success) {
        return 0;
    }
    return 1;
}

static int EmbSe_x25519_derive_key(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
    sss_status_t status = kStatus_SSS_Fail;

    status = EmbSe_derive_key(ctx, key, keylen, EVP_PKEY_X25519);
    if (status != kStatus_SSS_Success) {
        return 0;
    }
    return 1;
}

static int EmbSe_x_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    AX_UNUSED_ARG(ctx);
    AX_UNUSED_ARG(p1);
    AX_UNUSED_ARG(p2);
    if (type == EVP_PKEY_CTRL_PEER_KEY) {
        return 1;
    }
    return -2;
}

EVP_PKEY_METHOD *EmbSe_assign_x25519_pkey_meth(void)
{
    if (sss_x25519_pmeth) {
        return sss_x25519_pmeth;
    }

    /* Will be used for rollback operations */
    default_x25519_pmethods = EVP_PKEY_meth_find(EVP_PKEY_X25519);
    if (default_x25519_pmethods == NULL) {
        EmbSe_Print(LOG_ERR_ON, "Error in EmbSe_assign_x25519_pkey_meth \n");
        return NULL;
    }

    sss_x25519_pmeth = EVP_PKEY_meth_new(EVP_PKEY_X25519, 0);
    if (sss_x25519_pmeth == NULL) {
        EmbSe_Print(LOG_ERR_ON, "Error in EmbSe_assign_x25519_pkey_meth \n");
        return NULL;
    }

    EVP_PKEY_meth_copy(sss_x25519_pmeth, default_x25519_pmethods);
    EVP_PKEY_meth_set_derive(sss_x25519_pmeth, NULL, EmbSe_x25519_derive_key);
    EVP_PKEY_meth_set_ctrl(sss_x25519_pmeth, EmbSe_x_ctrl, NULL);

    return sss_x25519_pmeth;
}

EVP_PKEY_METHOD *EmbSe_assign_x448_pkey_meth(void)
{
    if (sss_x448_pmeth) {
        return sss_x448_pmeth;
    }

    /* Will be used for rollback operations */
    default_x448_pmethods = EVP_PKEY_meth_find(EVP_PKEY_X448);
    if (default_x448_pmethods == NULL) {
        EmbSe_Print(LOG_ERR_ON, "Error in EmbSe_assign_x448_pkey_meth \n");
        return NULL;
    }

    sss_x448_pmeth = EVP_PKEY_meth_new(EVP_PKEY_X448, 0);
    if (sss_x448_pmeth == NULL) {
        EmbSe_Print(LOG_ERR_ON, "Error in EmbSe_assign_x448_pkey_meth \n");
        return NULL;
    }

    EVP_PKEY_meth_copy(sss_x448_pmeth, default_x448_pmethods);
    EVP_PKEY_meth_set_derive(sss_x448_pmeth, NULL, EmbSe_x448_derive_key);
    EVP_PKEY_meth_set_ctrl(sss_x448_pmeth, EmbSe_x_ctrl, NULL);

    return sss_x448_pmeth;
}

static EVP_PKEY_METHOD *EmbSe_assign_pkey_meth(int nid)
{
    switch (nid) {
    case EVP_PKEY_X25519:
        return EmbSe_assign_x25519_pkey_meth();
    case EVP_PKEY_X448:
        return EmbSe_assign_x448_pkey_meth();
    default:
        return NULL;
    }
}
int setup_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pkey_meth, const int **nid_list, int nid)
{
    AX_UNUSED_ARG(e);
    int i;
    if (pkey_meth == NULL) {
        *nid_list = supported_nid;
        return supported_nid_cnt;
    }

    for (i = 0; i < supported_nid_cnt; i++) {
        if (nid == supported_nid[i]) {
            *pkey_meth = EmbSe_assign_pkey_meth(nid);
            return 1;
        }
    }

    EmbSe_Print(LOG_ERR_ON, "Nid not supported in openssl engine \n");
    *pkey_meth = NULL;
    return 0;
}

#endif //#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#endif //#if SSS_HAVE_ECC
