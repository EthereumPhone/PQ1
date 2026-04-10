/**
 * @file ax_sssEngine_rsa.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2018,2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Engine for NXP Embedded Secure Element over SSS API's
 *
 * RSA specific implementation
 *
 * @note
 *   Compatible with:
 *   - OpenSSL 1.0.2
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

#if SSS_HAVE_RSA || (SSS_HAVE_APPLET_NONE && (SSS_HAVE_HOSTCRYPTO_OPENSSL || SSS_HAVE_HOSTCRYPTO_MBEDTLS))

#include <ex_sss.h>
#include <stdlib.h>
//#include <malloc.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "ax_api.h"
#include "ax_embSeEngine.h"
#include "ax_embSeEngine_Internal.h"
#include "fsl_sss_api.h"
#include "nxLog_sss.h"
#include "sm_printf.h"

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
RSA_METHOD *EmbSe_RSA = NULL;
#endif
RSA_METHOD *EmbSe_default_RSA = NULL;

sss_algorithm_t getSignAlgorithmfromSHAtype(int type)
{
    sss_algorithm_t algo = kAlgorithm_None;
    switch (type) {
    case NID_sha1:
        algo = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1;
        break;
    case NID_sha224:
        algo = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224;
        break;
    case NID_sha256:
        algo = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
        break;
    case NID_sha384:
        algo = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384;
        break;
    case NID_sha512:
        algo = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512;
        break;
    default:
        break;
    }
    return algo;
}

sss_algorithm_t getEncryptAlgorithmfromPaddingType(int padding, int bit_length)
{
    sss_algorithm_t algo = kAlgorithm_None;
    switch (padding) {
    case RSA_PKCS1_PADDING: {
        algo = kAlgorithm_SSS_RSAES_PKCS1_V1_5;
        break;
    }
    case RSA_NO_PADDING: {
        algo = kAlgorithm_SSS_RSASSA_NO_PADDING;
    } break;
    case RSA_SSLV23_PADDING: {
        algo = kAlgorithm_None;
    } break;
    case RSA_PKCS1_OAEP_PADDING: {
        switch (bit_length) {
        case 1024:
        case 2048:
        case 3072:
        case 4096:
            algo = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1;
            break;
        default:
            LOG_E("Invalid bit_length");
        }
        break;
    }
    default:
        break;
    }
    return algo;
}

static int EmbSe_RSA_Sign(int dtype,
    const unsigned char *m,
    unsigned int m_length,
    unsigned char *sigret,
    unsigned int *siglen,
    const RSA *rsa)
{
    BN_ULONG Ident = 0xFF;
    BN_ULONG keyId = 0xFF;
    BN_ULONG Coeff = 0xFF;
    int ret = 1;
    RSA *dup_rsakey = NULL;
    sss_object_t keyPair = {
        0,
    };

    sss_status_t status = kStatus_SSS_Success;
    sss_asymmetric_t asymm = {
        0,
    };
    sss_algorithm_t algorithm = 0;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    const BIGNUM *dmp = NULL;
    const BIGNUM *dmq = NULL;
    const BIGNUM *iqmp = NULL;
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if ((rsa != NULL) && (rsa->iqmp != NULL)) {
        Ident = BN_get_word(rsa->p);
        keyId = BN_get_word(rsa->q);
        Coeff = BN_get_word(rsa->iqmp);
    }
#else
    if (rsa != NULL) {
        RSA_get0_factors(rsa, &dmp, &dmq);
        RSA_get0_crt_params(rsa, NULL, NULL, &iqmp);

        if (dmp != NULL) {
            Ident = BN_get_word(dmp);
        }
        if (dmq != NULL) {
            keyId = BN_get_word(dmq);
        }
        if (iqmp != NULL) {
            Coeff = BN_get_word(iqmp);
        }
    }
#endif

    EmbSe_Print(LOG_DBG_ON, "EmbSe: EmbSe_RSA_Sign invoked KeyIdent=%x, KeyId=%x, Coeff=0x%x\n", Ident, keyId, Coeff);

    // if not our ref key
    if (Coeff != EMBSE_REFKEY_ID) {
        EmbSe_Print(LOG_FLOW_ON, "EmbSe: Not our SE key\n");

        dup_rsakey = RSAPrivateKey_dup((RSA *)rsa);
        RSA_set_method(dup_rsakey, RSA_get_default_method());
        ret = RSA_sign(dtype, m, m_length, sigret, siglen, dup_rsakey);

        if (ret == 1) {
            EmbSe_Print(LOG_DBG_ON, "EmbSe: Sign PASS\n");
        }
        else {
            EmbSe_Print(LOG_DBG_ON, "EmbSe: Sign FAIL\n");
        }
    }
    else {
        status = sss_key_object_init(&keyPair, &gpCtx->ks);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        algorithm = getSignAlgorithmfromSHAtype(dtype);
        if (kAlgorithm_None == algorithm) {
            EmbSe_Print(LOG_ERR_ON, "type not supported for sign \n");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        if (keyId > UINT32_MAX) {
            EmbSe_Print(LOG_ERR_ON, "unsupported keyId value\n");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        status = sss_key_object_get_handle(&keyPair, keyId);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_asymmetric_context_init(&asymm, &gpCtx->session, &keyPair, algorithm, kMode_SSS_Sign);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        EmbSe_Print(LOG_FLOW_ON, "EmbSe: Invoking sss_asymmetric_sign_digest \n");
        size_t szSigLen = 512;
        status = sss_asymmetric_sign_digest(&asymm, (uint8_t *)m, m_length, sigret, &szSigLen);
        *siglen = szSigLen;

        sss_asymmetric_context_free(&asymm);
    }

exit:
    if (keyPair.keyStore != NULL) {
        sss_key_object_free(&keyPair);
    }

    if (dup_rsakey != NULL) {
        RSA_free(dup_rsakey);
    }

    if (status != kStatus_SSS_Success) {
        ret = -1;
    }

    return ret;
}

static int EmbSe_RSA_Verify(int dtype,
    const unsigned char *m,
    unsigned int m_length,
    const unsigned char *sigbuf,
    unsigned int siglen,
    const RSA *rsa)

{
    BN_ULONG Ident = 0xFF;
    BN_ULONG keyId = 0xFF;
    BN_ULONG Coeff = 0xFF;
    int ret = 1;
    sss_status_t status = kStatus_SSS_Success;
    sss_asymmetric_t asymm = {
        0,
    };
    sss_algorithm_t algorithm = 0;
    RSA *dup_rsakey = NULL;
    sss_object_t keyObject = {
        0,
    };

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    const BIGNUM *dmp = NULL;
    const BIGNUM *dmq = NULL;
    const BIGNUM *iqmp = NULL;
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if ((rsa != NULL) && (rsa->iqmp != NULL)) {
        Ident = BN_get_word(rsa->p);
        keyId = BN_get_word(rsa->q);
        Coeff = BN_get_word(rsa->iqmp);
    }
#else
    if (rsa != NULL) {
        RSA_get0_factors(rsa, &dmp, &dmq);
        RSA_get0_crt_params(rsa, NULL, NULL, &iqmp);
        if (dmp != NULL) {
            Ident = BN_get_word(dmp);
        }
        if (dmq != NULL) {
            keyId = BN_get_word(dmq);
        }
        if (iqmp != NULL) {
            Coeff = BN_get_word(iqmp);
        }
    }
#endif
    EmbSe_Print(LOG_DBG_ON, "EmbSe: EmbSe_RSA_Verify invoked KeyIdent=%x, KeyId=%x, Coeff=0x%x\n", Ident, keyId, Coeff);

    if (Coeff != EMBSE_REFKEY_ID) {
        EmbSe_Print(LOG_FLOW_ON, "EmbSe: Not our SE key\n");

        dup_rsakey = RSAPublicKey_dup((RSA *)rsa);
        RSA_set_method(dup_rsakey, RSA_get_default_method());
        ret = RSA_verify(dtype, m, m_length, sigbuf, siglen, dup_rsakey);

        if (ret == 1) {
            EmbSe_Print(LOG_DBG_ON, "EmbSe: Verification PASS\n");
        }
        else {
            EmbSe_Print(LOG_DBG_ON, "EmbSe: Verification FAIL\n");
        }
    }
    else {
        status = sss_key_object_init(&keyObject, &gpCtx->ks);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        algorithm = getSignAlgorithmfromSHAtype(dtype);
        if (kAlgorithm_None == algorithm) {
            EmbSe_Print(LOG_ERR_ON, "type not supported for sign \n");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        if (keyId > UINT32_MAX) {
            EmbSe_Print(LOG_ERR_ON, "unsupported keyId value\n");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        status = sss_key_object_get_handle(&keyObject, keyId);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_asymmetric_context_init(&asymm, &gpCtx->session, &keyObject, algorithm, kMode_SSS_Verify);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        EmbSe_Print(LOG_FLOW_ON, "EmbSe: Invoking sss_asymmetric_verify_digest \n");
        status = sss_asymmetric_verify_digest(&asymm, (uint8_t *)m, m_length, (uint8_t *)sigbuf, siglen);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_DBG_ON, "Verification failed \n");
        }

        sss_asymmetric_context_free(&asymm);
    }

exit:
    if (keyObject.keyStore != NULL) {
        sss_key_object_free(&keyObject);
    }

    if (dup_rsakey != NULL) {
        RSA_free(dup_rsakey);
    }

    if (status != kStatus_SSS_Success) {
        ret = -1;
    }

    return ret;
}

static int EmbSe_RSA_Pub_Decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    BN_ULONG Ident = 0xFF;
    BN_ULONG keyId = 0xFF;
    BN_ULONG Coeff = 0xFF;
    int ret = 0;
    sss_status_t status = kStatus_SSS_Success;
    sss_asymmetric_t asymm = {
        0,
    };
    size_t destLen = 512;
    sss_algorithm_t algorithm = 0;
    sss_object_t keyObject = {
        0,
    };

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    const BIGNUM *dmp = NULL;
    const BIGNUM *dmq = NULL;
    const BIGNUM *iqmp = NULL;
    RSA *dup_rsakey = NULL;
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if ((rsa != NULL) && (rsa->iqmp != NULL)) {
        Ident = BN_get_word(rsa->p);
        keyId = BN_get_word(rsa->q);
        Coeff = BN_get_word(rsa->iqmp);
    }
#else
    if (rsa != NULL) {
        RSA_get0_factors(rsa, &dmp, &dmq);
        RSA_get0_crt_params(rsa, NULL, NULL, &iqmp);
        if (dmp != NULL) {
            Ident = BN_get_word(dmp);
        }
        if (dmq != NULL) {
            keyId = BN_get_word(dmq);
        }
        if (iqmp != NULL) {
            Coeff = BN_get_word(iqmp);
        }
    }
#endif

    EmbSe_Print(
        LOG_DBG_ON, "EmbSe: EmbSe_RSA_Pub_Decrypt invoked KeyIdent=%x, KeyId=%x, Coeff=0x%x\n", Ident, keyId, Coeff);

    if (Coeff != EMBSE_REFKEY_ID) {
        EmbSe_Print(LOG_FLOW_ON, "EmbSe: Not our SE key\n");
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        if ((EmbSe_default_RSA != NULL) && (EmbSe_default_RSA->rsa_priv_dec != NULL)) {
            EmbSe_Print(LOG_FLOW_ON, "EmbSe: Invoking Software rsa_pub_dec\n");
            ret = EmbSe_default_RSA->rsa_pub_dec(flen, from, to, rsa, padding);
        }
        else {
            ret = -1;
        }
#else
        dup_rsakey = RSAPublicKey_dup(rsa);
        RSA_set_method(dup_rsakey, RSA_get_default_method());
        ret = RSA_public_decrypt(flen, from, to, dup_rsakey, padding);
#endif
        goto exit;
    }
    else {
        if (padding != RSA_NO_PADDING) {
            EmbSe_Print(
                LOG_ERR_ON, "EmbSe: EmbSe_RSA_Pub_Decrypt. Padding %d not supported for private decrypt\n", padding);
            ret = -1;
            goto exit;
        }

        status = sss_key_object_init(&keyObject, &gpCtx->ks);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        algorithm = getEncryptAlgorithmfromPaddingType(padding, RSA_size(rsa) * 8);
        if (kAlgorithm_None == algorithm) {
            EmbSe_Print(LOG_ERR_ON, "type not supported for encrypt\n");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        if (keyId > UINT32_MAX) {
            EmbSe_Print(LOG_ERR_ON, "unsupported keyId value\n");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        status = sss_key_object_get_handle(&keyObject, keyId);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_asymmetric_context_init(&asymm, &gpCtx->session, &keyObject, algorithm, kMode_SSS_Encrypt);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        EmbSe_Print(LOG_FLOW_ON, "EmbSe: Invoking sss_asymmetric_encrypt \n");
        status = sss_asymmetric_encrypt(&asymm, from, flen, to, &destLen);

        ret = destLen;
        sss_asymmetric_context_free(&asymm);
    }

exit:
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    if (dup_rsakey != NULL) {
        RSA_free(dup_rsakey);
    }
#endif

    if (status != kStatus_SSS_Success) {
        ret = -1;
    }

    return ret;
}

static int EmbSe_RSA_Priv_Decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    BN_ULONG Ident = 0xFF;
    BN_ULONG keyId = 0xFF;
    BN_ULONG Coeff = 0xFF;
    int ret = 0;
    sss_status_t status = kStatus_SSS_Success;
    size_t destLen = 512;
    sss_asymmetric_t asymm = {
        0,
    };
    sss_algorithm_t algorithm = 0;
    sss_object_t keyPair = {
        0,
    };

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    const BIGNUM *dmp = NULL;
    const BIGNUM *dmq = NULL;
    const BIGNUM *iqmp = NULL;
    RSA *dup_rsakey = NULL;
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if ((rsa != NULL) && (rsa->iqmp != NULL)) {
        Ident = BN_get_word(rsa->p);
        keyId = BN_get_word(rsa->q);
        Coeff = BN_get_word(rsa->iqmp);
    }
#else
    if (rsa != NULL) {
        RSA_get0_factors(rsa, &dmp, &dmq);
        RSA_get0_crt_params(rsa, NULL, NULL, &iqmp);
        if (dmp != NULL) {
            Ident = BN_get_word(dmp);
        }
        if (dmq != NULL) {
            keyId = BN_get_word(dmq);
        }
        if (iqmp != NULL) {
            Coeff = BN_get_word(iqmp);
        }
    }
#endif

    EmbSe_Print(
        LOG_DBG_ON, "EmbSe: EmbSe_RSA_Priv_Decrypt invoked KeyIdent=%x, KeyId=%x, Coeff=0x%x\n", Ident, keyId, Coeff);

    if (Coeff != EMBSE_REFKEY_ID) {
        EmbSe_Print(LOG_FLOW_ON, "EmbSe: Not our SE key\n");
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        if ((EmbSe_default_RSA != NULL) && (EmbSe_default_RSA->rsa_priv_dec != NULL)) {
            EmbSe_Print(LOG_FLOW_ON, "EmbSe: Invoking Software rsa_priv_dec\n");
            ret = EmbSe_default_RSA->rsa_priv_dec(flen, from, to, rsa, padding);
        }
        else {
            ret = -1;
        }
#else
        dup_rsakey = RSAPrivateKey_dup(rsa);
        RSA_set_method(dup_rsakey, RSA_get_default_method());
        ret = RSA_private_decrypt(flen, from, to, dup_rsakey, padding);
#endif
        goto exit;
    }
    else {
        status = sss_key_object_init(&keyPair, &gpCtx->ks);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        algorithm = getEncryptAlgorithmfromPaddingType(padding, RSA_size(rsa) * 8);
        if (kAlgorithm_None == algorithm) {
            EmbSe_Print(LOG_ERR_ON, "type not supported for decrypt\n");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        if (keyId > UINT32_MAX) {
            EmbSe_Print(LOG_ERR_ON, "unsupported keyId value\n");
            status = kStatus_SSS_Fail;
            goto exit;
        }
        status = sss_key_object_get_handle(&keyPair, keyId);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_asymmetric_context_init(&asymm, &gpCtx->session, &keyPair, algorithm, kMode_SSS_Decrypt);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        EmbSe_Print(LOG_FLOW_ON, "EmbSe: Invoking sss_asymmetric_decrypt \n");
        status = sss_asymmetric_decrypt(&asymm, from, flen, to, &destLen);

        ret = destLen;
        sss_asymmetric_context_free(&asymm);
    }

exit:
    if (keyPair.keyStore != NULL) {
        sss_key_object_free(&keyPair);
    }

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    if (dup_rsakey != NULL) {
        RSA_free(dup_rsakey);
    }
#endif

    if (status != kStatus_SSS_Success) {
        ret = -1;
    }

    return ret;
}

static int EmbSe_RSA_Pub_Encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    BN_ULONG Ident = 0xFF;
    BN_ULONG keyId = 0xFF;
    BN_ULONG Coeff = 0xFF;
    sss_status_t status = kStatus_SSS_Success;
    sss_asymmetric_t asymm = {
        0,
    };
    size_t destLen = 512;
    int ret = 0;
    sss_algorithm_t algorithm = 0;
    sss_object_t keyObject = {
        0,
    };

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    const BIGNUM *dmp = NULL;
    const BIGNUM *dmq = NULL;
    const BIGNUM *iqmp = NULL;
    RSA *dup_rsakey = NULL;
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if ((rsa != NULL) && (rsa->iqmp != NULL)) {
        Ident = BN_get_word(rsa->p);
        keyId = BN_get_word(rsa->q);
        Coeff = BN_get_word(rsa->iqmp);
    }
#else
    if (rsa != NULL) {
        RSA_get0_factors(rsa, &dmp, &dmq);
        RSA_get0_crt_params(rsa, NULL, NULL, &iqmp);
        if (dmp != NULL) {
            Ident = BN_get_word(dmp);
        }
        if (dmq != NULL) {
            keyId = BN_get_word(dmq);
        }
        if (iqmp != NULL) {
            Coeff = BN_get_word(iqmp);
        }
    }
#endif

    EmbSe_Print(
        LOG_DBG_ON, "EmbSe: EmbSe_RSA_Pub_Encrypt invoked KeyIdent=%x, KeyId=%x, Coeff=0x%x\n", Ident, keyId, Coeff);

    if (Coeff != EMBSE_REFKEY_ID) {
        EmbSe_Print(LOG_FLOW_ON, "EmbSe: Not our SE key\n");
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        if ((EmbSe_default_RSA != NULL) && (EmbSe_default_RSA->rsa_pub_enc != NULL)) {
            EmbSe_Print(LOG_FLOW_ON, "EmbSe: Invoking OpenSSL rsa_pub_enc\n");
            ret = EmbSe_default_RSA->rsa_pub_enc(flen, from, to, rsa, padding);
        }
        else {
            ret = -1;
        }
#else
        dup_rsakey = RSAPublicKey_dup(rsa);
        RSA_set_method(dup_rsakey, RSA_get_default_method());
        ret = RSA_public_encrypt(flen, from, to, dup_rsakey, padding);
#endif
        goto exit;
    }
    else {
        status = sss_key_object_init(&keyObject, &gpCtx->ks);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        algorithm = getEncryptAlgorithmfromPaddingType(padding, RSA_size(rsa) * 8);
        if (kAlgorithm_None == algorithm) {
            EmbSe_Print(LOG_ERR_ON, "type not supported for encrypt\n");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        if (keyId > UINT32_MAX) {
            EmbSe_Print(LOG_ERR_ON, "unsupported keyId value\n");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        status = sss_key_object_get_handle(&keyObject, keyId);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_asymmetric_context_init(&asymm, &gpCtx->session, &keyObject, algorithm, kMode_SSS_Encrypt);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        EmbSe_Print(LOG_FLOW_ON, "EmbSe: Invoking sss_asymmetric_encrypt \n");
        status = sss_asymmetric_encrypt(&asymm, from, flen, to, &destLen);

        ret = destLen;
        sss_asymmetric_context_free(&asymm);
    }

exit:
    if (keyObject.keyStore != NULL) {
        sss_key_object_free(&keyObject);
    }

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    if (dup_rsakey != NULL) {
        RSA_free(dup_rsakey);
    }
#endif

    if (status != kStatus_SSS_Success) {
        ret = -1;
    }

    return ret;
}

static int EmbSe_RSA_Priv_Encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    BN_ULONG Ident = 0xFF;
    BN_ULONG keyId = 0xFF;
    BN_ULONG Coeff = 0xFF;
    int ret = 0;
    sss_status_t status = kStatus_SSS_Success;
    size_t destLen = 512;
    sss_asymmetric_t asymm = {
        0,
    };
    sss_algorithm_t algorithm = 0;
    sss_object_t keyObject = {
        0,
    };

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    const BIGNUM *dmp = NULL;
    const BIGNUM *dmq = NULL;
    const BIGNUM *iqmp = NULL;
    RSA *dup_rsakey = NULL;
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if ((rsa != NULL) && (rsa->iqmp != NULL)) {
        Ident = BN_get_word(rsa->p);
        keyId = BN_get_word(rsa->q);
        Coeff = BN_get_word(rsa->iqmp);
    }
#else
    if (rsa != NULL) {
        RSA_get0_factors(rsa, &dmp, &dmq);
        RSA_get0_crt_params(rsa, NULL, NULL, &iqmp);
        if (dmp != NULL) {
            Ident = BN_get_word(dmp);
        }
        if (dmq != NULL) {
            keyId = BN_get_word(dmq);
        }
        if (iqmp != NULL) {
            Coeff = BN_get_word(iqmp);
        }
    }
#endif

    EmbSe_Print(
        LOG_DBG_ON, "EmbSe: EmbSe_RSA_Priv_Encrypt invoked KeyIdent=%x, KeyId=%x, Coeff=0x%x\n", Ident, keyId, Coeff);
    EmbSe_Print(LOG_DBG_ON, "EmbSe: EmbSe_RSA_Priv_Encrypt. Requested padding = %d\n", padding);

    if (Coeff != EMBSE_REFKEY_ID) {
        EmbSe_Print(LOG_FLOW_ON, "EmbSe: Not our SE key\n");
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        if ((EmbSe_default_RSA != NULL) && (EmbSe_default_RSA->rsa_pub_enc != NULL)) {
            EmbSe_Print(LOG_FLOW_ON, "EmbSe: Invoking OpenSSL rsa_prv_enc\n");
            ret = EmbSe_default_RSA->rsa_priv_enc(flen, from, to, rsa, padding);
        }
        else {
            ret = -1;
        }
#else
        dup_rsakey = RSAPrivateKey_dup(rsa);
        RSA_set_method(dup_rsakey, RSA_get_default_method());
        ret = RSA_private_encrypt(flen, from, to, dup_rsakey, padding);
#endif
        goto exit;
    }
    else {
        if (padding != RSA_NO_PADDING) {
            EmbSe_Print(
                LOG_ERR_ON, "EmbSe: EmbSe_RSA_Priv_Encrypt. Padding %d not supported for private encrypt\n", padding);
            ret = -1;
            goto exit;
        }

        status = sss_key_object_init(&keyObject, &gpCtx->ks);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        algorithm = getEncryptAlgorithmfromPaddingType(padding, RSA_size(rsa) * 8);
        if (kAlgorithm_None == algorithm) {
            EmbSe_Print(LOG_ERR_ON, "type not supported for decrypt\n");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        if (keyId > UINT32_MAX) {
            EmbSe_Print(LOG_ERR_ON, "unsupported keyId value\n");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        status = sss_key_object_get_handle(&keyObject, keyId);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_asymmetric_context_init(&asymm, &gpCtx->session, &keyObject, algorithm, kMode_SSS_Decrypt);
        EMBSE_ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        EmbSe_Print(LOG_FLOW_ON, "EmbSe: Invoking sss_asymmetric_decrypt \n");
        status = sss_asymmetric_decrypt(&asymm, from, flen, to, &destLen);

        ret = destLen;
        sss_asymmetric_context_free(&asymm);
    }

exit:
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    if (dup_rsakey != NULL) {
        RSA_free(dup_rsakey);
    }
#endif

    if (status != kStatus_SSS_Success) {
        ret = -1;
    }

    return ret;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
RSA_METHOD EmbSe_RSA = {
    "e2se_rsa",
    EmbSe_RSA_Pub_Encrypt,  /*rsa_pub_enc*/
    EmbSe_RSA_Pub_Decrypt,  /*rsa_pub_dec*/
    EmbSe_RSA_Priv_Encrypt, /*rsa_priv_enc*/
    EmbSe_RSA_Priv_Decrypt, /*rsa_priv_dec*/
    NULL,                   // Invokes O'ssl API.See  bind_helper()      /*rsa_mod_exp*/
    NULL,                   // Invokes O'ssl API.See  bind_helper()      /*bn_mod_exp*/
    NULL,                   /*init*/
    NULL,                   /*finish*/
    RSA_FLAG_SIGN_VER,      /*flags*/
    NULL,                   /*app_data*/
    EmbSe_RSA_Sign,         /*rsa_sign*/
    EmbSe_RSA_Verify,       /*rsa_verify*/
    NULL,                   /*rsa_keygen*/
};
#else

int setup_rsa_key_method(void)
{
    EmbSe_RSA = RSA_meth_new("e2se_rsa", 0);

    if (EmbSe_RSA == NULL) {
        return 0;
    }

    RSA_meth_set_pub_enc(EmbSe_RSA, &EmbSe_RSA_Pub_Encrypt);
    RSA_meth_set_pub_dec(EmbSe_RSA, &EmbSe_RSA_Pub_Decrypt);
    RSA_meth_set_priv_enc(EmbSe_RSA, &EmbSe_RSA_Priv_Encrypt);
    RSA_meth_set_priv_dec(EmbSe_RSA, &EmbSe_RSA_Priv_Decrypt);
    RSA_meth_set_sign(EmbSe_RSA, &EmbSe_RSA_Sign);
    RSA_meth_set_verify(EmbSe_RSA, &EmbSe_RSA_Verify);

    return 1;
}
#endif

#endif //#if SSS_HAVE_RSA || (SSS_HAVE_APPLET_NONE && (SSS_HAVE_HOSTCRYPTO_OPENSSL || SSS_HAVE_HOSTCRYPTO_MBEDTLS))
