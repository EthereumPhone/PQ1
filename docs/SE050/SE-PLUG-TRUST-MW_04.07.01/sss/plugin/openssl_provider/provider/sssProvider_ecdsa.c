/**
 * @file sssProvider_ecdsa.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022,2024-2025 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for ECDSA using SSS API's
 *
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_ECC

/* ********************** Include files ********************** */
#include "sssProvider_main.h"
#include <openssl/core_names.h>
#include <string.h>

/* ********************** Constants ************************** */
#define MAX_DIGEST_INPUT_DATA 512

/* ********************** structure definition *************** */
typedef struct
{
    sss_algorithm_t sha_algorithm;
    uint8_t digest[64]; /* MAX SHA512 */
    size_t digestLen;
    sss_provider_store_obj_t *pStoreObjCtx;
    sss_provider_context_t *pProvCtx;
    sss_digest_t digestCtx;
    uint8_t digestInit;
} sss_provider_ecdsa_ctx_st;

/* ********************** Private funtions ******************* */

static void *sss_ecdsa_signature_newctx(void *provctx, const char *propq)
{
    sss_provider_ecdsa_ctx_st *pEcdsaCtx = OPENSSL_zalloc(sizeof(sss_provider_ecdsa_ctx_st));
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(propq);
    if (pEcdsaCtx != NULL) {
        pEcdsaCtx->pProvCtx = provctx;
    }
    return pEcdsaCtx;
}

static void sss_ecdsa_signature_freectx(void *ctx)
{
    sss_provider_ecdsa_ctx_st *sctx = ctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (sctx != NULL) {
        OPENSSL_clear_free(sctx, sizeof(sss_provider_ecdsa_ctx_st));
    }
    return;
}

static void *sss_ecdsa_signature_dupctx(void *ctx)
{
    sss_provider_ecdsa_ctx_st *pEcdsaCtx    = (sss_provider_ecdsa_ctx_st *)ctx;
    sss_provider_ecdsa_ctx_st *pEcdsaDupCtx = NULL;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(pEcdsaCtx != NULL);

    pEcdsaDupCtx = OPENSSL_zalloc(sizeof(sss_provider_ecdsa_ctx_st));
    ENSURE_OR_GO_CLEANUP(pEcdsaDupCtx != NULL);

    pEcdsaDupCtx->digestLen = pEcdsaCtx->digestLen;
    if (pEcdsaCtx->digestLen > 0) {
        memcpy(pEcdsaDupCtx->digest, pEcdsaCtx->digest, pEcdsaCtx->digestLen);
    }
    pEcdsaDupCtx->pProvCtx      = pEcdsaCtx->pProvCtx;
    pEcdsaDupCtx->pStoreObjCtx  = pEcdsaCtx->pStoreObjCtx;
    pEcdsaDupCtx->sha_algorithm = pEcdsaCtx->sha_algorithm;
    memcpy(&pEcdsaDupCtx->digestCtx, &pEcdsaCtx->digestCtx, sizeof(pEcdsaCtx->digestCtx));

cleanup:
    return pEcdsaDupCtx;
}

static int sss_ecdsa_sign_verify_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    int ret                              = 0;
    sss_provider_ecdsa_ctx_st *pEcdsaCtx = (sss_provider_ecdsa_ctx_st *)ctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(params);
    ENSURE_OR_GO_CLEANUP(pEcdsaCtx != NULL);
    pEcdsaCtx->pStoreObjCtx = provkey;
    ret                     = 1;
cleanup:
    return ret;
}

static int sss_ecdsa_set_sha_algo(size_t tbslen, sss_provider_ecdsa_ctx_st *pEcdsaCtx)
{
    switch (tbslen) {
    case 20: {
        pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA1;
        break;
    }
    case 28: {
        pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA224;
        break;
    }
    case 32: {
        pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA256;
        break;
    }
    case 48: {
        pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA384;
        break;
    }
    case 64: {
        pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA512;
        break;
    }
    default: {
        sssProv_Print(LOG_DBG_ON, "data length is not supported \n");
        return 0;
    }
    }
    return 1;
}

static int sss_ecdsa_signature_sign(
    void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    sss_provider_ecdsa_ctx_st *pEcdsaCtx = (sss_provider_ecdsa_ctx_st *)ctx;
    int ret                              = 0;
    sss_status_t status;
    sss_asymmetric_t asymmCtx = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;
    const EVP_MD *md     = NULL;
    int maxSize          = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(sigsize);

    ENSURE_OR_GO_CLEANUP(pEcdsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(siglen != NULL);
    ENSURE_OR_GO_CLEANUP(tbs != NULL);

    if (pEcdsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        if (sig == NULL) {
            if ((pEcdsaCtx->pStoreObjCtx->object.cipherType == kSSS_CipherType_EC_BRAINPOOL) &&
                (pEcdsaCtx->pStoreObjCtx->key_len == 64)) {
                *siglen = (((pEcdsaCtx->pStoreObjCtx->key_len) * 2) + 9);
            }
            else {
                *siglen = (((pEcdsaCtx->pStoreObjCtx->key_len) * 2) + 8);
            }
            return 1;
        }
        else {
            if (!sss_ecdsa_set_sha_algo(tbslen, pEcdsaCtx)) {
                goto cleanup;
            }

            // asymmetric context initialization
            status = sss_asymmetric_context_init(&asymmCtx,
                &(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx->session),
                &pEcdsaCtx->pStoreObjCtx->object,
                pEcdsaCtx->sha_algorithm,
                kMode_SSS_Sign);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            sssProv_Print(LOG_FLOW_ON, "Performing ECDSA sign using SE05x \n");
            sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pEcdsaCtx->pStoreObjCtx->object.keyId);

            // sign digest
            status = sss_asymmetric_sign_digest(&asymmCtx, (uint8_t *)tbs, tbslen, sig, siglen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        }
    }
    else {
        /* Roll back to software implementation */

        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        if (sig == NULL) {
            maxSize = EVP_PKEY_size(pEcdsaCtx->pStoreObjCtx->pEVPPkey);
            if (maxSize > 0) {
                *siglen = maxSize;
                return 1;
            }
            else {
                return 0;
            }
        }
        else {
            int openssl_ret = 0;

            sssProv_Print(LOG_FLOW_ON,
                "Not a key in secure element. Performing "
                "ECDSA sign operation using host software \n");

            evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pEcdsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            openssl_ret = EVP_PKEY_sign_init(evpCtx);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            if (!sss_ecdsa_set_sha_algo(tbslen, pEcdsaCtx)) {
                goto cleanup;
            }

            switch (pEcdsaCtx->sha_algorithm) {
            case kAlgorithm_SSS_SHA1: {
                md = EVP_sha1();
                break;
            }
            case kAlgorithm_SSS_SHA224: {
                md = EVP_sha224();
                break;
            }
            case kAlgorithm_SSS_SHA256: {
                md = EVP_sha256();
                break;
            }
            case kAlgorithm_SSS_SHA384: {
                md = EVP_sha384();
                break;
            }
            case kAlgorithm_SSS_SHA512: {
                md = EVP_sha512();
                break;
            }
            default: {
                goto cleanup;
            }
            }

            openssl_ret = EVP_PKEY_CTX_set_signature_md(evpCtx, md);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            openssl_ret = EVP_PKEY_sign(evpCtx, sig, siglen, tbs, tbslen);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);
        }
    }

    ret = 1;
cleanup:
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

static int sss_ecdsa_signature_digest_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM params[])
{
    int ret                              = 0;
    sss_provider_ecdsa_ctx_st *pEcdsaCtx = ctx;
    sss_status_t status;

    ENSURE_OR_GO_CLEANUP(pEcdsaCtx != NULL);

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(params);

    pEcdsaCtx->pStoreObjCtx = provkey;
    pEcdsaCtx->digestLen    = sizeof(pEcdsaCtx->digest);

    if (mdname == NULL) {
        pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA256;
        sssProv_Print(LOG_DBG_ON, "Using sha256 \n");
    }
    else {
        if ((0 == SSS_CMP_STR(mdname, "sha1")) || (0 == SSS_CMP_STR(mdname, "SHA1"))) {
            pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA1;
            sssProv_Print(LOG_DBG_ON, "Using sha1 \n");
        }
        else if ((0 == SSS_CMP_STR(mdname, "sha224")) || (0 == SSS_CMP_STR(mdname, "SHA224")) ||
                 (0 == SSS_CMP_STR(mdname, "SHA2-224"))) {
            pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA224;
            sssProv_Print(LOG_DBG_ON, "Using sha224 \n");
        }
        else if ((0 == SSS_CMP_STR(mdname, "sha256")) || (0 == SSS_CMP_STR(mdname, "SHA256")) ||
                 (0 == SSS_CMP_STR(mdname, "SHA2-256"))) {
            pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA256;
            sssProv_Print(LOG_DBG_ON, "Using sha256 \n");
        }
        else if ((0 == SSS_CMP_STR(mdname, "sha384")) || (0 == SSS_CMP_STR(mdname, "SHA384")) ||
                 (0 == SSS_CMP_STR(mdname, "SHA2-384"))) {
            pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA384;
            sssProv_Print(LOG_DBG_ON, "Using sha384 \n");
        }
        else if ((0 == SSS_CMP_STR(mdname, "sha512")) || (0 == SSS_CMP_STR(mdname, "SHA512")) ||
                 (0 == SSS_CMP_STR(mdname, "SHA2-512"))) {
            pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA512;
            sssProv_Print(LOG_DBG_ON, "Using sha512 \n");
        }
        else {
            sssProv_Print(LOG_DBG_ON, "sha_algorithm does not match \n");
            goto cleanup;
        }
    }

#if SSS_HAVE_HOSTCRYPTO_ANY
    /* digest context initialization */
    status = sss_digest_context_init(&pEcdsaCtx->digestCtx,
        &(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx->host_session),
        pEcdsaCtx->sha_algorithm,
        kMode_SSS_Digest);
#else
    /* Digest of the message is always done on host */
    status = kStatus_SSS_Fail;
    sssProv_Print(LOG_ERR_ON, "Enable host crypto support");
#endif
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    ret = 1;
cleanup:
    return ret;
}

static int sss_ecdsa_signature_digest_update(void *ctx, const unsigned char *data, size_t datalen)
{
    sss_status_t status;
    sss_provider_ecdsa_ctx_st *pEcdsaCtx = ctx;
    size_t offset                        = 0;
    size_t templen                       = 0;
    int ret                              = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    sssProv_Print(LOG_DBG_ON, "Input data length = %zu \n", datalen);

    ENSURE_OR_GO_CLEANUP(data != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

    if (pEcdsaCtx->digestInit == 0) {
        status = sss_digest_init(&pEcdsaCtx->digestCtx);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        pEcdsaCtx->digestInit = 1;
    }

    while (datalen > 0) {
        templen = (datalen > MAX_DIGEST_INPUT_DATA) ? MAX_DIGEST_INPUT_DATA : datalen;

        status = sss_digest_update(&pEcdsaCtx->digestCtx, data + offset, templen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        datalen = datalen - templen;
        ENSURE_OR_GO_CLEANUP((SIZE_MAX - offset) >= templen);
        offset = offset + templen;
    }

    ret = 1;
cleanup:
    return ret;
}

static int sss_ecdsa_signature_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    sss_status_t status;
    int ret                              = 0;
    sss_provider_ecdsa_ctx_st *pEcdsaCtx = ctx;
    sss_asymmetric_t asymmCtx            = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;
    const EVP_MD *md     = NULL;
    int maxSize          = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(sigsize);

    ENSURE_OR_GO_CLEANUP(pEcdsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(siglen != NULL);

    if (pEcdsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        if (sig == NULL) {
            if ((pEcdsaCtx->pStoreObjCtx->object.cipherType == kSSS_CipherType_EC_BRAINPOOL) &&
                (pEcdsaCtx->pStoreObjCtx->key_len == 64)) {
                *siglen = (((pEcdsaCtx->pStoreObjCtx->key_len) * 2) + 9);
            }
            else {
                *siglen = (((pEcdsaCtx->pStoreObjCtx->key_len) * 2) + 8);
            }
            return 1;
        }
        else {
            status = sss_digest_finish(&pEcdsaCtx->digestCtx, pEcdsaCtx->digest, &(pEcdsaCtx->digestLen));
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            status = sss_asymmetric_context_init(&asymmCtx,
                &(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx->session),
                &pEcdsaCtx->pStoreObjCtx->object,
                pEcdsaCtx->sha_algorithm,
                kMode_SSS_Sign);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            sssProv_Print(LOG_FLOW_ON, "Performing ECDSA sign using SE05x \n");
            sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pEcdsaCtx->pStoreObjCtx->object.keyId);
            status = sss_asymmetric_sign_digest(&asymmCtx, pEcdsaCtx->digest, pEcdsaCtx->digestLen, sig, siglen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        }
    }
    else {
        /* Roll back to software implementation */

        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        if (sig == NULL) {
            maxSize = EVP_PKEY_size(pEcdsaCtx->pStoreObjCtx->pEVPPkey);
            if (maxSize > 0) {
                *siglen = maxSize;
                return 1;
            }
            else {
                return 0;
            }
        }
        else {
            int openssl_ret = 0;

            sssProv_Print(LOG_FLOW_ON,
                "Not a key in secure element. Performing "
                "ECDSA sign operation using host software \n");

            evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pEcdsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            openssl_ret = EVP_PKEY_sign_init(evpCtx);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            switch (pEcdsaCtx->sha_algorithm) {
            case kAlgorithm_SSS_SHA1: {
                md = EVP_sha1();
                break;
            }
            case kAlgorithm_SSS_SHA224: {
                md = EVP_sha224();
                break;
            }
            case kAlgorithm_SSS_SHA256: {
                md = EVP_sha256();
                break;
            }
            case kAlgorithm_SSS_SHA384: {
                md = EVP_sha384();
                break;
            }
            case kAlgorithm_SSS_SHA512: {
                md = EVP_sha512();
                break;
            }
            default: {
                goto cleanup;
            }
            }

            status = sss_digest_finish(&pEcdsaCtx->digestCtx, pEcdsaCtx->digest, &(pEcdsaCtx->digestLen));
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            openssl_ret = EVP_PKEY_CTX_set_signature_md(evpCtx, md);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            openssl_ret = EVP_PKEY_sign(evpCtx, sig, siglen, pEcdsaCtx->digest, pEcdsaCtx->digestLen);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);
        }
    }

    ret = 1;
cleanup:
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (pEcdsaCtx != NULL) {
        pEcdsaCtx->digestInit = 0;
        if (pEcdsaCtx->digestCtx.session != NULL) {
            sss_digest_context_free(&pEcdsaCtx->digestCtx);
        }
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

static int sss_ecdsa_signature_digest_sign(
    void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *data, size_t datalen)
{
    sss_provider_ecdsa_ctx_st *pEcdsaCtx = (sss_provider_ecdsa_ctx_st *)ctx;
    int ret                              = 0;
    sss_status_t status;
    sss_digest_t digestCtx    = {0};
    sss_asymmetric_t asymmCtx = {
        0,
    };
    size_t datalenTmp    = datalen;
    size_t offset        = 0;
    size_t templen       = 0;
    EVP_PKEY_CTX *evpCtx = NULL;
    const EVP_MD *md     = NULL;
    int maxSize          = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(sigsize);

    ENSURE_OR_GO_CLEANUP(data != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pStoreObjCtx != NULL);

    if (pEcdsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        if (sig == NULL) {
            if ((pEcdsaCtx->pStoreObjCtx->object.cipherType == kSSS_CipherType_EC_BRAINPOOL) &&
                (pEcdsaCtx->pStoreObjCtx->key_len == 64)) {
                *siglen = (((pEcdsaCtx->pStoreObjCtx->key_len) * 2) + 9);
            }
            else {
                *siglen = (((pEcdsaCtx->pStoreObjCtx->key_len) * 2) + 8);
            }
            return 1;
        }
        else {
#if SSS_HAVE_HOSTCRYPTO_ANY
            /* digest context initialization */
            status = sss_digest_context_init(&digestCtx,
                &(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx->host_session),
                pEcdsaCtx->sha_algorithm,
                kMode_SSS_Digest);
#else
            /* Digest of the message is always done on host */
            status = kStatus_SSS_Fail;
            sssProv_Print(LOG_ERR_ON, "Enable host crypto support");
#endif
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            // performing digest on the input data
            status = sss_digest_init(&digestCtx);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            while (datalenTmp > 0) {
                templen = (datalenTmp > MAX_DIGEST_INPUT_DATA) ? MAX_DIGEST_INPUT_DATA : datalenTmp;

                status = sss_digest_update(&digestCtx, data + offset, templen);
                ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

                datalenTmp = datalenTmp - templen;
                ENSURE_OR_GO_CLEANUP((SIZE_MAX - offset) >= templen);
                offset = offset + templen;
            }

            status = sss_digest_finish(&digestCtx, pEcdsaCtx->digest, &(pEcdsaCtx->digestLen));
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            // asymmetric context initialization
            status = sss_asymmetric_context_init(&asymmCtx,
                &(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx->session),
                &pEcdsaCtx->pStoreObjCtx->object,
                pEcdsaCtx->sha_algorithm,
                kMode_SSS_Sign);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            sssProv_Print(LOG_FLOW_ON, "Performing ECDSA sign using SE05x \n");
            sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pEcdsaCtx->pStoreObjCtx->object.keyId);
            // sign digest
            status =
                sss_asymmetric_sign_digest(&asymmCtx, (uint8_t *)pEcdsaCtx->digest, pEcdsaCtx->digestLen, sig, siglen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        }
    }
    else {
        /* Roll back to software implementation */

        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        if (sig == NULL) {
            maxSize = EVP_PKEY_size(pEcdsaCtx->pStoreObjCtx->pEVPPkey);
            if (maxSize > 0) {
                *siglen = maxSize;
                return 1;
            }
            else {
                return 0;
            }
        }
        else {
            int openssl_ret = 0;

            sssProv_Print(LOG_FLOW_ON,
                "Not a key in secure element. Performing "
                "ECDSA sign operation using host software \n");

            evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pEcdsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            openssl_ret = EVP_PKEY_sign_init(evpCtx);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            switch (pEcdsaCtx->sha_algorithm) {
            case kAlgorithm_SSS_SHA1: {
                md = EVP_sha1();
                break;
            }
            case kAlgorithm_SSS_SHA224: {
                md = EVP_sha224();
                break;
            }
            case kAlgorithm_SSS_SHA256: {
                md = EVP_sha256();
                break;
            }
            case kAlgorithm_SSS_SHA384: {
                md = EVP_sha384();
                break;
            }
            case kAlgorithm_SSS_SHA512: {
                md = EVP_sha512();
                break;
            }
            default: {
                md = NULL;
            }
            }

#if SSS_HAVE_HOSTCRYPTO_ANY
            /* digest context initialization */
            status = sss_digest_context_init(&digestCtx,
                &(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx->host_session),
                pEcdsaCtx->sha_algorithm,
                kMode_SSS_Digest);
#else
            /* Digest of the message is always done on host */
            status = kStatus_SSS_Fail;
            sssProv_Print(LOG_ERR_ON, "Enable host crypto support");
#endif
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            status = sss_digest_init(&digestCtx);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            while (datalenTmp > 0) {
                templen = (datalenTmp > MAX_DIGEST_INPUT_DATA) ? MAX_DIGEST_INPUT_DATA : datalenTmp;

                status = sss_digest_update(&digestCtx, data + offset, templen);
                ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

                datalenTmp = datalenTmp - templen;
                ENSURE_OR_GO_CLEANUP((SIZE_MAX - offset) >= templen);
                offset = offset + templen;
            }

            status = sss_digest_finish(&digestCtx, pEcdsaCtx->digest, &(pEcdsaCtx->digestLen));
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            openssl_ret = EVP_PKEY_CTX_set_signature_md(evpCtx, md);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            openssl_ret = EVP_PKEY_sign(evpCtx, sig, siglen, pEcdsaCtx->digest, pEcdsaCtx->digestLen);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);
        }
    }

    ret = 1;
cleanup:
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (digestCtx.session != NULL) {
        sss_digest_context_free(&digestCtx);
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

static int sss_ecdsa_signature_verify(
    void *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    sss_provider_ecdsa_ctx_st *pEcdsaCtx = (sss_provider_ecdsa_ctx_st *)ctx;
    int ret                              = 0;
    sss_status_t status;
    sss_asymmetric_t asymmCtx = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;
    const EVP_MD *md     = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(pEcdsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(sig != NULL);
    ENSURE_OR_GO_CLEANUP(tbs != NULL);

    if (!sss_ecdsa_set_sha_algo(tbslen, pEcdsaCtx)) {
        goto cleanup;
    }

    if (pEcdsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        status = sss_asymmetric_context_init(&asymmCtx,
            &(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx->session),
            &pEcdsaCtx->pStoreObjCtx->object,
            pEcdsaCtx->sha_algorithm,
            kMode_SSS_Verify);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        sssProv_Print(LOG_FLOW_ON, "Performing ECDSA verify using SE05x \n");
        sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pEcdsaCtx->pStoreObjCtx->object.keyId);
        status = sss_asymmetric_verify_digest(&asymmCtx, (uint8_t *)tbs, tbslen, (uint8_t *)sig, siglen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    }
    else {
        /* Roll back to software implementation */

        int openssl_ret = 0;

        sssProv_Print(LOG_FLOW_ON,
            "Not a key in secure element. Performing ECDSA "
            "verify operation using host software \n");

        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pEcdsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
        ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

        openssl_ret = EVP_PKEY_verify_init(evpCtx);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        switch (pEcdsaCtx->sha_algorithm) {
        case kAlgorithm_SSS_SHA1: {
            md = EVP_sha1();
            break;
        }
        case kAlgorithm_SSS_SHA224: {
            md = EVP_sha224();
            break;
        }
        case kAlgorithm_SSS_SHA256: {
            md = EVP_sha256();
            break;
        }
        case kAlgorithm_SSS_SHA384: {
            md = EVP_sha384();
            break;
        }
        case kAlgorithm_SSS_SHA512: {
            md = EVP_sha512();
            break;
        }
        default: {
            md = NULL;
        }
        }

        openssl_ret = EVP_PKEY_CTX_set_signature_md(evpCtx, md);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        openssl_ret = EVP_PKEY_verify(evpCtx, sig, siglen, tbs, tbslen);
        if (openssl_ret == 0) {
            sssProv_Print(LOG_ERR_ON, "Verification failed \n");
        }
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);
    }

    ret = 1;
cleanup:
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

static int sss_ecdsa_signature_digest_verify_final(void *ctx, const unsigned char *sig, size_t siglen)
{
    sss_status_t status;
    int ret                              = 0;
    sss_provider_ecdsa_ctx_st *pEcdsaCtx = ctx;
    sss_asymmetric_t asymmCtx            = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;
    const EVP_MD *md     = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(pEcdsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(sig != NULL);

    if (pEcdsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        status = sss_digest_finish(&pEcdsaCtx->digestCtx, pEcdsaCtx->digest, &(pEcdsaCtx->digestLen));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_asymmetric_context_init(&asymmCtx,
            &(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx->session),
            &pEcdsaCtx->pStoreObjCtx->object,
            pEcdsaCtx->sha_algorithm,
            kMode_SSS_Verify);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        sssProv_Print(LOG_FLOW_ON, "Performing ECDSA verify using SE05x \n");
        sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pEcdsaCtx->pStoreObjCtx->object.keyId);
        status =
            sss_asymmetric_verify_digest(&asymmCtx, pEcdsaCtx->digest, pEcdsaCtx->digestLen, (uint8_t *)sig, siglen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    }
    else {
        /* Roll back to software implementation */

        int openssl_ret = 0;

        sssProv_Print(LOG_FLOW_ON,
            "Not a key in secure element. Performing ECDSA "
            "verify operation using host software \n");

        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pEcdsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
        ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

        openssl_ret = EVP_PKEY_verify_init(evpCtx);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        switch (pEcdsaCtx->sha_algorithm) {
        case kAlgorithm_SSS_SHA1: {
            md = EVP_sha1();
            break;
        }
        case kAlgorithm_SSS_SHA224: {
            md = EVP_sha224();
            break;
        }
        case kAlgorithm_SSS_SHA256: {
            md = EVP_sha256();
            break;
        }
        case kAlgorithm_SSS_SHA384: {
            md = EVP_sha384();
            break;
        }
        case kAlgorithm_SSS_SHA512: {
            md = EVP_sha512();
            break;
        }
        default: {
            md = NULL;
        }
        }

        status = sss_digest_finish(&pEcdsaCtx->digestCtx, pEcdsaCtx->digest, &(pEcdsaCtx->digestLen));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        openssl_ret = EVP_PKEY_CTX_set_signature_md(evpCtx, md);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        openssl_ret = EVP_PKEY_verify(evpCtx, sig, siglen, pEcdsaCtx->digest, pEcdsaCtx->digestLen);
        if (openssl_ret == 0) {
            sssProv_Print(LOG_ERR_ON, "Verification failed \n");
        }
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);
    }

    ret = 1;
cleanup:
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (pEcdsaCtx != NULL) {
        pEcdsaCtx->digestInit = 0;
        if (pEcdsaCtx->digestCtx.session != NULL) {
            sss_digest_context_free(&pEcdsaCtx->digestCtx);
        }
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

static int sss_ecdsa_signature_digest_verify(
    void *ctx, unsigned char *sig, size_t sigsize, const unsigned char *data, size_t datalen)
{
    sss_provider_ecdsa_ctx_st *pEcdsaCtx = (sss_provider_ecdsa_ctx_st *)ctx;
    int ret                              = 0;
    sss_status_t status;
    sss_digest_t digestCtx    = {0};
    sss_asymmetric_t asymmCtx = {
        0,
    };
    size_t datalenTmp    = datalen;
    size_t offset        = 0;
    size_t templen       = 0;
    EVP_PKEY_CTX *evpCtx = NULL;
    const EVP_MD *md     = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(data != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(sig != NULL);

    if (pEcdsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

#if SSS_HAVE_HOSTCRYPTO_ANY
        /* digest context initialization */
        status = sss_digest_context_init(&digestCtx,
            &(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx->host_session),
            pEcdsaCtx->sha_algorithm,
            kMode_SSS_Digest);
#else
        /* Digest of the message is always done on host */
        status = kStatus_SSS_Fail;
        sssProv_Print(LOG_ERR_ON, "Enable host crypto support");
#endif
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        // performing digest on the input data
        status = sss_digest_init(&digestCtx);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        while (datalenTmp > 0) {
            templen = (datalenTmp > MAX_DIGEST_INPUT_DATA) ? MAX_DIGEST_INPUT_DATA : datalenTmp;

            status = sss_digest_update(&digestCtx, data + offset, templen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            datalenTmp = datalenTmp - templen;
            ENSURE_OR_GO_CLEANUP((SIZE_MAX - offset) >= templen);
            offset = offset + templen;
        }

        status = sss_digest_finish(&digestCtx, pEcdsaCtx->digest, &(pEcdsaCtx->digestLen));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        // asymmetric context initialization
        status = sss_asymmetric_context_init(&asymmCtx,
            &(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx->session),
            &pEcdsaCtx->pStoreObjCtx->object,
            pEcdsaCtx->sha_algorithm,
            kMode_SSS_Verify);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        sssProv_Print(LOG_FLOW_ON, "Performing ECDSA verify using SE05x \n");
        sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pEcdsaCtx->pStoreObjCtx->object.keyId);
        status =
            sss_asymmetric_verify_digest(&asymmCtx, pEcdsaCtx->digest, pEcdsaCtx->digestLen, (uint8_t *)sig, sigsize);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        ret = 1;
    }
    else {
        /* Roll back to software implementation */

        ENSURE_OR_GO_CLEANUP(pEcdsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        int openssl_ret = 0;

        sssProv_Print(LOG_FLOW_ON,
            "Not a key in secure element. Performing ECDSA "
            "verify operation using host software \n");

        evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pEcdsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
        ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

        openssl_ret = EVP_PKEY_verify_init(evpCtx);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        switch (pEcdsaCtx->sha_algorithm) {
        case kAlgorithm_SSS_SHA1: {
            md = EVP_sha1();
            break;
        }
        case kAlgorithm_SSS_SHA224: {
            md = EVP_sha224();
            break;
        }
        case kAlgorithm_SSS_SHA256: {
            md = EVP_sha256();
            break;
        }
        case kAlgorithm_SSS_SHA384: {
            md = EVP_sha384();
            break;
        }
        case kAlgorithm_SSS_SHA512: {
            md = EVP_sha512();
            break;
        }
        default: {
            md = NULL;
        }
        }

#if SSS_HAVE_HOSTCRYPTO_ANY
        /* digest context initialization */
        status = sss_digest_context_init(&digestCtx,
            &(pEcdsaCtx->pProvCtx->p_ex_sss_boot_ctx->host_session),
            pEcdsaCtx->sha_algorithm,
            kMode_SSS_Digest);
#else
        /* Digest of the message is always done on host */
        status = kStatus_SSS_Fail;
        sssProv_Print(LOG_ERR_ON, "Enable host crypto support");
#endif
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_digest_init(&digestCtx);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        while (datalenTmp > 0) {
            templen = (datalenTmp > MAX_DIGEST_INPUT_DATA) ? MAX_DIGEST_INPUT_DATA : datalenTmp;

            status = sss_digest_update(&digestCtx, data + offset, templen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            datalenTmp = datalenTmp - templen;
            ENSURE_OR_GO_CLEANUP((SIZE_MAX - offset) >= templen);
            offset = offset + templen;
        }

        status = sss_digest_finish(&digestCtx, pEcdsaCtx->digest, &(pEcdsaCtx->digestLen));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        openssl_ret = EVP_PKEY_CTX_set_signature_md(evpCtx, md);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        openssl_ret = EVP_PKEY_verify(evpCtx, sig, sigsize, pEcdsaCtx->digest, pEcdsaCtx->digestLen);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);
    }
    ret = 1;
cleanup:
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (digestCtx.session != NULL) {
        sss_digest_context_free(&digestCtx);
    }
    if (pEcdsaCtx != NULL) {
        if (pEcdsaCtx->digestCtx.session != NULL) {
            sss_digest_context_free(&pEcdsaCtx->digestCtx);
        }
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }

    return ret;
}

static int sss_ecdsa_signature_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    int ret                              = 0;
    sss_provider_ecdsa_ctx_st *pEcdsaCtx = ctx;
    OSSL_PARAM *p;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(pEcdsaCtx != NULL);

    if (pEcdsaCtx->sha_algorithm == kAlgorithm_SSS_SHA1) {
        uint8_t aid_sha1[] = AID_ECDSA_WITH_SHA1;
        p                  = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL && !OSSL_PARAM_set_octet_string(p, aid_sha1, sizeof(aid_sha1))) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, 20)) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
        if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SHA1")) {
            return 0;
        }
    }
    else if (pEcdsaCtx->sha_algorithm == kAlgorithm_SSS_SHA224) {
        uint8_t aid_sha224[] = AID_ECDSA_WITH_SHA224;
        p                    = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL && !OSSL_PARAM_set_octet_string(p, aid_sha224, sizeof(aid_sha224))) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, 28)) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
        if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SHA224")) {
            return 0;
        }
    }
    else if (pEcdsaCtx->sha_algorithm == kAlgorithm_SSS_SHA256) {
        uint8_t aid_sha256[] = AID_ECDSA_WITH_SHA256;
        p                    = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL && !OSSL_PARAM_set_octet_string(p, aid_sha256, sizeof(aid_sha256))) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, 32)) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
        if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SHA256")) {
            return 0;
        }
    }
    else if (pEcdsaCtx->sha_algorithm == kAlgorithm_SSS_SHA384) {
        uint8_t aid_sha384[] = AID_ECDSA_WITH_SHA384;

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL && !OSSL_PARAM_set_octet_string(p, aid_sha384, sizeof(aid_sha384))) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, 48)) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
        if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SHA384")) {
            return 0;
        }
    }
    else if (pEcdsaCtx->sha_algorithm == kAlgorithm_SSS_SHA512) {
        uint8_t aid_sha512[] = AID_ECDSA_WITH_SHA512;

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL && !OSSL_PARAM_set_octet_string(p, aid_sha512, sizeof(aid_sha512))) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, 64)) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
        if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SHA512")) {
            return 0;
        }
    }

    ret = 1;
cleanup:
    return ret;
}

static const OSSL_PARAM sss_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *sss_ecdsa_signature_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    return sss_gettable_ctx_params;
}

static int sss_ecdsa_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    sss_provider_ecdsa_ctx_st *pEcdsaCtx = ctx;
    const OSSL_PARAM *p;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_UTF8_STRING: {
            if (p->data == NULL) {
                return 0;
            }
            if ((0 == SSS_CMP_STR(p->data, "sha1")) || (0 == SSS_CMP_STR(p->data, "SHA1")) ||
                (0 == SSS_CMP_STR(p->data, "SHA-1"))) {
                pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA1;
            }
            else if ((0 == SSS_CMP_STR(p->data, "sha224")) || (0 == SSS_CMP_STR(p->data, "SHA224")) ||
                     (0 == SSS_CMP_STR(p->data, "SHA2-224"))) {
                pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA224;
            }
            else if ((0 == SSS_CMP_STR(p->data, "sha256")) || (0 == SSS_CMP_STR(p->data, "SHA256")) ||
                     (0 == SSS_CMP_STR(p->data, "SHA2-256"))) {
                pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA256;
            }
            else if ((0 == SSS_CMP_STR(p->data, "sha384")) || (0 == SSS_CMP_STR(p->data, "SHA384")) ||
                     (0 == SSS_CMP_STR(p->data, "SHA2-384"))) {
                pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA384;
            }
            else if ((0 == SSS_CMP_STR(p->data, "sha512")) || (0 == SSS_CMP_STR(p->data, "SHA512")) ||
                     (0 == SSS_CMP_STR(p->data, "SHA2-512"))) {
                pEcdsaCtx->sha_algorithm = kAlgorithm_SSS_SHA512;
            }
            else {
                sssProv_Print(LOG_ERR_ON, "sha not supported ! \n");
                return 0;
            }
        } break;
        default:
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM settable_ctx_params[] = {OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *sss_ecdsa_settable_ctx_params(void *vctx, ossl_unused void *provctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(vctx);
    return settable_ctx_params;
}

const OSSL_DISPATCH sss_ecdsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sss_ecdsa_signature_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sss_ecdsa_signature_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))sss_ecdsa_signature_dupctx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))sss_ecdsa_sign_verify_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))sss_ecdsa_signature_sign},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))sss_ecdsa_signature_digest_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))sss_ecdsa_signature_digest_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))sss_ecdsa_signature_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))sss_ecdsa_signature_digest_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))sss_ecdsa_sign_verify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))sss_ecdsa_signature_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))sss_ecdsa_signature_digest_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))sss_ecdsa_signature_digest_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))sss_ecdsa_signature_digest_verify_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))sss_ecdsa_signature_digest_verify},

    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))sss_ecdsa_signature_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))sss_ecdsa_signature_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))sss_ecdsa_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))sss_ecdsa_settable_ctx_params},

    {0, NULL}};

#endif //#if SSS_HAVE_ECC
