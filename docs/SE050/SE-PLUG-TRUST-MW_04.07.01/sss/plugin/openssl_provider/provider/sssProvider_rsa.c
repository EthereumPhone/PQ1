/**
 * @file sssProvider_rsa.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for RSA sign / verify using SSS API's
 *
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_RSA

/* ********************** Include files ********************** */
#include "openssl/rsa.h"
#include "sssProvider_main.h"
#include <openssl/core_names.h>
#include <string.h>

/* ********************** Constants ************************** */
#define MAX_DIGEST_INPUT_DATA 512

/* ********************** structure definition *************** */
typedef struct
{
    sss_algorithm_t sha_algorithm;
    sss_algorithm_t sign_algorithm;
    int pad_mode;
    uint8_t digest[64]; /* MAX SHA512 */
    size_t digestLen;
    sss_provider_store_obj_t *pStoreObjCtx;
    sss_provider_context_t *pProvCtx;
    sss_digest_t digestCtx;
} sss_provider_rsa_ctx_st;

/* ********************** Private funtions ******************* */

static int sss_openssl_get_padding(sss_algorithm_t algorithm)
{
    int padding = 0;
    switch (algorithm) {
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH:
    case kAlgorithm_SSS_RSAES_PKCS1_V1_5:
        padding = RSA_PKCS1_PADDING;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA224:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512:
        padding = RSA_PKCS1_PSS_PADDING;
        break;
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA224:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA384:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA512:
        padding = RSA_PKCS1_OAEP_PADDING;
        break;
    default:
        padding = RSA_PKCS1_PADDING;
    }
    return padding;
}

static void *sss_rsa_signature_newctx(void *provctx, const char *propq)
{
    sss_provider_rsa_ctx_st *pRSACtx = OPENSSL_zalloc(sizeof(sss_provider_rsa_ctx_st));
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(propq);
    if (pRSACtx != NULL) {
        pRSACtx->pProvCtx = provctx;
    }
    return pRSACtx;
}

static void sss_rsa_signature_freectx(void *ctx)
{
    sss_provider_rsa_ctx_st *sctx = ctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (sctx != NULL) {
        OPENSSL_clear_free(sctx, sizeof(sss_provider_rsa_ctx_st));
    }
    return;
}

static void *sss_rsa_signature_dupctx(void *ctx)
{
    sss_provider_rsa_ctx_st *pRsaCtx    = (sss_provider_rsa_ctx_st *)ctx;
    sss_provider_rsa_ctx_st *pRsaDupCtx = OPENSSL_zalloc(sizeof(sss_provider_rsa_ctx_st));

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(pRsaDupCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);

    pRsaDupCtx->digestLen = pRsaCtx->digestLen;
    if (pRsaCtx->digestLen > 0) {
        memcpy(pRsaDupCtx->digest, pRsaCtx->digest, pRsaCtx->digestLen);
    }
    pRsaDupCtx->pProvCtx       = pRsaCtx->pProvCtx;
    pRsaDupCtx->pStoreObjCtx   = pRsaCtx->pStoreObjCtx;
    pRsaDupCtx->sha_algorithm  = pRsaCtx->sha_algorithm;
    pRsaDupCtx->sign_algorithm = pRsaCtx->sign_algorithm;
    memcpy(&pRsaDupCtx->digestCtx, &pRsaCtx->digestCtx, sizeof(pRsaCtx->digestCtx));
    return pRsaDupCtx;

cleanup:
    if (pRsaDupCtx != NULL) {
        OPENSSL_clear_free(pRsaDupCtx, sizeof(sss_provider_rsa_ctx_st));
    }
    return NULL;
}

static int sss_rsa_signature_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    int ret                          = 0;
    sss_provider_rsa_ctx_st *pRsaCtx = ctx;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(params);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    pRsaCtx->pStoreObjCtx   = provkey;
    pRsaCtx->sign_algorithm = kAlgorithm_None;

    ret = 1;
cleanup:
    return ret;
}

static int sss_rsa_signature_sign(
    void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    sss_provider_rsa_ctx_st *pRsaCtx = (sss_provider_rsa_ctx_st *)ctx;
    int ret                          = 0;
    sss_status_t status;
    sss_asymmetric_t asymmCtx = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;
    int maxSize          = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(sigsize);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(siglen != NULL);
    ENSURE_OR_GO_CLEANUP(tbs != NULL);

    if (pRsaCtx->sign_algorithm == kAlgorithm_None) {
        pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH;
    }

    if (pRsaCtx->pStoreObjCtx->object.keyId != 0) {
        if (sig == NULL) {
            *siglen = pRsaCtx->pStoreObjCtx->key_len;
            return 1;
        }
        else {
            ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
            ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);
            ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

            status = sss_asymmetric_context_init(&asymmCtx,
                &pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->session,
                &pRsaCtx->pStoreObjCtx->object,
                pRsaCtx->sign_algorithm,
                kMode_SSS_Sign);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            sssProv_Print(LOG_FLOW_ON, "Performing RSA sign using SE05x \n");
            sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pRsaCtx->pStoreObjCtx->object.keyId);
            status = sss_asymmetric_sign_digest(&asymmCtx, (uint8_t *)tbs, tbslen, sig, siglen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        }
    }
    else {
        /* Roll back to software implementation */

        ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        if (sig == NULL) {
            maxSize = EVP_PKEY_size(pRsaCtx->pStoreObjCtx->pEVPPkey);
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
                "Not a key in secure element. Performing RSA "
                "sign operation using host software \n");

            evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pRsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            openssl_ret = EVP_PKEY_sign_init(evpCtx);
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

static int sss_rsa_signature_digest_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM params[])
{
    int ret                             = 0;
    sss_provider_store_obj_t *pStoreCtx = provkey;
    sss_provider_rsa_ctx_st *pRsaCtx    = ctx;
    sss_status_t status;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(params);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);

    pRsaCtx->pStoreObjCtx = pStoreCtx;
    pRsaCtx->digestLen    = sizeof(pRsaCtx->digest);

    if (mdname == NULL) {
        pRsaCtx->sha_algorithm  = kAlgorithm_SSS_SHA256;
        pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
    }
    else {
        if ((0 == SSS_CMP_STR(mdname, "sha1")) || (0 == SSS_CMP_STR(mdname, "SHA1"))) {
            pRsaCtx->sha_algorithm  = kAlgorithm_SSS_SHA1;
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1;
            sssProv_Print(LOG_DBG_ON, "Using sha1 \n");
        }
        else if ((0 == SSS_CMP_STR(mdname, "sha224")) || (0 == SSS_CMP_STR(mdname, "SHA224")) ||
                 (0 == SSS_CMP_STR(mdname, "SHA2-224"))) {
            pRsaCtx->sha_algorithm  = kAlgorithm_SSS_SHA224;
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224;
            sssProv_Print(LOG_DBG_ON, "Using sha224 \n");
        }
        else if ((0 == SSS_CMP_STR(mdname, "sha256")) || (0 == SSS_CMP_STR(mdname, "SHA256")) ||
                 (0 == SSS_CMP_STR(mdname, "SHA2-256"))) {
            pRsaCtx->sha_algorithm  = kAlgorithm_SSS_SHA256;
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
            sssProv_Print(LOG_DBG_ON, "Using sha256 \n");
        }
        else if ((0 == SSS_CMP_STR(mdname, "sha384")) || (0 == SSS_CMP_STR(mdname, "SHA384")) ||
                 (0 == SSS_CMP_STR(mdname, "SHA2-384"))) {
            pRsaCtx->sha_algorithm  = kAlgorithm_SSS_SHA384;
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384;
            sssProv_Print(LOG_DBG_ON, "Using sha384 \n");
        }
        else if ((0 == SSS_CMP_STR(mdname, "sha512")) || (0 == SSS_CMP_STR(mdname, "SHA512")) ||
                 (0 == SSS_CMP_STR(mdname, "SHA2-512"))) {
            pRsaCtx->sha_algorithm  = kAlgorithm_SSS_SHA512;
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512;
            sssProv_Print(LOG_DBG_ON, "Using sha512 \n");
        }
        else {
            sssProv_Print(LOG_DBG_ON, "sha_algorithm does not match \n");
            goto cleanup;
        }
    }

#if SSS_HAVE_HOSTCRYPTO_ANY
    /* digest context initialization */
    status = sss_digest_context_init(&pRsaCtx->digestCtx,
        &pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->host_session,
        pRsaCtx->sha_algorithm,
        kMode_SSS_Digest);
#else
    /* Digest of the message is always done on host */
    status = kStatus_SSS_Fail;
    sssProv_Print(LOG_ERR_ON, "Enable host crypto support");
#endif
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_digest_init(&pRsaCtx->digestCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    ret = 1;
cleanup:
    return ret;
}

static int sss_rsa_signature_digest_update(void *ctx, const unsigned char *data, size_t datalen)
{
    sss_provider_rsa_ctx_st *pRsaCtx = ctx;
    int ret                          = 0;
    sss_status_t status;
    size_t datalenTmp = datalen;
    size_t offset     = 0;
    size_t templen    = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(data != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

    while (datalenTmp > 0) {
        templen = (datalenTmp > MAX_DIGEST_INPUT_DATA) ? MAX_DIGEST_INPUT_DATA : datalenTmp;

        status = sss_digest_update(&pRsaCtx->digestCtx, data + offset, templen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        datalenTmp = datalenTmp - templen;
        ENSURE_OR_GO_CLEANUP((SIZE_MAX - offset) >= templen);
        offset = offset + templen;
    }

    ret = 1;
cleanup:
    return ret;
}

static int sss_rsa_signature_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    sss_status_t status;
    int ret                          = 0;
    sss_provider_rsa_ctx_st *pRsaCtx = ctx;
    sss_asymmetric_t asymmCtx        = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;
    const EVP_MD *md     = NULL;
    int maxSize          = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(sigsize);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(siglen != NULL);

    if (pRsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        if (sig == NULL) {
            *siglen = pRsaCtx->pStoreObjCtx->key_len;
            return (*siglen > 0);
        }
        else {
            status = sss_digest_finish(&pRsaCtx->digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            status = sss_asymmetric_context_init(&asymmCtx,
                &pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->session,
                &pRsaCtx->pStoreObjCtx->object,
                pRsaCtx->sign_algorithm,
                kMode_SSS_Sign);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            sssProv_Print(LOG_FLOW_ON, "Performing RSA sign using SE05x \n");
            sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pRsaCtx->pStoreObjCtx->object.keyId);
            status = sss_asymmetric_sign_digest(&asymmCtx, pRsaCtx->digest, pRsaCtx->digestLen, sig, siglen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        }
    }
    else {
        /* Roll back to software implementation */

        ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        if (sig == NULL) {
            maxSize = EVP_PKEY_size(pRsaCtx->pStoreObjCtx->pEVPPkey);
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
                "Not a key in secure element. Performing RSA "
                "sign operation using host software \n");

            evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pRsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            openssl_ret = EVP_PKEY_sign_init(evpCtx);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            switch (pRsaCtx->sha_algorithm) {
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

            status = sss_digest_finish(&pRsaCtx->digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            openssl_ret = EVP_PKEY_CTX_set_signature_md(evpCtx, md);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            openssl_ret = EVP_PKEY_sign(evpCtx, sig, siglen, pRsaCtx->digest, pRsaCtx->digestLen);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);
        }
    }

    ret = 1;
cleanup:
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (pRsaCtx != NULL) {
        if (pRsaCtx->digestCtx.session != NULL) {
            sss_digest_context_free(&pRsaCtx->digestCtx);
        }
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

static int sss_rsa_signature_digest_sign(
    void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *data, size_t datalen)
{
    sss_provider_rsa_ctx_st *pRsaCtx = (sss_provider_rsa_ctx_st *)ctx;
    int ret                          = 0;
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
    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);

    if (pRsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        if (sig == NULL) {
            *siglen = (((pRsaCtx->pStoreObjCtx->key_len) * 2) + 8);
            return 1;
        }
        else {
#if SSS_HAVE_HOSTCRYPTO_ANY
            /* digest context initialization */
            status = sss_digest_context_init(&digestCtx,
                &(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->host_session),
                pRsaCtx->sha_algorithm,
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

            status = sss_digest_finish(&digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            // asymmetric context initialization
            status = sss_asymmetric_context_init(&asymmCtx,
                &(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->session),
                &pRsaCtx->pStoreObjCtx->object,
                pRsaCtx->sign_algorithm,
                kMode_SSS_Sign);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            sssProv_Print(LOG_FLOW_ON, "Performing RSA sign using SE05x \n");
            sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pRsaCtx->pStoreObjCtx->object.keyId);
            // sign digest
            status = sss_asymmetric_sign_digest(&asymmCtx, (uint8_t *)pRsaCtx->digest, pRsaCtx->digestLen, sig, siglen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        }
    }
    else {
        /* Roll back to software implementation */

        ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        if (sig == NULL) {
            maxSize = EVP_PKEY_size(pRsaCtx->pStoreObjCtx->pEVPPkey);
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
                "Not a key in secure element. Performing RSA "
                "sign operation using host software \n");

            evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pRsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            openssl_ret = EVP_PKEY_sign_init(evpCtx);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            switch (pRsaCtx->sha_algorithm) {
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
                &(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->host_session),
                pRsaCtx->sha_algorithm,
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

            status = sss_digest_finish(&digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            openssl_ret = EVP_PKEY_CTX_set_signature_md(evpCtx, md);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            openssl_ret = EVP_PKEY_sign(evpCtx, sig, siglen, pRsaCtx->digest, pRsaCtx->digestLen);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);
        }
    }

    ret = 1;
cleanup:
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (pRsaCtx != NULL) {
        if (pRsaCtx->digestCtx.session != NULL) {
            sss_digest_context_free(&pRsaCtx->digestCtx);
        }
    }
    if (digestCtx.session != NULL) {
        sss_digest_context_free(&digestCtx);
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

static int sss_rsa_signature_verify(
    void *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    sss_provider_rsa_ctx_st *pRsaCtx = (sss_provider_rsa_ctx_st *)ctx;
    int ret                          = 0;
    sss_status_t status;
    sss_asymmetric_t asymmCtx = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(sig != NULL);
    ENSURE_OR_GO_CLEANUP(tbs != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);

    if (pRsaCtx->sign_algorithm == kAlgorithm_None) {
        pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH;
    }

    if (pRsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        // Asymmetric context initialization
        status = sss_asymmetric_context_init(&asymmCtx,
            &(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->session),
            &pRsaCtx->pStoreObjCtx->object,
            pRsaCtx->sign_algorithm,
            kMode_SSS_Verify);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        sssProv_Print(LOG_FLOW_ON, "Performing RSA verify using SE05x \n");
        sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pRsaCtx->pStoreObjCtx->object.keyId);
        status = sss_asymmetric_verify_digest(&asymmCtx, (uint8_t *)tbs, tbslen, (uint8_t *)sig, siglen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    }
    else {
        /* Roll back to software implementation */

        int openssl_ret = 0;

        sssProv_Print(LOG_FLOW_ON,
            "Not a key in secure element. Performing RSA "
            "verify operation using host software \n");

        ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pRsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
        ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

        openssl_ret = EVP_PKEY_verify_init(evpCtx);
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
    return ret;
}

static int sss_rsa_signature_digest_verify_final(void *ctx, const unsigned char *sig, size_t siglen)
{
    sss_status_t status;
    int ret                          = 0;
    sss_provider_rsa_ctx_st *pRsaCtx = ctx;
    sss_asymmetric_t asymmCtx        = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;
    const EVP_MD *md     = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(sig != NULL);

    if (pRsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        status = sss_digest_finish(&pRsaCtx->digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        // Asymmetric context initialization
        status = sss_asymmetric_context_init(&asymmCtx,
            &pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->session,
            &pRsaCtx->pStoreObjCtx->object,
            pRsaCtx->sign_algorithm,
            kMode_SSS_Verify);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        sssProv_Print(LOG_FLOW_ON, "Performing RSA verify using SE05x \n");
        sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pRsaCtx->pStoreObjCtx->object.keyId);
        status = sss_asymmetric_verify_digest(&asymmCtx, pRsaCtx->digest, pRsaCtx->digestLen, (uint8_t *)sig, siglen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    }
    else {
        /* Roll back to software implementation */

        int openssl_ret = 0;

        sssProv_Print(LOG_FLOW_ON,
            "Not a key in secure element. Performing RSA "
            "verify operation using host software \n");

        ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pRsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
        ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

        openssl_ret = EVP_PKEY_verify_init(evpCtx);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        switch (pRsaCtx->sha_algorithm) {
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

        status = sss_digest_finish(&pRsaCtx->digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        openssl_ret = EVP_PKEY_CTX_set_signature_md(evpCtx, md);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        openssl_ret = EVP_PKEY_verify(evpCtx, sig, siglen, pRsaCtx->digest, pRsaCtx->digestLen);
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
    if (pRsaCtx != NULL) {
        if (pRsaCtx->digestCtx.session != NULL) {
            sss_digest_context_free(&pRsaCtx->digestCtx);
        }
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

static int sss_rsa_signature_digest_verify(
    void *ctx, unsigned char *sig, size_t siglen, const unsigned char *data, size_t datalen)
{
    sss_provider_rsa_ctx_st *pRsaCtx = (sss_provider_rsa_ctx_st *)ctx;
    int ret                          = 0;
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
    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(sig != NULL);

    if (pRsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

#if SSS_HAVE_HOSTCRYPTO_ANY
        /* digest context initialization */
        status = sss_digest_context_init(&digestCtx,
            &(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->host_session),
            pRsaCtx->sha_algorithm,
            kMode_SSS_Digest);
#else
        /* Digest of the message is always done on host */
        status = kStatus_SSS_Fail;
        sssProv_Print(LOG_ERR_ON, "Enable host crypto support");
#endif
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        //performing digest on the input data
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

        status = sss_digest_finish(&digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        // asymmetric context initialization
        status = sss_asymmetric_context_init(&asymmCtx,
            &(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->session),
            &pRsaCtx->pStoreObjCtx->object,
            pRsaCtx->sign_algorithm,
            kMode_SSS_Verify);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        sssProv_Print(LOG_FLOW_ON, "Performing RSA verify using SE05x \n");
        sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pRsaCtx->pStoreObjCtx->object.keyId);
        status = sss_asymmetric_verify_digest(&asymmCtx, pRsaCtx->digest, pRsaCtx->digestLen, (uint8_t *)sig, siglen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        ret = 1;
    }
    else {
        /* Roll back to software implementation */

        ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        int openssl_ret = 0;

        sssProv_Print(
            LOG_FLOW_ON, "Not a key in secure element. Performing rsa verify operation using host software \n");

        evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pRsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
        ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

        openssl_ret = EVP_PKEY_verify_init(evpCtx);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        switch (pRsaCtx->sha_algorithm) {
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
            &(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->host_session),
            pRsaCtx->sha_algorithm,
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

        status = sss_digest_finish(&digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        openssl_ret = EVP_PKEY_CTX_set_signature_md(evpCtx, md);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        openssl_ret = EVP_PKEY_CTX_set_rsa_padding(evpCtx, sss_openssl_get_padding(pRsaCtx->sign_algorithm));
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        openssl_ret = EVP_PKEY_verify(evpCtx, sig, siglen, pRsaCtx->digest, pRsaCtx->digestLen);
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
    if (pRsaCtx != NULL) {
        if (pRsaCtx->digestCtx.session != NULL) {
            sss_digest_context_free(&pRsaCtx->digestCtx);
        }
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }

    return ret;
}

static int sss_rsa_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p              = NULL;
    sss_provider_rsa_ctx_st *pRsaCtx = ctx;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pRsaCtx == NULL) {
        return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_UTF8_STRING: {
            if (p->data == NULL) {
                return 0;
            }
            if (strcmp(p->data, "SHA1") == 0) {
                pRsaCtx->sha_algorithm = kAlgorithm_SSS_SHA1;
            }
            else if (strcmp(p->data, "SHA224") == 0) {
                pRsaCtx->sha_algorithm = kAlgorithm_SSS_SHA224;
            }
            else if (strcmp(p->data, "SHA256") == 0) {
                pRsaCtx->sha_algorithm = kAlgorithm_SSS_SHA256;
            }
            else if (strcmp(p->data, "SHA384") == 0) {
                pRsaCtx->sha_algorithm = kAlgorithm_SSS_SHA384;
            }
            else if (strcmp(p->data, "SHA512") == 0) {
                pRsaCtx->sha_algorithm = kAlgorithm_SSS_SHA512;
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

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_get_int(p, &pRsaCtx->pad_mode)) {
                return 0;
            }
            break;
        case OSSL_PARAM_UTF8_STRING: {
            if (p->data == NULL) {
                return 0;
            }
            if (strcmp(p->data, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0) {
                pRsaCtx->pad_mode = RSA_PKCS1_PADDING;
            }
            else if (strcmp(p->data, OSSL_PKEY_RSA_PAD_MODE_NONE) == 0) {
                pRsaCtx->pad_mode       = RSA_NO_PADDING;
                pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH;
            }
            else if (strcmp(p->data, OSSL_PKEY_RSA_PAD_MODE_PSS) == 0) {
                pRsaCtx->pad_mode = RSA_PKCS1_PSS_PADDING;
            }
            else {
                sssProv_Print(LOG_ERR_ON, "Padding not supported ! \n");
                return 0;
            }
        } break;
        default:
            return 0;
        }
    }

    if (pRsaCtx->pad_mode == RSA_PKCS1_PADDING) {
        switch (pRsaCtx->sha_algorithm) {
        case kAlgorithm_SSS_SHA1:
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1;
            break;
        case kAlgorithm_SSS_SHA224:
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224;
            break;
        case kAlgorithm_SSS_SHA256:
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
            break;
        case kAlgorithm_SSS_SHA384:
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384;
            break;
        case kAlgorithm_SSS_SHA512:
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512;
            break;
        default:
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
            break;
        }
    }
    else if (pRsaCtx->pad_mode == RSA_PKCS1_PSS_PADDING) {
        switch (pRsaCtx->sha_algorithm) {
        case kAlgorithm_SSS_SHA1:
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1;
            break;
        case kAlgorithm_SSS_SHA224:
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA224;
            break;
        case kAlgorithm_SSS_SHA256:
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256;
            break;
        case kAlgorithm_SSS_SHA384:
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384;
            break;
        case kAlgorithm_SSS_SHA512:
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512;
            break;
        default:
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256;
            break;
        }
    }

    return 1;
}

static const OSSL_PARAM *sss_rsa_settable_ctx_params(void *vprsactx, ossl_unused void *provctx)
{
    static const OSSL_PARAM settable_ctx_params[] = {OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END};

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(vprsactx);
    return settable_ctx_params;
}

static int sss_rsa_signature_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    int ret                          = 0;
    sss_provider_rsa_ctx_st *pRsaCtx = ctx;
    OSSL_PARAM *p;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    if (pRsaCtx->sha_algorithm == kAlgorithm_SSS_SHA1) {
        uint8_t aid_sha1[] = AID_RSA_WITH_SHA1;
        p                  = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL && !OSSL_PARAM_set_octet_string(p, aid_sha1, sizeof(aid_sha1))) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
        if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SHA1")) {
            return 0;
        }
    }
    else if (pRsaCtx->sha_algorithm == kAlgorithm_SSS_SHA224) {
        uint8_t aid_sha224[] = AID_RSA_WITH_SHA224;
        p                    = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL && !OSSL_PARAM_set_octet_string(p, aid_sha224, sizeof(aid_sha224))) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
        if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SHA224")) {
            return 0;
        }
    }
    else if (pRsaCtx->sha_algorithm == kAlgorithm_SSS_SHA256) {
        uint8_t aid_sha256[] = AID_RSA_WITH_SHA256;
        p                    = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL && !OSSL_PARAM_set_octet_string(p, aid_sha256, sizeof(aid_sha256))) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
        if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SHA256")) {
            return 0;
        }
    }
    else if (pRsaCtx->sha_algorithm == kAlgorithm_SSS_SHA384) {
        uint8_t aid_sha384[] = AID_RSA_WITH_SHA384;
        p                    = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL && !OSSL_PARAM_set_octet_string(p, aid_sha384, sizeof(aid_sha384))) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
        if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SHA384")) {
            return 0;
        }
    }
    else if (pRsaCtx->sha_algorithm == kAlgorithm_SSS_SHA512) {
        uint8_t aid_sha512[] = AID_RSA_WITH_SHA512;
        p                    = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL && !OSSL_PARAM_set_octet_string(p, aid_sha512, sizeof(aid_sha512))) {
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

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *sss_rsa_gettable_ctx_params(ossl_unused void *vprsactx, ossl_unused void *provctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    return known_gettable_ctx_params;
}

const OSSL_DISPATCH sss_rsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sss_rsa_signature_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sss_rsa_signature_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))sss_rsa_signature_dupctx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))sss_rsa_signature_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))sss_rsa_signature_sign},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))sss_rsa_signature_digest_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))sss_rsa_signature_digest_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))sss_rsa_signature_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))sss_rsa_signature_digest_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))sss_rsa_signature_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))sss_rsa_signature_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))sss_rsa_signature_digest_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))sss_rsa_signature_digest_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))sss_rsa_signature_digest_verify_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))sss_rsa_signature_digest_verify},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))sss_rsa_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))sss_rsa_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))sss_rsa_signature_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))sss_rsa_gettable_ctx_params},

    {0, NULL}};

#endif //#if SSS_HAVE_RSA
