/**
 * @file sssProvider_rsa_enc.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for RSA enc / dec using SSS API's
 *
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_RSA
/* ********************** Include files ********************** */
#include "sssProvider_main.h"
#include <openssl/core_names.h>
#include <openssl/rsa.h>
#include <string.h>

/* ********************** structure definition *************** */
typedef struct
{
    sss_algorithm_t enc_algorithm;
    sss_provider_store_obj_t *pStoreObjCtx;
    sss_provider_context_t *pProvCtx;
} sss_provider_rsa_enc_ctx_st;

/* ********************** Private funtions ******************* */

static void *sss_rsa_enc_newctx(void *provctx)
{
    sss_provider_rsa_enc_ctx_st *pRSACtx = OPENSSL_zalloc(sizeof(sss_provider_rsa_enc_ctx_st));
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (pRSACtx != NULL) {
        pRSACtx->pProvCtx = provctx;
    }
    return pRSACtx;
}

static int sss_rsa_enc_encrypt_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    int ret                              = 0;
    sss_provider_rsa_enc_ctx_st *pRsaCtx = ctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(params);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    pRsaCtx->pStoreObjCtx  = provkey;
    pRsaCtx->enc_algorithm = kAlgorithm_None;

    ret = 1;
cleanup:
    return ret;
}

static int sss_rsa_enc_encrypt(
    void *ctx, unsigned char *out, size_t *outlen, size_t outsize, const unsigned char *in, size_t inlen)
{
    sss_provider_rsa_enc_ctx_st *pRsaCtx = (sss_provider_rsa_enc_ctx_st *)ctx;
    int ret                              = 0;
    sss_status_t status;
    sss_asymmetric_t asymmCtx = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;
    int maxSize          = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(outsize);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(outlen != NULL);
    ENSURE_OR_GO_CLEANUP(in != NULL);

    if (pRsaCtx->pStoreObjCtx->object.keyId != 0) {
        if (out == NULL) {
            *outlen = pRsaCtx->pStoreObjCtx->key_len;
            return 1;
        }
        else {
            ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
            ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);
            ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);
            status = sss_asymmetric_context_init(&asymmCtx,
                &pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->session,
                &pRsaCtx->pStoreObjCtx->object,
                pRsaCtx->enc_algorithm,
                kMode_SSS_Encrypt);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            sssProv_Print(LOG_FLOW_ON, "Performing RSA Encrypt using SE05x \n");
            sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pRsaCtx->pStoreObjCtx->object.keyId);
            status = sss_asymmetric_encrypt(&asymmCtx, in, inlen, out, outlen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        }
    }
    else {
        /* Roll back to software implementation */

        ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        if (out == NULL) {
            maxSize = EVP_PKEY_size(pRsaCtx->pStoreObjCtx->pEVPPkey);
            if (maxSize > 0) {
                *outlen = maxSize;
                return 1;
            }
            else {
                return 0;
            }
        }
        else {
            int openssl_ret = 0;
            int padding     = 0;

            sssProv_Print(LOG_FLOW_ON,
                "Not a key in secure element. Performing RSA "
                "Encrypt operation using host software \n");

            switch (pRsaCtx->enc_algorithm) {
            case kAlgorithm_SSS_RSAES_PKCS1_V1_5:
                padding = RSA_PKCS1_PADDING;
                break;
            case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1:
                padding = RSA_PKCS1_OAEP_PADDING;
                break;
            default:
                sssProv_Print(LOG_ERR_ON, "Padding not supported ! \n");
            }

            evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pRsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            openssl_ret = EVP_PKEY_encrypt_init(evpCtx);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            if (EVP_PKEY_CTX_set_rsa_padding(evpCtx, padding) <= 0) {
                goto cleanup;
            }

            openssl_ret = EVP_PKEY_encrypt(evpCtx, out, outlen, in, inlen);
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

static int sss_rsa_enc_decrypt_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    int ret                              = 0;
    sss_provider_rsa_enc_ctx_st *pRsaCtx = ctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(params);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    pRsaCtx->pStoreObjCtx  = provkey;
    pRsaCtx->enc_algorithm = kAlgorithm_None;

    ret = 1;
cleanup:
    return ret;
}

static int sss_rsa_enc_decrypt(
    void *ctx, unsigned char *out, size_t *outlen, size_t outsize, const unsigned char *in, size_t inlen)
{
    sss_provider_rsa_enc_ctx_st *pRsaCtx = (sss_provider_rsa_enc_ctx_st *)ctx;
    int ret                              = 0;
    sss_status_t status;
    sss_asymmetric_t asymmCtx = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;
    int maxSize          = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(outsize);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(outlen != NULL);
    ENSURE_OR_GO_CLEANUP(in != NULL);

    if (pRsaCtx->pStoreObjCtx->object.keyId != 0) {
        if (out == NULL) {
            *outlen = pRsaCtx->pStoreObjCtx->key_len;
            return 1;
        }
        else {
            ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
            ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);
            ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);
            status = sss_asymmetric_context_init(&asymmCtx,
                &pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->session,
                &pRsaCtx->pStoreObjCtx->object,
                pRsaCtx->enc_algorithm,
                kMode_SSS_Encrypt);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            sssProv_Print(LOG_FLOW_ON, "Performing RSA Decrypt using SE05x \n");
            sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pRsaCtx->pStoreObjCtx->object.keyId);
            status = sss_asymmetric_decrypt(&asymmCtx, in, inlen, out, outlen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        }
    }
    else {
        /* Roll back to software implementation */

        ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        if (out == NULL) {
            maxSize = EVP_PKEY_size(pRsaCtx->pStoreObjCtx->pEVPPkey);
            if (maxSize > 0) {
                *outlen = maxSize;
                return 1;
            }
            else {
                return 0;
            }
        }
        else {
            int openssl_ret = 0;
            int padding     = 0;

            sssProv_Print(LOG_FLOW_ON,
                "Not a key in secure element. Performing RSA "
                "Decrypt operation using host software \n");

            switch (pRsaCtx->enc_algorithm) {
            case kAlgorithm_SSS_RSAES_PKCS1_V1_5:
                padding = RSA_PKCS1_PADDING;
                break;
            case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1:
                padding = RSA_PKCS1_OAEP_PADDING;
                break;
            default:
                sssProv_Print(LOG_ERR_ON, "Padding not supported ! \n");
            }

            evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pRsaCtx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            openssl_ret = EVP_PKEY_decrypt_init(evpCtx);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            if (EVP_PKEY_CTX_set_rsa_padding(evpCtx, padding) <= 0) {
                goto cleanup;
            }

            openssl_ret = EVP_PKEY_decrypt(evpCtx, out, outlen, in, inlen);
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

static void sss_rsa_enc_freectx(void *ctx)
{
    sss_provider_rsa_enc_ctx_st *sctx = ctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (sctx != NULL) {
        if (sctx->pStoreObjCtx->pEVPPkey != NULL) {
            EVP_PKEY_free(sctx->pStoreObjCtx->pEVPPkey);
            sctx->pStoreObjCtx->pEVPPkey = NULL;
        }
        OPENSSL_clear_free(sctx, sizeof(sss_provider_rsa_enc_ctx_st));
    }
    return;
}

static void *sss_rsa_enc_dupctx(void *ctx)
{
    sss_provider_rsa_enc_ctx_st *pRsaCtx    = (sss_provider_rsa_enc_ctx_st *)ctx;
    sss_provider_rsa_enc_ctx_st *pRsaDupCtx = OPENSSL_zalloc(sizeof(sss_provider_rsa_enc_ctx_st));

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(pRsaDupCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);

    pRsaDupCtx->pProvCtx      = pRsaCtx->pProvCtx;
    pRsaDupCtx->pStoreObjCtx  = pRsaCtx->pStoreObjCtx;
    pRsaDupCtx->enc_algorithm = pRsaCtx->enc_algorithm;

    return pRsaDupCtx;

cleanup:
    if (pRsaDupCtx != NULL) {
        OPENSSL_clear_free(pRsaDupCtx, sizeof(sss_provider_rsa_enc_ctx_st));
    }
    return NULL;
}

static int sss_rsa_enc_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p                  = NULL;
    int pad_mode                         = 0;
    sss_provider_rsa_enc_ctx_st *pRsaCtx = ctx;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pRsaCtx == NULL) {
        return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: {
            if (!OSSL_PARAM_get_int(p, &pad_mode)) {
                return 0;
            }
            if (pad_mode == RSA_PKCS1_PADDING) {
                pRsaCtx->enc_algorithm = kAlgorithm_SSS_RSAES_PKCS1_V1_5;
            }
            else if (pad_mode == RSA_PKCS1_OAEP_PADDING) {
                pRsaCtx->enc_algorithm = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1;
            }
            else {
                sssProv_Print(LOG_ERR_ON, "Padding not supported ! \n");
                return 0;
            }
        } break;
        case OSSL_PARAM_UTF8_STRING: {
            if (p->data == NULL) {
                return 0;
            }
            if (strcmp(p->data, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0) {
                pRsaCtx->enc_algorithm = kAlgorithm_SSS_RSAES_PKCS1_V1_5;
            }
            else if (strcmp(p->data, OSSL_PKEY_RSA_PAD_MODE_OAEP) == 0) {
                pRsaCtx->enc_algorithm = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1;
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

    return 1;
}

static const OSSL_PARAM *sss_rsa_enc_settable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
        OSSL_PARAM_END};

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(ctx);
    (void)(provctx);
    return known_settable_ctx_params;
}

const OSSL_DISPATCH sss_rsa_enc_functions[] = {{OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))sss_rsa_enc_newctx},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))sss_rsa_enc_encrypt_init},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))sss_rsa_enc_encrypt},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))sss_rsa_enc_decrypt_init},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))sss_rsa_enc_decrypt},
    {OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))sss_rsa_enc_freectx},
    {OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))sss_rsa_enc_dupctx},
    {OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))sss_rsa_enc_set_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))sss_rsa_enc_settable_ctx_params},
    {0, NULL}};

#endif //#if SSS_HAVE_RSA