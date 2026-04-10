/**
 * @file sssProvider_file_store.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for file store to decode reference keys or
 * openssl keys
 *
 */

/* ********************** Include files ********************** */
#include "sssProvider_main.h"
#include <limits.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/pem.h>
#include <openssl/store.h>
#include <string.h>

/* ********************** Public funtions ******************* */

#define USE_OSSL_PARAM_CALLS 1

int sss_handle_ecc_ref_key(sss_provider_store_obj_t *pStoreCtx, EVP_PKEY *pEVPKey)
{
    int ret                       = 1;
    size_t i                      = 0;
    sss_status_t status           = kStatus_SSS_Fail;
    unsigned char privKeyBuf[256] = {
        0,
    };
    size_t privKeyLen = 0;
    U32 Coeff[2]      = {0, 0};

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pEVPKey != NULL);

#if USE_OSSL_PARAM_CALLS
    {
        int j = 0;
        OSSL_PARAM params[2];
        int openssl_ret = 0;

        params[0]   = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, &privKeyBuf[0], sizeof(privKeyBuf));
        params[1]   = OSSL_PARAM_construct_end();
        openssl_ret = EVP_PKEY_get_params(pEVPKey, params);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        privKeyLen = params[0].data_size;

        for (size_t start = 0, end = privKeyLen - 1; start < end; start++, end--) {
            unsigned char temp = privKeyBuf[start];
            privKeyBuf[start]  = privKeyBuf[end];
            privKeyBuf[end]    = temp;
        }

        for (j = 0; j < 2; j++) {
            for (i = 3; i < 7; i++) {
                Coeff[j] |= privKeyBuf[privKeyLen - i - (j * 4)] << 8 * (i - 3);
            }
        }

        if (((unsigned int)Coeff[0] == (unsigned int)SIGNATURE_REFKEY_ID) &&
            ((unsigned int)Coeff[1] == (unsigned int)SIGNATURE_REFKEY_ID)) {
            j = 2;
            for (i = 3; i < 7; i++) {
                pStoreCtx->keyid |= privKeyBuf[privKeyLen - i - (j * 4)] << 8 * (i - 3);
            }
        }
        else {
            // Not a reference key
            goto cleanup;
        }
    }

#else
    {
        size_t index               = 0;
        unsigned char *pPrivKeyBuf = &privKeyBuf[0];
        privKeyLen                 = i2d_PrivateKey(pEVPKey, &pPrivKeyBuf);
        ENSURE_OR_GO_CLEANUP(privKeyLen > 0);

        for (i = 0; i < (privKeyLen - 4); i++) {
            // get the reference key signature id (first part)
            Coeff[0] =
                (privKeyBuf[i] << 24) | (privKeyBuf[i + 1] << 16) | (privKeyBuf[i + 2] << 8) | (privKeyBuf[i + 3]);
            if ((unsigned int)Coeff[0] == (unsigned int)SIGNATURE_REFKEY_ID) {
                index = i - 4;
                break;
            }
        }

        if (index == 0) {
            // Not a ref key
            goto cleanup;
        }

        // get the reference key signature id (second part)
        i        = i + 4;
        Coeff[1] = (privKeyBuf[i] << 24) | (privKeyBuf[i + 1] << 16) | (privKeyBuf[i + 2] << 8) | (privKeyBuf[i + 3]);
        if ((unsigned int)Coeff[1] != (unsigned int)SIGNATURE_REFKEY_ID) {
            goto cleanup;
        }

        ENSURE_OR_GO_CLEANUP((index + 4) < privKeyLen);
        pStoreCtx->keyid = ((unsigned int)privKeyBuf[index] << 24) | ((unsigned int)privKeyBuf[index + 1] << 16) |
                           ((unsigned int)privKeyBuf[index + 2] << 8) | (unsigned int)privKeyBuf[index + 3];
    }
#endif

    if (pStoreCtx->isEVPKey) {
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        status = sss_key_object_init(&(pStoreCtx->object), &pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_key_object_get_handle(&(pStoreCtx->object), pStoreCtx->keyid);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    }

    pStoreCtx->isEVPKey = 0;
    ret                 = 0;
cleanup:
    return ret;
}

int sss_handle_rsa_ref_key(sss_provider_store_obj_t *pStoreCtx, EVP_PKEY *pEVPKey)
{
    int ret             = 1;
    sss_status_t status = kStatus_SSS_Fail;
    int openssl_ret     = 0;
    size_t coefficient1 = 0;
    size_t keyid        = 0;

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pEVPKey != NULL);

    openssl_ret = EVP_PKEY_get_size_t_param(pEVPKey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &coefficient1);
    ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

    /* confirm that the key is reference key */
    if (coefficient1 != SIGNATURE_REFKEY_ID) {
        // Not a reference key
        goto cleanup;
    }

    openssl_ret = EVP_PKEY_get_size_t_param(pEVPKey, OSSL_PKEY_PARAM_RSA_FACTOR2, &keyid);
    ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

    ENSURE_OR_GO_CLEANUP(keyid <= UINT32_MAX);
    pStoreCtx->keyid = keyid;

    if (pStoreCtx->isEVPKey) {
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        status = sss_key_object_init(&(pStoreCtx->object), &pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_key_object_get_handle(&(pStoreCtx->object), pStoreCtx->keyid);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    }

    pStoreCtx->isEVPKey = 0;
    ret                 = 0;
cleanup:
    return ret;
}

/* ********************** Private funtions ******************* */

static void *sss_file_store_object_open(void *provctx, const char *uri)
{
    sss_provider_store_obj_t *pStoreCtx = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (uri == NULL) {
        return NULL;
    }

    if ((pStoreCtx = OPENSSL_zalloc(sizeof(sss_provider_store_obj_t))) == NULL) {
        return NULL;
    }

    /*
  Set it to 1.
  We do not know yet if the file is reference key or actual key
  */
    pStoreCtx->isEVPKey = 1;

    pStoreCtx->pProvCtx = provctx;

    // Opening the pem file
    pStoreCtx->pFile = fopen(uri, "rb");
    if (pStoreCtx->pFile == NULL) {
        OPENSSL_clear_free(pStoreCtx, sizeof(sss_provider_store_obj_t));
        pStoreCtx = NULL;
    }

    return pStoreCtx;
}

static int sss_file_store_object_load(
    void *ctx, OSSL_CALLBACK *object_cb, void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    int ret                             = 1;
    sss_provider_store_obj_t *pStoreCtx = ctx;
    OSSL_PARAM params[5];
    int object_type        = OSSL_OBJECT_UNKNOWN;
    const char *keytype    = NULL;
    EVP_PKEY *pEVPKey      = NULL;
    int i                  = 0;
    int buf_len            = 0;
    unsigned char *buffer  = NULL;
    unsigned char *pbuffer = NULL;
    X509 *x509             = NULL;
    char buf[30]           = {
        0,
    };
    bool isPEM = false;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(pw_cb);
    (void)(pw_cbarg);

    if (pStoreCtx == NULL || pStoreCtx->pFile == NULL) {
        return 0;
    }

    if (pStoreCtx->expected_type == OSSL_STORE_INFO_PARAMS) {
        pStoreCtx->pFile = NULL;
        return 0;
    }
    ENSURE_OR_GO_EXIT(fgets(buf, sizeof(buf), pStoreCtx->pFile) != NULL);
    ENSURE_OR_GO_EXIT(fseek(pStoreCtx->pFile, 0, SEEK_SET) == 0);
    if (strstr(buf, "-----BEGIN") != NULL) {
        isPEM = true;
    }

    if (isPEM) {
        pEVPKey = PEM_read_PrivateKey(pStoreCtx->pFile, NULL, NULL, NULL);
    }
    else {
        pEVPKey = d2i_PrivateKey_fp(pStoreCtx->pFile, NULL);
    }
    if (pEVPKey) /* Handle private key */
    {
        pStoreCtx->pEVPPkey     = pEVPKey;
        pStoreCtx->isPrivateKey = true;

        if (EVP_PKEY_id(pEVPKey) == EVP_PKEY_EC) {
            keytype = "EC";
            /* If reference key, pStoreCtx->isEVPKey is set to 0 in the below call. */
            ret = sss_handle_ecc_ref_key(pStoreCtx, pEVPKey);
            if (ret != 0) {
                /* Not a ref key */
                sssProv_Print(LOG_FLOW_ON, "Not a ref key \n");
            }
            object_type = OSSL_OBJECT_PKEY;
        }
        else if (EVP_PKEY_id(pEVPKey) == EVP_PKEY_RSA) {
            keytype = "RSA";
            /* If reference key, pStoreCtx->isEVPKey is set to 0 in the below call. */
            ret = sss_handle_rsa_ref_key(pStoreCtx, pEVPKey);
            if (ret != 0) {
                /* Not a ref key */
                sssProv_Print(LOG_FLOW_ON, "Not a ref key \n");
            }
            object_type = OSSL_OBJECT_PKEY;
        }
        else {
            keytype     = "unknown";
            object_type = OSSL_OBJECT_UNKNOWN;
        }
        goto key_read_complete;
    }

    ENSURE_OR_GO_EXIT(fseek(pStoreCtx->pFile, 0, SEEK_SET) == 0);
    if (isPEM) {
        pEVPKey = PEM_read_PUBKEY(pStoreCtx->pFile, NULL, NULL, NULL);
    }
    else {
        pEVPKey = d2i_PUBKEY_fp(pStoreCtx->pFile, NULL);
    }
    if (pEVPKey) /* Handle public key */
    {
        pStoreCtx->isPrivateKey = false;
        pStoreCtx->pEVPPkey     = pEVPKey;
        pStoreCtx->isEVPKey     = 1;
        if (EVP_PKEY_RSA == EVP_PKEY_id(pStoreCtx->pEVPPkey)) {
            keytype     = "RSA";
            object_type = OSSL_OBJECT_PKEY;
        }
        else if (EVP_PKEY_EC == EVP_PKEY_id(pStoreCtx->pEVPPkey)) {
            keytype     = "EC";
            object_type = OSSL_OBJECT_PKEY;
        }
        else {
            keytype     = "unknown";
            object_type = OSSL_OBJECT_UNKNOWN;
        }
        goto key_read_complete;
    }

    ENSURE_OR_GO_EXIT(fseek(pStoreCtx->pFile, 0L, SEEK_SET) == 0);
    if (isPEM) {
        x509 = PEM_read_X509(pStoreCtx->pFile, &x509, NULL, NULL);
    }
    else {
        x509 = d2i_X509_fp(pStoreCtx->pFile, NULL);
    }
    if (x509 != NULL) {
        buf_len = i2d_X509(x509, NULL);
        ENSURE_OR_GO_EXIT(buf_len > 0);
        buffer = OPENSSL_malloc(buf_len);
        ENSURE_OR_GO_EXIT(buffer != NULL);
        pbuffer = buffer;
        ENSURE_OR_GO_EXIT(i2d_X509(x509, &pbuffer) > 0);
        pStoreCtx->isPrivateKey = false;
        pStoreCtx->pEVPPkey     = NULL;
        pStoreCtx->isEVPKey     = 1;
        keytype                 = "CERTIFICATE";
        object_type             = OSSL_OBJECT_CERT;
        params[i++]             = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, (char *)buffer, buf_len);
        goto key_read_complete;
    }

    keytype     = "unknown";
    object_type = OSSL_OBJECT_UNKNOWN;

key_read_complete:
    params[i++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)keytype, 0);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &pStoreCtx, sizeof(pStoreCtx));
    params[i++] = OSSL_PARAM_construct_end();

    ret = object_cb(params, object_cbarg);
exit:
    if (x509 != NULL) {
        X509_free(x509);
    }
    if (buffer != NULL) {
        OPENSSL_free(buffer);
    }
    return ret;
}

static const OSSL_PARAM *sss_file_settable_ctx_params(void *provctx)
{
    (void)(provctx);
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL), OSSL_PARAM_END};
    return known_settable_ctx_params;
}

static int sss_file_set_ctx_params(void *provctx, const OSSL_PARAM params[])
{
    sss_provider_store_obj_t *pStoreCtx = provctx;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    const OSSL_PARAM *p;

    if (params == NULL) {
        return 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT);
    if (p != NULL && !OSSL_PARAM_get_int(p, &pStoreCtx->expected_type)) {
        return 0;
    }

    return 1;
}

static int sss_file_store_object_eof(void *ctx)
{
    sss_provider_store_obj_t *pStoreCtx = ctx;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pStoreCtx != NULL) {
        if (pStoreCtx->pFile != NULL) {
            return 0;
        }
    }
    return 1;
}

static int sss_file_store_object_close(void *ctx)
{
    sss_provider_store_obj_t *pStoreCtx = ctx;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pStoreCtx != NULL) {
        if (pStoreCtx->pFile != NULL) {
            if (fclose(pStoreCtx->pFile) < 0) {
                // return 0;
            }
        }
        if (pStoreCtx->pEVPPkey == NULL) { /* Provider store object with EVP Key are
                                          freed in key mgmt APIs */
            OPENSSL_free(pStoreCtx);
        }
    }
    return 1;
}

const OSSL_DISPATCH sss_file_store_object_functions[] = {
    {OSSL_FUNC_STORE_OPEN, (void (*)(void))sss_file_store_object_open},
    {OSSL_FUNC_STORE_LOAD, (void (*)(void))sss_file_store_object_load},
    {OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void (*)(void))sss_file_settable_ctx_params},
    {OSSL_FUNC_STORE_SET_CTX_PARAMS, (void (*)(void))sss_file_set_ctx_params},
    {OSSL_FUNC_STORE_EOF, (void (*)(void))sss_file_store_object_eof},
    {OSSL_FUNC_STORE_CLOSE, (void (*)(void))sss_file_store_object_close},
    {0, NULL}};
