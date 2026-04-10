/**
 * @file sssProvider_store.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for file store to decode key labels
 *
 */

/* ********************** Include files ********************** */
#include "sssProvider_main.h"
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/pem.h>
#include <string.h>

/* ********************** Funtions declarations ******************* */

int sss_handle_ecc_ref_key(sss_provider_store_obj_t *pStoreCtx, EVP_PKEY *pEVPKey);
int sss_handle_rsa_ref_key(sss_provider_store_obj_t *pStoreCtx, EVP_PKEY *pEVPKey);

/* ********************** Private funtions ******************* */

static void *sss_store_object_open(void *provctx, const char *uri)
{
    sss_provider_store_obj_t *pStoreCtx;
    FILE *pFile             = NULL;
    char *baseuri           = NULL;
    char *endptr            = NULL;
    unsigned long int value = 0;
    EVP_PKEY *pEVPKey       = NULL;
    int ret                 = 1;
    char buf[30]            = {
        0,
    };
    bool isPEM = false;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if ((pStoreCtx = OPENSSL_zalloc(sizeof(sss_provider_store_obj_t))) == NULL) {
        return NULL;
    }

    baseuri = OPENSSL_strdup(uri);
    if (baseuri == NULL) {
        OPENSSL_free(pStoreCtx);
        return NULL;
    }

    if (strncmp(baseuri, "nxp:0x", 6) == 0) {
        // converting string str  to unsigned long int value base on the base
        // extracting the keyid from the uri nxp:0xxxxxxxxx"
        value = strtoul((baseuri + 4), &endptr, 16);
        if (*endptr != 0 || value > UINT32_MAX) {
            OPENSSL_free(pStoreCtx);
            OPENSSL_free(baseuri);
            return NULL;
        }

        pStoreCtx->keyid    = value;
        pStoreCtx->pProvCtx = provctx;
        pStoreCtx->isEVPKey = 0;
    }
    else {
        // Reference key files with nxp: prefix comes here.
        // Extracting the file path
        char *filePath = strchr(baseuri, ':');
        if (filePath != NULL) {
            filePath++;
        }
        else {
            OPENSSL_free(pStoreCtx);
            OPENSSL_free(baseuri);
            return NULL;
        }
        // Opening the pem file
        pFile = fopen(filePath, "rb");
        if (pFile == NULL) {
            OPENSSL_free(pStoreCtx);
            OPENSSL_free(baseuri);
            return NULL;
        }

        if (fgets(buf, sizeof(buf), pFile) == NULL) {
            if (fclose(pFile) != 0) {
                sssProv_Print(LOG_FLOW_ON, "file close failed \n");
            }
            OPENSSL_free(pStoreCtx);
            OPENSSL_free(baseuri);
            return NULL;
        }
        if (fseek(pFile, 0, SEEK_SET) != 0) {
            if (fclose(pFile) != 0) {
                sssProv_Print(LOG_FLOW_ON, "file close failed \n");
            }
            OPENSSL_free(pStoreCtx);
            OPENSSL_free(baseuri);
            return NULL;
        }
        if (strstr(buf, "-----BEGIN") != NULL) {
            isPEM = true;
        }

        // Read file
        if (isPEM) {
            pEVPKey = PEM_read_PrivateKey(pFile, NULL, NULL, NULL);
        }
        else {
            pEVPKey = d2i_PrivateKey_fp(pFile, NULL);
        }
        if (pEVPKey == NULL) {
            if (fclose(pFile) != 0) {
                sssProv_Print(LOG_FLOW_ON, "file close failed \n");
            }
            OPENSSL_free(pStoreCtx);
            OPENSSL_free(baseuri);
            return NULL;
        }

        // reference key is a private key
        pStoreCtx->isPrivateKey = true;

        if (EVP_PKEY_id(pEVPKey) == EVP_PKEY_EC) {
            ret = sss_handle_ecc_ref_key(pStoreCtx, pEVPKey);
            if (ret != 0) {
                /* Not a ref key */
                sssProv_Print(LOG_FLOW_ON, "Not a ref key \n");
                if (fclose(pFile) != 0) {
                    sssProv_Print(LOG_FLOW_ON, "file close failed \n");
                }
                OPENSSL_free(pStoreCtx);
                OPENSSL_free(baseuri);
                return NULL;
            }
        }
        else if (EVP_PKEY_id(pEVPKey) == EVP_PKEY_RSA) {
            ret = sss_handle_rsa_ref_key(pStoreCtx, pEVPKey);
            if (ret != 0) {
                /* Not a ref key */
                sssProv_Print(LOG_FLOW_ON, "Not a ref key \n");
                if (fclose(pFile) != 0) {
                    sssProv_Print(LOG_FLOW_ON, "file close failed \n");
                }
                OPENSSL_free(pStoreCtx);
                OPENSSL_free(baseuri);
                return NULL;
            }
        }
        else {
            sssProv_Print(LOG_FLOW_ON, "Unknown Key type \n");
            if (fclose(pFile) != 0) {
                sssProv_Print(LOG_FLOW_ON, "file close failed \n");
            }
            OPENSSL_free(pStoreCtx);
            OPENSSL_free(baseuri);
            return NULL;
        }

        pStoreCtx->pProvCtx = provctx;
        if (fclose(pFile) != 0) {
            sssProv_Print(LOG_FLOW_ON, "file close failed \n");
        }
    }

    if (baseuri != NULL) {
        OPENSSL_free(baseuri);
    }
    if (pEVPKey != NULL) {
        EVP_PKEY_free(pEVPKey);
    }
    return pStoreCtx;
}

static int sss_store_object_load(
    void *ctx, OSSL_CALLBACK *object_cb, void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)ctx;
    sss_status_t status                 = kStatus_SSS_Fail;
    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;
    const char *keytype;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(pw_cb);
    (void)(pw_cbarg);

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

    status = sss_key_object_init(&(pStoreCtx->object), &pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&(pStoreCtx->object), pStoreCtx->keyid);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    if (pStoreCtx->object.cipherType == kSSS_CipherType_EC_NIST_P ||
        pStoreCtx->object.cipherType == kSSS_CipherType_EC_BRAINPOOL ||
        pStoreCtx->object.cipherType == kSSS_CipherType_EC_NIST_K) {
        keytype = "EC";
    }
    else if (pStoreCtx->object.cipherType == kSSS_CipherType_RSA ||
             pStoreCtx->object.cipherType == kSSS_CipherType_RSA_CRT) {
        keytype = "RSA";
    }
    else {
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)keytype, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &pStoreCtx, sizeof(pStoreCtx));
    params[3] = OSSL_PARAM_construct_end();

    return object_cb(params, object_cbarg);
cleanup:
    return 0;
}

static int sss_store_object_eof(void *ctx)
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)ctx;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pStoreCtx == NULL) {
        return 0;
    }

    if (pStoreCtx->object.keyId == 0) {
        return 0;
    }
    else {
        return 1;
    }
}

static int sss_store_object_close(void *ctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(ctx);
    return 1;
}

static const OSSL_PARAM *sss_store_settable_ctx_params(void *provctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(provctx);
    static const OSSL_PARAM known_settable_ctx_params[] = {OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
        OSSL_PARAM_END};
    return known_settable_ctx_params;
}

static int sss_store_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)ctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    char *propq = NULL;

    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_PROPERTIES);
    if (p != NULL && !OSSL_PARAM_get_utf8_string(p, &propq, 0))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT);
    if (p != NULL && !OSSL_PARAM_get_int(p, &pStoreCtx->expected_type)) {
        return 0;
    }

    if (propq != NULL) {
        free(propq); /*propq is not being used as of now*/
    }

    return 1;
}

const OSSL_DISPATCH sss_store_object_functions[] = {{OSSL_FUNC_STORE_OPEN, (void (*)(void))sss_store_object_open},
    {OSSL_FUNC_STORE_LOAD, (void (*)(void))sss_store_object_load},
    {OSSL_FUNC_STORE_EOF, (void (*)(void))sss_store_object_eof},
    {OSSL_FUNC_STORE_CLOSE, (void (*)(void))sss_store_object_close},
    {OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void (*)(void))sss_store_settable_ctx_params},
    {OSSL_FUNC_STORE_SET_CTX_PARAMS, (void (*)(void))sss_store_set_ctx_params},
    {0, NULL}};
