/**
 * @file sssProvider_ecdh.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022,2024,2025 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for ECDH using SSS API's
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
#include <string.h>

/* ********************** structure definition *************** */
typedef struct
{
    EVP_PKEY *pPeerEVPPkey;
    sss_provider_store_obj_t *pStoreObjCtx; // Host key object
    sss_provider_context_t *pProvCtx;
} sss_provider_ecdh_ctx_st;

/* ********************** Private funtions ******************* */

static void *sss_ecdh_keyexch_newctx(void *provctx)
{
    sss_provider_ecdh_ctx_st *pEcdhCtx = OPENSSL_zalloc(sizeof(sss_provider_ecdh_ctx_st));
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (pEcdhCtx != NULL) {
        pEcdhCtx->pProvCtx = provctx;
    }
    return pEcdhCtx;
}

static void sss_ecdh_keyexch_freectx(void *ctx)
{
    sss_provider_ecdh_ctx_st *pEcdhctx = ctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (pEcdhctx != NULL) {
        if (pEcdhctx->pPeerEVPPkey != NULL) {
            EVP_PKEY_free(pEcdhctx->pPeerEVPPkey);
            pEcdhctx->pPeerEVPPkey = NULL;
        }
        OPENSSL_clear_free(pEcdhctx, sizeof(sss_provider_ecdh_ctx_st));
    }
    return;
}

static int sss_ecdh_keyexch_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    int ret                             = 0;
    sss_provider_ecdh_ctx_st *pEcdhctx  = ctx;
    sss_provider_store_obj_t *pStoreCtx = provkey;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(params);
    ENSURE_OR_GO_CLEANUP(pEcdhctx != NULL && pStoreCtx != NULL);
    pEcdhctx->pStoreObjCtx = pStoreCtx;
    ret                    = 1;
cleanup:
    return ret;
}

static int sss_ecdh_keyexch_set_peer(void *ctx, void *provkey)
{
    int ret                             = 0;
    sss_provider_store_obj_t *pStoreCtx = provkey;
    sss_provider_ecdh_ctx_st *pEcdhctx  = ctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    ENSURE_OR_GO_CLEANUP(pEcdhctx != NULL && pStoreCtx != NULL);
    pEcdhctx->pPeerEVPPkey = EVP_PKEY_dup(pStoreCtx->pEVPPkey);
    ret                    = 1;
cleanup:
    return ret;
}

static int sss_ecdh_keyexch_derive(void *ctx, unsigned char *secret, size_t *secretlen, size_t outlen)
{
    int ret                            = 0;
    sss_provider_ecdh_ctx_st *pEcdhctx = ctx;
    sss_se05x_session_t *pSession      = NULL;
    EVP_PKEY_CTX *evpCtx               = NULL;
    int openssl_ret                    = 0;
    int evp_secretLen;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    ENSURE_OR_GO_CLEANUP(pEcdhctx != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdhctx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(secretlen != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdhctx->pPeerEVPPkey != NULL);

    if (pEcdhctx->pStoreObjCtx->isEVPKey == 0) {
        ENSURE_OR_GO_CLEANUP(pEcdhctx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pEcdhctx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        pSession = (sss_se05x_session_t *)&(pEcdhctx->pProvCtx->p_ex_sss_boot_ctx->session);
        ENSURE_OR_GO_CLEANUP(pSession != NULL);

        if (secret == NULL) {
            evp_secretLen = EVP_PKEY_size(pEcdhctx->pPeerEVPPkey);
            if (evp_secretLen < 0) {
                return 0;
            }
            *secretlen = (size_t)evp_secretLen;
            return (*secretlen > 0);
        }
        else {
            smStatus_t sm_status;
            uint8_t pubBuf[256] = {
                0,
            };
            size_t pubBufLen         = 0;
            unsigned char *pubKeyPtr = pubBuf;
            /* Get the public key from the peer key */
            openssl_ret = i2d_PublicKey(pEcdhctx->pPeerEVPPkey, &pubKeyPtr);
            if (openssl_ret > 0) {
                pubBufLen = openssl_ret;
            }
            else {
                goto cleanup;
            }

            sssProv_Print(LOG_FLOW_ON, "Performing ECDH on SE05x \n");
            sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pEcdhctx->pStoreObjCtx->keyid);

            sm_status = Se05x_API_ECDHGenerateSharedSecret(
                &(pSession->s_ctx), pEcdhctx->pStoreObjCtx->keyid, pubBuf, pubBufLen, secret, secretlen);
            ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
        }
    }
    else {
        /* Roll back to software implementation */
        if (secret == NULL) {
            evp_secretLen = EVP_PKEY_size(pEcdhctx->pPeerEVPPkey);
            if (evp_secretLen < 0) {
                return 0;
            }
            *secretlen = (size_t)evp_secretLen;
            return (*secretlen > 0);
        }
        else {
            size_t secret_len = outlen;

            ENSURE_OR_GO_CLEANUP(pEcdhctx->pStoreObjCtx->pEVPPkey != NULL);

            sssProv_Print(LOG_FLOW_ON, "Not a key in secure element. Performing ECDH on host software \n");

            evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pEcdhctx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            openssl_ret = EVP_PKEY_derive_init(evpCtx);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            openssl_ret = EVP_PKEY_derive_set_peer(evpCtx, pEcdhctx->pPeerEVPPkey);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            openssl_ret = EVP_PKEY_derive(evpCtx, secret, &secret_len);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            *secretlen = secret_len;
        }
    }

    ret = 1;
cleanup:
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

const OSSL_DISPATCH sss_ecdh_keyexch_functions[] = {{OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))sss_ecdh_keyexch_newctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))sss_ecdh_keyexch_init},
    {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))sss_ecdh_keyexch_set_peer},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))sss_ecdh_keyexch_derive},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))sss_ecdh_keyexch_freectx},
    {0, NULL}};

#endif //#if SSS_HAVE_ECC
