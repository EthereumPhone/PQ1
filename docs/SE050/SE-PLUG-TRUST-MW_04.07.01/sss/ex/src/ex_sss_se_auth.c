/*
*
* Copyright 2019 NXP
* SPDX-License-Identifier: Apache-2.0
*/

/** @file
*
* ex_sss_se050x_auth.c:  *The purpose and scope of this file*
*
* Project:  sss-doc-upstream
*
* $Date: Mar 10, 2019 $
* $Author: ing05193 $
* $Revision$
*/

/* *****************************************************************************************************************
* Includes
* ***************************************************************************************************************** */
#include <string.h>

#include "ex_sss_auth.h"
#include "ex_sss_boot_int.h"
#include "nxLog_App.h"
#include "nxScp03_Types.h"

/* *****************************************************************************************************************
* Internal Definitions
* ***************************************************************************************************************** */

/* *****************************************************************************************************************
* Type Definitions
* ***************************************************************************************************************** */

/* *****************************************************************************************************************
* Global and Static Variables
* Total Size: NNNbytes
* ***************************************************************************************************************** */

/* *****************************************************************************************************************
* Private Functions Prototypes
* ***************************************************************************************************************** */

#if SSS_HAVE_APPLET

#if SSS_HAVE_SCP_SCP03_SSS
static sss_status_t ex_sss_se_prepare_host_platformscp(
    NXSCP03_AuthCtx_t *pCtx, ex_SE05x_authCtx_t *pauthctx, sss_key_store_t *pKs);

static sss_status_t Alloc_Scp03key_toSEAuthctx(sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId);

#endif

/* *****************************************************************************************************************
* Public Functions
* ***************************************************************************************************************** */

#if SSS_HAVE_HOSTCRYPTO_ANY
sss_status_t ex_sss_se_prepare_host(sss_session_t *host_session,
    sss_key_store_t *host_ks,
    SE_Connect_Ctx_t *se05x_open_ctx,
    ex_SE05x_authCtx_t *se05x_auth_ctx,
    SE_AuthType_t auth_type)
{
    sss_status_t status = kStatus_SSS_Fail;

    if (host_session->subsystem == kType_SSS_SubSystem_NONE) {
        sss_type_t hostsubsystem = kType_SSS_SubSystem_NONE;

        hostsubsystem = kType_SSS_Software;

        status = sss_host_session_open(host_session, hostsubsystem, 0, kSSS_ConnectionType_Plain, NULL);

        if (kStatus_SSS_Success != status) {
            LOG_E("Failed to open Host Session");
            goto cleanup;
        }
        status = sss_host_key_store_context_init(host_ks, host_session);
        if (kStatus_SSS_Success != status) {
            LOG_E("Host: sss_key_store_context_init failed");
            goto cleanup;
        }
        status = sss_host_key_store_allocate(host_ks, __LINE__);
        if (kStatus_SSS_Success != status) {
            LOG_E("Host: sss_key_store_allocate failed");
            goto cleanup;
        }
    }
    switch (auth_type) {
#if SSS_HAVE_SCP_SCP03_SSS
    case kSSS_AuthType_SCP03:
        status = ex_sss_se_prepare_host_platformscp(&se05x_open_ctx->auth.ctx.scp03, se05x_auth_ctx, host_ks);
        break;
#endif
    case kSSS_AuthType_None:
        /* Nothing to do */
        status = kStatus_SSS_Success;
        break;
    default:
        status = kStatus_SSS_Fail;
        LOG_E("Not handled");
    }

    if (kStatus_SSS_Success != status) {
        LOG_E(
            "Host: ex_sss_se05x_prepare_host_<type=(SE_AuthType_t)%d> "
            "failed",
            auth_type);
        goto cleanup;
    }
    se05x_open_ctx->auth.authType = auth_type;

cleanup:
    return status;
}
#endif // SSS_HAVE_HOSTCRYPTO_ANY

/* *****************************************************************************************************************
* Private Functions
* ***************************************************************************************************************** */

#if SSS_HAVE_SCP_SCP03_SSS
/* Function to Set Init and Allocate static Scp03Keys and Init Allocate dynamic keys */
static sss_status_t ex_sss_se_prepare_host_platformscp(
    NXSCP03_AuthCtx_t *pAuthCtx, ex_SE05x_authCtx_t *pEx_auth, sss_key_store_t *pKs)
{
    sss_status_t status              = kStatus_SSS_Fail;
    uint8_t KEY_ENC[]                = EX_SSS_AUTH_SE05X_KEY_ENC;
    uint8_t KEY_MAC[]                = EX_SSS_AUTH_SE05X_KEY_MAC;
    uint8_t KEY_DEK[]                = EX_SSS_AUTH_SE05X_KEY_DEK;
    pAuthCtx->pStatic_ctx            = &pEx_auth->scp03.ex_static;
    pAuthCtx->pDyn_ctx               = &pEx_auth->scp03.ex_dyn;
    NXSCP03_StaticCtx_t *pStatic_ctx = pAuthCtx->pStatic_ctx;
    NXSCP03_DynCtx_t *pDyn_ctx       = pAuthCtx->pDyn_ctx;

    pStatic_ctx->keyVerNo = EX_SSS_AUTH_SE05X_KEY_VERSION_NO;

    /* Init Allocate ENC Static Key */
    status = Alloc_Scp03key_toSEAuthctx(&pStatic_ctx->Enc, pKs, MAKE_TEST_ID(__LINE__));
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Set ENC Static Key */
    status = sss_host_key_store_set_key(pKs, &pStatic_ctx->Enc, KEY_ENC, 16, 16 * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate MAC Static Key */
    status = Alloc_Scp03key_toSEAuthctx(&pStatic_ctx->Mac, pKs, MAKE_TEST_ID(__LINE__));
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Set MAC Static Key */
    status = sss_host_key_store_set_key(pKs, &pStatic_ctx->Mac, KEY_MAC, 16, 16 * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate DEK Static Key */
    status = Alloc_Scp03key_toSEAuthctx(&pStatic_ctx->Dek, pKs, MAKE_TEST_ID(__LINE__));
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Set DEK Static Key */
    status = sss_host_key_store_set_key(pKs, &pStatic_ctx->Dek, KEY_DEK, 16, 16 * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate ENC Session Key */
    status = Alloc_Scp03key_toSEAuthctx(&pDyn_ctx->Enc, pKs, MAKE_TEST_ID(__LINE__));
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Init Allocate MAC Session Key */
    status = Alloc_Scp03key_toSEAuthctx(&pDyn_ctx->Mac, pKs, MAKE_TEST_ID(__LINE__));
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Init Allocate DEK Session Key */
    status = Alloc_Scp03key_toSEAuthctx(&pDyn_ctx->Rmac, pKs, MAKE_TEST_ID(__LINE__));
    return status;
}
#endif

#if SSS_HAVE_SCP_SCP03_SSS
static sss_status_t Alloc_Scp03key_toSEAuthctx(sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId)
{
    sss_status_t status = kStatus_SSS_Fail;
    status              = sss_host_key_object_init(keyObject, pKs);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    status = sss_host_key_object_allocate_handle(
        keyObject, keyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, 16, kKeyObject_Mode_Transient);
    return status;
}

#endif
#endif
