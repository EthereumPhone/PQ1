/*
*
* Copyright 2019,2020 NXP
* SPDX-License-Identifier: Apache-2.0
*/

#include "se05x_SetAppletFeatures.h"

#include <ex_sss_boot.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <se05x_tlv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smCom.h"

static ex_sss_boot_ctx_t gex_sss_features_boot_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_features_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    smStatus_t sw_status;
    Se05xSession_t *pSe05xSession;

    uint8_t appletVersion[7]              = {0};
    size_t appletVersionLen               = sizeof(appletVersion);
    Se05x_AppletFeatures_t appletFeatures = {0};

#if (SSS_HAVE_APPLET_SE05X_C || SSS_HAVE_APPLET_SE051_UWB)
    LOG_W("Compiled for Applet C");
    appletFeatures.variant = C_FEATURES;
#elif (SSS_HAVE_APPLET_SE05X_A || SSS_HAVE_APPLET_AUTH || SSS_HAVE_APPLET_SE050_E)
    LOG_W("Compiled for Applet A");
    appletFeatures.variant = A_FEATURES;
#elif SSS_HAVE_APPLET_SE05X_B
    LOG_W("Compiled for Applet B");
    appletFeatures.variant = B_FEATURES;
#else
#error "No applet selected"
#endif

#if SSS_HAVE_SE05X_VER_GTE_07_02
    SE05x_ExtendedFeatures_t extended = {0};
    extended.features[7] |= 0x80;
    appletFeatures.extended_features = &extended;
#else
    appletFeatures.extended_features = NULL;
#endif

    sss_session_close(&pCtx->session);
    status = session_open_with_feature_id(pCtx);
    if (status != kStatus_SSS_Success) {
        goto cleanup;
    }

    pSe05xSession = &pSession->s_ctx;

    sw_status = Se05x_API_GetVersion(pSe05xSession, appletVersion, &appletVersionLen);
    if (SM_OK == sw_status) {
        LOG_AU8_I(appletVersion, sizeof(appletVersion));
        SE05x_Variant_t features = (appletVersion[3] << 8) | appletVersion[4];
        if (features == appletFeatures.variant) {
            LOG_W("Trying to set existing features");
        }
    }
    else {
        LOG_E("Se05x_API_GetVersion failed");
        goto cleanup;
    }

    sw_status = Se05x_API_SetAppletFeatures(pSe05xSession, &appletFeatures);
    if (SM_OK != sw_status) {
        LOG_E("Se05x_API_SetAppletFeatures failed");
        goto cleanup;
    }

    sw_status = Se05x_API_GetVersion(pSe05xSession, appletVersion, &appletVersionLen);
    if (SM_OK == sw_status) {
        LOG_AU8_I(appletVersion, sizeof(appletVersion));
        SE05x_Variant_t features = (appletVersion[3] << 8) | appletVersion[4];
        if (features != appletFeatures.variant) {
            LOG_E("Mismatch setting features");
        }
        else {
            LOG_I("Features set successsfully");
        }
    }
    else {
        LOG_E("Se05x_API_GetVersion failed");
    }

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_SetAppletFeatures Example Success !!!...");
    }
    else {
        LOG_E("se05x_SetAppletFeatures Example Failed !!!...");
    }
    return status;
}

sss_status_t session_open_with_feature_id(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
#if (SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03)
    SE05x_Connect_Ctx_t *pchannlCtxt = &pCtx->se05x_open_ctx;
    pchannlCtxt->auth.authType       = kSSS_AuthType_ECKey;
    ex_SE05x_authCtx_t ex_se05x_auth;

    status = ex_sss_se05x_prepare_host_EX(
        &pCtx->host_session, &pCtx->host_ks, pchannlCtxt, &ex_se05x_auth, kSSS_AuthType_ECKey);
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_se05x_prepare_host_EX failed");
        goto cleanup;
    }

    pchannlCtxt->connType  = kType_SE_Conn_Type_Channel;
    pchannlCtxt->tunnelCtx = pCtx->pTunnel_ctx;

    status = sss_session_open(
        &pCtx->session, kType_SSS_SE_SE05x, kSE05x_AppletResID_FEATURE, kSSS_ConnectionType_Encrypted, pchannlCtxt);
    if (kStatus_SSS_Success != status) {
        LOG_E("sss_session_open failed");
    }
#else
    sss_session_t *pSession          = NULL;
    SE05x_Connect_Ctx_t *pConnectCtx = NULL;
    pConnectCtx                      = &pCtx->se05x_open_ctx;
    pSession                         = &pCtx->session;
    status                           = ex_sss_se05x_prepare_host_EX(
        &pCtx->host_session, &pCtx->host_ks, pConnectCtx, &pCtx->ex_se05x_auth, kSSS_AuthType_ECKey);
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_se05x_prepare_host_EX failed");
        goto cleanup;
    }

    status = sss_session_open(
        pSession, kType_SSS_SE_SE05x, kSE05x_AppletResID_FEATURE, kSSS_ConnectionType_Encrypted, pConnectCtx);
    if (kStatus_SSS_Success != status) {
        LOG_E("sss_session_open failed");
    }
#endif

cleanup:
    return status;
}

sss_status_t ex_sss_se05x_prepare_host_EX(sss_session_t *host_session,
    sss_key_store_t *host_ks,
    SE05x_Connect_Ctx_t *se05x_open_ctx,
    ex_SE05x_authCtx_t *se05x_auth_ctx,
    SE_AuthType_t auth_type)
{
    sss_status_t status = kStatus_SSS_Fail;

    if (host_session->subsystem == kType_SSS_SubSystem_NONE) {
        sss_type_t hostsubsystem = kType_SSS_SubSystem_NONE;

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
        hostsubsystem = kType_SSS_mbedTLS;
#endif

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
        hostsubsystem = kType_SSS_OpenSSL;
#endif
        status = sss_session_open(host_session, hostsubsystem, 0, kSSS_ConnectionType_Plain, NULL);
        if (kStatus_SSS_Success != status) {
            LOG_E("Failed to open Host Session");
            goto cleanup;
        }
        status = sss_key_store_context_init(host_ks, host_session);
        if (kStatus_SSS_Success != status) {
            LOG_E("Host: sss_key_store_context_init failed");
            goto cleanup;
        }
        status = sss_key_store_allocate(host_ks, __LINE__);
        if (kStatus_SSS_Success != status) {
            LOG_E("Host: sss_key_store_allocate failed");
            goto cleanup;
        }
    }
    switch (auth_type) {
#if SSS_HAVE_SCP_SCP03_SSS
    case kSSS_AuthType_ECKey:
        status = ex_sss_se05x_prepare_host_eckey_EX(&se05x_open_ctx->auth.ctx.eckey, se05x_auth_ctx, host_ks);
        break;
#endif
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

sss_status_t ex_sss_se05x_prepare_host_eckey_EX(
    SE05x_AuthCtx_ECKey_t *pAuthCtx, ex_SE05x_authCtx_t *pEx_auth, sss_key_store_t *pKs)
{
    AX_UNUSED_ARG(pEx_auth);
    sss_status_t status        = kStatus_SSS_Fail;
    uint8_t hostEcdsakey[1024] = {0};

    int argc          = gex_sss_argc;
    const char **argv = gex_sss_argv;

    for (int j = 1; j < argc; j++) {
        if (strcmp(argv[j], "-file") == 0) {
            j++;
            if (j >= argc) {
                LOG_E("Invalid argument");
                return kStatus_SSS_Fail;
            }
            const char *filename = argv[j];
            if (strstr(filename, "..") != NULL) {
                LOG_W("Potential directory traversal");
            }
            if (filename[0] == '/') {
                LOG_W("Accessing file using absolute path");
            }
            FILE *fp = fopen(filename, "rb");
            if (fp == NULL) {
                LOG_E("Cannot open file");
                return kStatus_SSS_Fail;
            }
            if (fread(hostEcdsakey, sizeof(hostEcdsakey), 1, fp) < 1) {
                LOG_E("fread error");
                if (fclose(fp) != 0) {
                    LOG_E("fclose error");
                }
                return kStatus_SSS_Fail;
            }
            if (fclose(fp) != 0) {
                LOG_E("fclose error");
            }
        }
    }

    NXECKey03_StaticCtx_t *pStatic_ctx = pAuthCtx->pStatic_ctx;
    NXSCP03_DynCtx_t *pDyn_ctx         = pAuthCtx->pDyn_ctx;

    /* Init allocate Host ECDSA Key pair */
    status =
        Alloc_ECKeykey_toSE05xAuthctx_EX(&pStatic_ctx->HostEcdsaObj, pKs, MAKE_TEST_ID(__LINE__), kSSS_KeyPart_Pair);
    /* Set Host ECDSA Key pair */
    status = sss_key_store_set_key(pKs, &pStatic_ctx->HostEcdsaObj, hostEcdsakey, sizeof(hostEcdsakey), 256, NULL, 0);
    if (status == kStatus_SSS_Fail) {
        return status;
    }

    /* Init allocate Host ECKA Key pair */
    status =
        Alloc_ECKeykey_toSE05xAuthctx_EX(&pStatic_ctx->HostEcKeypair, pKs, MAKE_TEST_ID(__LINE__), kSSS_KeyPart_Pair);
    /* Generate Host EC Key pair */
    status = sss_key_store_generate_key(pKs, &pStatic_ctx->HostEcKeypair, 256, NULL);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init allocate SE ECKA Public Key */
    status =
        Alloc_ECKeykey_toSE05xAuthctx_EX(&pStatic_ctx->SeEcPubKey, pKs, MAKE_TEST_ID(__LINE__), kSSS_KeyPart_Public);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate Master Secret */
    status = Alloc_Scp03key_toSE05xAuthctx_EX(&pStatic_ctx->masterSec, pKs, MAKE_TEST_ID(__LINE__));
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate ENC Session Key */
    status = Alloc_Scp03key_toSE05xAuthctx_EX(&pDyn_ctx->Enc, pKs, MAKE_TEST_ID(__LINE__));
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Init Allocate MAC Session Key */
    status = Alloc_Scp03key_toSE05xAuthctx_EX(&pDyn_ctx->Mac, pKs, MAKE_TEST_ID(__LINE__));
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Init Allocate DEK Session Key */
    status = Alloc_Scp03key_toSE05xAuthctx_EX(&pDyn_ctx->Rmac, pKs, MAKE_TEST_ID(__LINE__));

    return status;
}

sss_status_t Alloc_ECKeykey_toSE05xAuthctx_EX(
    sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId, sss_key_part_t keypart)
{
    sss_status_t status = kStatus_SSS_Fail;
    status              = sss_key_object_init(keyObject, pKs);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    status = sss_key_object_allocate_handle(
        keyObject, keyId, keypart, kSSS_CipherType_EC_NIST_P, 256, kKeyObject_Mode_Persistent);
    return status;
}

sss_status_t Alloc_Scp03key_toSE05xAuthctx_EX(sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId)
{
    sss_status_t status = kStatus_SSS_Fail;
    status              = sss_key_object_init(keyObject, pKs);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    status = sss_key_object_allocate_handle(
        keyObject, keyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, 16, kKeyObject_Mode_Transient);
    return status;
}
