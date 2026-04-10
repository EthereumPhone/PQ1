/* Copyright 2020 NXP
*
* SPDX-License-Identifier: Apache-2.0
*/

#include "se05x_TransportAuth.h"

#include <nxLog_App.h>
#include <se05x_APDU.h>

/* clang-format off */
#define TRANSPORT_AES_VALUE                     \
    {                                                \
       'L','O','C','K','C','O','M','M','U','N','T','X','T','O','S','E',    \
    }
/* clang-format ON */


const uint8_t Transport_AES_value[16] = TRANSPORT_AES_VALUE;
size_t  Transport_AES_valueLen = sizeof(Transport_AES_value);
//sss_object_t TransportObject = { 0 };
NXSCP03_StaticCtx_t staticCtx = { 0 };
NXSCP03_DynCtx_t dynamicCtx = { 0 };
SE_Connect_Ctx_t authTransportCtx = { 0 };

sss_status_t se05x_TA_OpenAuthSession(ex_sss_boot_ctx_t *pCtx,
    sss_session_t *pTxSession,
    sss_tunnel_t *ptxTunnel)
{
    sss_status_t status = kStatus_SSS_Fail;
    authTransportCtx.auth.ctx.scp03.pStatic_ctx = &staticCtx;
    authTransportCtx.auth.ctx.scp03.pDyn_ctx = &dynamicCtx;

    authTransportCtx.tunnelCtx = ptxTunnel;
    ptxTunnel->session = &pCtx->session;
    authTransportCtx.connType = kType_SE_Conn_Type_Channel;
    authTransportCtx.portName = NULL;
    authTransportCtx.auth.authType = kSSS_AuthType_AESKey;
    authTransportCtx.skip_select_applet = 1;

    status = sss_session_open(pTxSession, kType_SSS_SE_SE05x,
        kSE05x_AppletResID_TRANSPORT,
        kSSS_ConnectionType_Encrypted, &authTransportCtx);

    return status;
}


 sss_status_t se05x_TA_CreateHostKey(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    int i;
    sss_object_t * pObjects[6];
    pObjects[0] = &staticCtx.Dek;
    pObjects[1] = &staticCtx.Enc;
    pObjects[2] = &staticCtx.Mac;
    pObjects[3] = &dynamicCtx.Enc;
    pObjects[4] = &dynamicCtx.Mac;
    pObjects[5] = &dynamicCtx.Rmac;

    for (i = 0; i < 6; i++) {
        status = sss_host_key_object_init(pObjects[i], &pCtx->host_ks);
        if (kStatus_SSS_Success != status) {
            LOG_E("Failed sss_key_object_init ");
            goto cleanup;
        }
        status = sss_host_key_object_allocate_handle(pObjects[i],
            MAKE_TEST_ID(__LINE__),
            kSSS_KeyPart_Default,
            kSSS_CipherType_AES,
            Transport_AES_valueLen,
            kKeyObject_Mode_Transient);
        if (kStatus_SSS_Success != status) {
            LOG_E("Failed sss_key_object_allocate_handle");
            goto cleanup;
        }
    }
    for (i = 0; i < 3; i++) {
        status = sss_host_key_store_set_key(&pCtx->host_ks,
            pObjects[i],
            Transport_AES_value,
            Transport_AES_valueLen,
            Transport_AES_valueLen * 8,
            NULL,
            0);
        if (kStatus_SSS_Success != status) {
            LOG_E("Failed sss_key_store_set_key");
            goto cleanup;
        }
    }

    status = kStatus_SSS_Success;
    cleanup:
        return status;
}

smStatus_t se05x_TA_CreateSETransportLockKey(Se05xSession_t *pSe05xSession)
{
    smStatus_t sw_status = SM_NOT_OK;
    SE05x_Result_t exists = kSE05x_Result_FAILURE;

    sw_status = Se05x_API_CheckObjectExists(pSe05xSession, kSE05x_AppletResID_TRANSPORT, &exists);
    if (sw_status == SM_OK && exists == kSE05x_Result_SUCCESS) {
        LOG_W("kSE05x_AppletResID_TRANSPORT Object already exists");
    }

    if (sw_status == SM_OK && exists == kSE05x_Result_FAILURE) {

        sw_status = Se05x_API_WriteSymmKey(pSe05xSession,
            NULL,
            SE05x_MaxAttemps_UNLIMITED,
            kSE05x_AppletResID_TRANSPORT,
            SE05x_KeyID_KEK_NONE,
            Transport_AES_value,
            Transport_AES_valueLen,
            (SE05x_INS_t) kSE05x_AttestationType_AUTH,
            kSE05x_SymmKeyType_AES);

        if (SM_OK != sw_status) {
            LOG_E("Failed Se05x_API_WriteSymmKey");
            goto cleanup;
        }
    }
cleanup:
    return sw_status;
}
