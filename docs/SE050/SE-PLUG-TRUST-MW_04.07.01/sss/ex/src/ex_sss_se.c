/*
 *
 * Copyright 2018,2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <ex_sss_boot.h>
#include <nxLog_App.h>
#include <sm_const.h>
#include <stdio.h>

#if SSS_HAVE_APPLET_SE05X_IOT
#include <fsl_sss_se05x_types.h>
#include <se05x_APDU.h>
#endif

#include "ex_sss_boot_int.h"
#if AX_EMBEDDED
#include <app_boot.h>
#endif

#include "ex_sss_auth.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

#define SSS_EX_SE05x_AUTH_MECH kSSS_AuthType_SCP03
#define SSS_EX_CONNECTION_TYPE kSSS_ConnectionType_Encrypted

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */
#if SSS_HAVE_APPLET
sss_status_t ex_sss_boot_se_open(ex_sss_boot_ctx_t *pCtx, const char *portName)
{
    sss_status_t status           = kStatus_SSS_Fail;
    SE_Connect_Ctx_t *pConnectCtx = NULL;

#if SSS_HAVE_APPLET_SE05X_IOT || SSS_HAVE_APPLET_LOOPBACK
    pConnectCtx = &pCtx->se05x_open_ctx;
#endif

#if defined(SMCOM_JRCP_V1)
    if (ex_sss_boot_isSocketPortName(portName)) {
        pConnectCtx->connType = kType_SE_Conn_Type_JRCP_V1;
        pConnectCtx->portName = portName;
    }
#endif

#if defined(SMCOM_JRCP_V2)
    if (ex_sss_boot_isSocketPortName(portName)) {
        pConnectCtx->connType = kType_SE_Conn_Type_JRCP_V2;
        pConnectCtx->portName = portName;
    }
#endif

#if defined(RJCT_VCOM)
    if (ex_sss_boot_isSerialPortName(portName)) {
        pConnectCtx->connType = kType_SE_Conn_Type_VCOM;
        pConnectCtx->portName = portName;
    }
#endif

#if defined(SCI2C)
#error "Not a valid  combination"
#endif

#if defined(T1oI2C)
    pConnectCtx->connType = kType_SE_Conn_Type_T1oI2C;
    pConnectCtx->portName = NULL;
#endif

#if defined(SMCOM_PCSC)
    pConnectCtx->connType = kType_SE_Conn_Type_PCSC;
    pConnectCtx->portName = NULL;
#endif

#if defined(SMCOM_PN7150)
    pConnectCtx->connType = kType_SE_Conn_Type_NFC;
    pConnectCtx->portName = NULL;
#endif

#if SSS_HAVE_HOSTCRYPTO_ANY && SSS_HAVE_APPLET_SE05X_IOT

    status = ex_sss_se_prepare_host(
        &pCtx->host_session, &pCtx->host_ks, pConnectCtx, &pCtx->ex_se05x_auth, SSS_EX_SE05x_AUTH_MECH);

    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_se05x_prepare_host failed");
        goto cleanup;
    }
cleanup:
#elif SSS_HAVE_APPLET_LOOPBACK
    status = kStatus_SSS_Success;
#endif // SSS_HAVE_HOSTCRYPTO_ANY
    return status;
}

#endif
