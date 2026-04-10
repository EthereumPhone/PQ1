/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <nxScp03_Types.h>
#include "nxLog_hostLib.h"
#include "nxEnsure.h"
#include "veneer_table.h"
#include "ns_channel.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define PRINTF_NSE DbgConsole_Printf_NSE
/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/

void SystemInit(void)
{
}

/*!
 * @brief Main function
 */
int main(void)
{
    PRINTF_NSE("Non-secure entry\r\n");
    sss_status_t status = kStatus_SSS_Success;
    sss_session_t session;
    sss_session_t *pSession = &session;

    SE_Connect_Ctx_t se05x_TunnelCtx;
    SE_Connect_Ctx_t *pNSTunnel_Ctxt = &se05x_TunnelCtx;

    sss_tunnel_t tunnelCtx;

    uint8_t rndData[256];
    size_t rndDataLen = 0x20;
    sss_rng_context_t rng;

    status = nsChannel_context_init(&tunnelCtx);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);
    PRINTF_NSE("NS Channel initialize successful\r\n");

    /* Open plain applet session
     * This session would be on top of PlatformSCP session opened by 
     * secure application.
     * Non-secure application can open UserID, AppletSCP, ECKey or 
     * plain session on top of PlatformSCP session
     */

    pNSTunnel_Ctxt->connType      = kType_SE_Conn_Type_Channel;
    pNSTunnel_Ctxt->auth.authType = kSSS_AuthType_None;
    pNSTunnel_Ctxt->tunnelCtx     = &tunnelCtx;

    status = sss_session_open(pSession, kType_SSS_SE_SE05x, 0, kSSS_ConnectionType_Plain, pNSTunnel_Ctxt);

    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);
    PRINTF_NSE("NS Session open is Successful\r\n");

    status = sss_rng_context_init(&rng, pSession /* Session */);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_rng_get_random(&rng, rndData, rndDataLen);
    if (status == kStatus_SSS_Success) {
        PRINTF_NSE("sss_rng_get_random successful \r\n");
    }
    else {
        PRINTF_NSE("sss_rng_get_random failed \r\n");
    }

cleanup:
    while (1) {
    }
}
