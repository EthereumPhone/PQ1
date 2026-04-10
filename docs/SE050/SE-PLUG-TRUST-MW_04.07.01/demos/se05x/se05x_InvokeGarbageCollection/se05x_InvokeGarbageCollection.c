/* Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ex_sss_boot.h>
#include <nxLog_App.h>
#include "cm_commands.h"

static ex_sss_boot_ctx_t gex_sss_boot_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0
#define EX_SSS_BOOT_SKIP_SELECT_APPLET 1

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status           = kStatus_SSS_Fail;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    U32 ret                       = 0;

    ret = CM_InvokeGarbageCollection(pSession->s_ctx.conn_ctx);
    if (ret != SM_OK) {
        goto exit;
    }

    status = kStatus_SSS_Success;
exit:
    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_InvokeGarbageCollection Success !!!...");
    }
    else {
        LOG_E("se05x_InvokeGarbageCollection Failed !!!...");
    }
    return status;
}
