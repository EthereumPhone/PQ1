/* Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>
#include "phNxpEse_Api.h"
#include "nxEnsure.h"
#include "sm_timer.h"

static ex_sss_boot_ctx_t gex_sss_boot_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status           = kStatus_SSS_Fail;
    ESESTATUS t1oi2c_status       = ESESTATUS_FAILED;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    smStatus_t sm_status          = SM_NOT_OK;
    uint8_t buff[8]               = {0};
    size_t buf_len                = sizeof(buff);

    LOG_I("Send Get Random Data APDU \n");
    sm_status = Se05x_API_GetRandom(&pSession->s_ctx, sizeof(buff), buff, &buf_len);
    ENSURE_OR_GO_EXIT(sm_status == SM_OK);
    LOG_MAU8_I("Random data ==>", buff, buf_len);

    LOG_I("Send deep power down command the IC \n");
    t1oi2c_status = phNxpEse_deepPwrDown(pSession->s_ctx.conn_ctx);
    ENSURE_OR_GO_EXIT(t1oi2c_status == ESESTATUS_SUCCESS);

    LOG_I("Sleep for 10 seconds\n");
    sm_sleep(10000);

    // Reopen the session. (This will also make the secure element wakeup from deep power down mode)
    status = ex_sss_boot_open(pCtx, NULL);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    LOG_I("Send Get Random Data APDU \n");
    buf_len   = sizeof(buff);
    sm_status = Se05x_API_GetRandom(&pSession->s_ctx, sizeof(buff), buff, &buf_len);
    ENSURE_OR_GO_EXIT(sm_status == SM_OK);

    LOG_MAU8_I("Random data ==>", buff, buf_len);

    LOG_I("SE052 deep power down example Success !!!...");
    return kStatus_SSS_Success;
exit:
    return kStatus_SSS_Fail;
}
