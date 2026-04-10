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
    int i                         = 1;
    uint8_t buff[2]               = {0};
    size_t buf_len                = sizeof(buff);

    while (1) {
        printf("Count i = %d \n", i);
        sm_status = Se05x_API_GetRandom(&pSession->s_ctx, sizeof(buff), buff, &buf_len);
        if (sm_status != SM_OK) {
            LOG_E("Se05x_API_GetRandom Failed");
            printf("Error is %02x \n", sm_status);
            break;
        }
        i++;
    }

    buf_len   = sizeof(buff);
    sm_status = Se05x_API_GetRandom(&pSession->s_ctx, sizeof(buff), buff, &buf_len);
    ENSURE_OR_GO_EXIT(sm_status == SM_ERR_APDU_THROUGHPUT);

    printf("Reset the IC \n");
    t1oi2c_status = phNxpEse_reset(pSession->s_ctx.conn_ctx);
    if (t1oi2c_status != ESESTATUS_SUCCESS) {
        printf("phNxpEse_reset failed");
    }

    status = ex_sss_boot_open(pCtx, NULL);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    buf_len   = sizeof(buff);
    sm_status = Se05x_API_GetRandom(&pSession->s_ctx, sizeof(buff), buff, &buf_len);
    ENSURE_OR_GO_EXIT(sm_status == SM_OK);

    LOG_I("SE052 reset test Success !!!...");
    return kStatus_SSS_Success;
exit:
    return kStatus_SSS_Fail;
}
