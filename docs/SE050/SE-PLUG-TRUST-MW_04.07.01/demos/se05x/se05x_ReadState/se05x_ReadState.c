/* Copyright 2019 NXP
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef __cplusplus
extern "C" {
#endif

#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <se05x_tlv.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>

#ifdef __cplusplus
}
#endif

static ex_sss_boot_ctx_t gex_sss_readstate_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_readstate_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;

    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    /* doc:start:read state variables */
    SE05x_LockState_t lockState;
    SE05x_RestrictMode_t restrictMode;
    SE05x_PlatformSCPRequest_t platformSCPRequest;
    /* doc:end:read state variables*/
    uint8_t state[4] = {0};
    size_t stateLen  = sizeof(state);
    smStatus_t sm_status;
    sm_status = Se05x_API_ReadState(&pSession->s_ctx, state, &stateLen);
    if (sm_status != SM_OK) {
        LOG_E("Se05x_API_ReadState Failed");
        goto exit;
    }
    if (stateLen == 3) {
        LOG_I("SE05x Read State Successfully!!!");
        LOG_I("Following is the SE05x Read State status");
        lockState = (SE05x_LockState_t)state[0];
        if (lockState == kSE05x_LockState_LOCKED) {
            LOG_I("%s = 0x%0X %s", "SE05x Lock State", lockState, " i.e. SE05x is Locked!!!");
        }
        else {
            LOG_I("%s = 0x%0X %s", "SE05x Lock State", lockState, " i.e. SE05x is Unlocked!!!");
        }
        restrictMode = (SE05x_RestrictMode_t)state[1];

        if (restrictMode == kSE05x_RestrictMode_NA) {
            LOG_I("%s = 0x%0X %s",
                "SE05x Restrict Mode",
                restrictMode,
                " i.e. No Restriction is applied for object creation!!!");
        }
        else if (restrictMode == kSE05x_RestrictMode_RESTRICT_NEW) {
            LOG_I("%s = 0x%0X %s",
                "SE05x Restrict Mode",
                restrictMode,
                " i.e. Restriction is applied for new object creation!!!");
        }
        else if (restrictMode == kSE05x_RestrictMode_RESTRICT_ALL) {
            LOG_I("%s = 0x%0X %s",
                "SE05x Restrict Mode",
                restrictMode,
                " i.e. Restriction is applied for all objects !!!");
        }
        else {
            goto exit;
        }
        platformSCPRequest = (SE05x_PlatformSCPRequest_t)state[2];
        if (platformSCPRequest == kSE05x_PlatformSCPRequest_REQUIRED) {
            LOG_I("%s = 0x%0X %s",
                "SE05x Platform SCP Request",
                platformSCPRequest,
                " i.e. Platform SCP is Requested for Communication!!!");
        }
        else if (platformSCPRequest == kSE05x_PlatformSCPRequest_NOT_REQUIRED) {
            LOG_I("%s = 0x%0X %s",
                "SE05x Platform SCP Request",
                platformSCPRequest,
                " i.e. Platform SCP is not required for Communication!!!");
        }
        else {
            goto exit;
        }
        status = kStatus_SSS_Success;
    }
exit:
    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_ReadState Example Success !!!...");
    }
    else {
        LOG_E("se05x_ReadState Example Failed !!!...");
    }
    return status;
}
