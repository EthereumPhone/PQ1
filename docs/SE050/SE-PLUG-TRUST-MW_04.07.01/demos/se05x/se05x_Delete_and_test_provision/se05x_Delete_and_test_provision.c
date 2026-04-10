/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
/* Only for quick testing.... Not for production use ................. */
/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */

/* TO BE Run only under default session */

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>
#include <sm_types.h>
#include <string.h>

#include "ex_sss_auth.h"
#include "smCom.h"
#include "fsl_sss_se05x_policy.h"

extern void ReInitializeTestSample(ex_sss_boot_ctx_t *pCtx);
extern void AddAttestationKeys(ex_sss_boot_ctx_t *pCtx);

/* clang-format off */
#define TEST_UID 0x04, 0x00, 0x50, 0x01, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFA
/* clang-format ON */

static ex_sss_boot_ctx_t gex_sss_delete_all_boot_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_delete_all_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_se05x_session_t *pSession =
        (sss_se05x_session_t *)&pCtx->session;
    SE05x_Result_t production_uid_present = kSE05x_Result_NA;
    smStatus_t sw_status;

    LOG_E("# se05x_Delete_and_test_provision !!! Only for testing. NOT FOR PRODUCTION USE!!!!");

    sw_status = Se05x_API_CheckObjectExists(
        &pSession->s_ctx, kSE05x_AppletResID_UNIQUE_ID, &production_uid_present);
    if (SM_OK == sw_status && production_uid_present == kSE05x_Result_SUCCESS) {
        uint8_t uid[SE050_MODULE_UNIQUE_ID_LEN] = { 0 };
        uint8_t const_uid[SE050_MODULE_UNIQUE_ID_LEN] = { TEST_UID };
        size_t uidLen = sizeof(uid);
        sw_status = Se05x_API_ReadObject(&pSession->s_ctx,
                                      kSE05x_AppletResID_UNIQUE_ID,
                                      0,
                                      (uint16_t)uidLen,
                                      uid,
                                      &uidLen);
        if (SM_OK == sw_status && 0 == memcmp(const_uid, uid, sizeof(const_uid))) {
            production_uid_present = kSE05x_Result_FAILURE;
        }
    }
    else
    {
        const uint8_t const_uid[SE050_MODULE_UNIQUE_ID_LEN] = { TEST_UID };
        size_t uidLen = sizeof(const_uid);
        LOG_W("kSE05x_AppletResID_UNIQUE_ID Missing. Injecting Dummy KEY!.");
        sw_status = Se05x_API_WriteBinary(&pSession->s_ctx,
            NULL,
            kSE05x_AppletResID_UNIQUE_ID,
            0,
            (uint16_t)uidLen,
            const_uid,
            uidLen);
        LOG_X16_I(sw_status);
        production_uid_present = kSE05x_Result_FAILURE;
    }

    sw_status = Se05x_API_DeleteAll_Iterative(&pSession->s_ctx);
    if (SM_OK != sw_status) {
        LOG_E("Failed Se05x_API_DeleteAll");
        goto cleanup;
    }

    AddAttestationKeys(pCtx);
    ReInitializeTestSample(pCtx);

    if (sw_status == SW_OK) {
        status = kStatus_SSS_Success;
    }

cleanup:
    return status;
}
