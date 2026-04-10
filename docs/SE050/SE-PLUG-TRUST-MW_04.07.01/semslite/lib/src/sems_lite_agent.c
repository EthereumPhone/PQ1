/*
 *
 * Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sems_lite_agent.h"

#include <ex_sss_boot.h>
#include <nxLog_App.h>
#include <sm_types.h>

#include "sems_lite_api.h"
#include "nxEnsure.h"
#include "nxp_iot_agent_context.h"
#include "nxp_iot_agent_keystore.h"
#include "pb.h"
#include "pb_decode.h"
#include "pb_encode.h"
#include "se05x_reset_apis.h"
#include "string.h" /* memset */
//#include "sems_lite_agent.pb.h"
#include <smCom.h>

#include "global_platf.h"
#include "sems_lite_agent_context.h"

#if (SSS_HAVE_SSS)
/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */
sems_lite_status_t sems_lite_agent_register_keystore(iot_agent_context_t *ctx, iot_agent_keystore_t *keystore)
{
    sems_lite_status_t retval = kStatus_SEMS_Lite_ERR_General;

    ENSURE_OR_GO_EXIT(ctx->numKeystores < NXP_IOT_AGENT_MAX_NUM_KEYSTORES);

    ctx->keystores[ctx->numKeystores++] = keystore;
    retval                              = kStatus_SEMS_Lite_Success;
exit:
    return retval;
}

sems_lite_status_t sems_lite_agent_init_dispatcher(iot_agent_dispatcher_context_t *dispatcher_context,
    iot_agent_context_t *agent_context,
    iot_agent_stream_type_t stream_type)
{
    sems_lite_status_t retval = kStatus_SEMS_Lite_ERR_General;
    size_t num_endpoints      = 0;

    ENSURE_OR_GO_EXIT((dispatcher_context != NULL) && (agent_context != NULL));

    dispatcher_context->agent_context   = agent_context;
    dispatcher_context->current_request = NULL;
    dispatcher_context->closed          = false;

    for (size_t i = 0; i < NXP_IOT_AGENT_MAX_NUM_ENDPOINTS; i++)
        dispatcher_context->endpoints[i].type = nxp_iot_EndpointType_INVALID;

    for (size_t i = 0; (i < agent_context->numKeystores) && (num_endpoints < NXP_IOT_AGENT_MAX_NUM_ENDPOINTS); i++) {
        dispatcher_context->endpoints[num_endpoints].type = (nxp_iot_EndpointType)(agent_context->keystores[i]->type);
        dispatcher_context->endpoints[num_endpoints].id   = agent_context->keystores[i]->identifier;
        dispatcher_context->endpoints[num_endpoints].endpoint_interface =
            agent_context->keystores[i]->iface.endpoint_interface;
        dispatcher_context->endpoints[num_endpoints].endpoint_context = agent_context->keystores[i]->context;
        num_endpoints++;
    }

    dispatcher_context->closed      = false;
    dispatcher_context->stream_type = stream_type;
    retval                          = kStatus_SEMS_Lite_Success;
exit:
    return retval;
}

sems_lite_status_t sems_lite_agent_handle_status_word(void *context)
{
    sems_lite_agent_ctx_t *sems_lite_agent_context = (sems_lite_agent_ctx_t *)context;
    uint32_t status_word;
    sems_lite_status_t return_code;

    if (context == NULL) {
        LOG_E("SEMS Lite Check Status Word: Pointer Error!!!");
        return_code = kStatus_SEMS_Lite_ERR_General;
    }
    else {
        status_word = sems_lite_agent_context->status_word;
        LOG_D("SEMS Lite Check Status Word: %x.", status_word);

        if (status_word == SEMS_LITE_AGENT_STATUS_WORD_INIT) {
            /** status word is initial value. Some error other than R-APDU happens */
            LOG_E("SEMS Lite Check Status Word: Generic Error!!!");
            return_code = kStatus_SEMS_Lite_ERR_General;
        }
        else if ((status_word & SEMS_LITE_AGENT_STATUS_WORD_HOST_CMD_MASK) ==
                 SEMS_LITE_AGENT_STATUS_WORD_HOST_CMD_MASK) {
            /** The only possible status word for host control command is OK by now */
            LOG_I("SEMS Lite Check Status Word: Host Command Success.");
            return_code = kStatus_SEMS_Lite_Success;
        }
        else if (status_word == 0x9000) {
            LOG_I("SEMS Lite Check Status Word: Success.");
            return_code = kStatus_SEMS_Lite_Success;
        }
        else if (status_word == SEMS_LITE_AGENT_STATUS_WORD_USER_DEFINE_SUCCESS) {
            LOG_I("SEMS Lite Check Status Word: Success.");
            return_code = kStatus_SEMS_Lite_Success;
        }
        else if (((status_word & 0xFF00) == 0x6100) || status_word == 0x6310) {
            LOG_I("SEMS Lite Check Status Word: Success.");
            return_code = kStatus_SEMS_Lite_Success;
        }
        else if (status_word == 0x6A82 || status_word == 0x6A88 || status_word == 0x6999 || status_word == 0x6A80 ||
                 status_word == 0x6982) {
            LOG_E("SEMS Lite Check Status Word: Not Applicable.");
            return_code = kStatus_SEMS_Lite_ERR_NotApplicable;
        }
        else if (status_word == 0x6201) {
            if (sems_lite_agent_context->recovery_executed) {
                // Report Successful. Recovery to old version. Exit current script.
                LOG_I("SEMS Lite Check Status Word: Recovery Success.");
                return_code = kStatus_SEMS_Lite_Success;
            }
            else {
                LOG_E("SEMS Lite Check Status Word: Not Applicable.");
                return_code = kStatus_SEMS_Lite_ERR_NotApplicable;
            }
        }
        else if ((status_word & 0xFF00) == 0x6400) {
            LOG_E("SEMS Lite Check Status Word: Fatal Error.");
            return_code = kStatus_SEMS_Lite_ERR_Fatal;
        }
        else if (status_word == SEMS_LITE_AGENT_STATUS_WORD_COM_FAILURE) {
            LOG_E("SEMS Lite Check Status Word: COM Error.");
            return_code = kStatus_SEMS_Lite_ERR_COM;
        }
        else {
            // Whether applet upgrade session is in progress. GET DATA [p1p2=00C2]
            sems_lite_upgradeProgress_status_t upgradeStatus;
            sss_status_t sss_stat = kStatus_SSS_Fail;

            sss_stat = sems_lite_check_AppletUpgradeProgress(sems_lite_agent_context, &upgradeStatus);
            if (sss_stat != kStatus_SSS_Success) {
                LOG_E(
                    "SEMS Lite Check Status Word: Fail to get applet upgrade "
                    "progress.");
                return_code = kStatus_SEMS_Lite_ERR_General;
            }
            else if (upgradeStatus == sems_lite_upgrade_not_inProgress) {
                /*not in progress*/
                LOG_E("SEMS Lite Check Status Word: Not Applicable.");
                return_code = kStatus_SEMS_Lite_ERR_NotApplicable;
            }
            else if ((status_word == 0x6200) || (status_word == 0x6202) || (status_word == 0x6203)) {
                LOG_E("SEMS Lite Check Status Word: Do Recovery.");
                return_code = kStatus_SEMS_Lite_ERR_DoRecovery;
            }
            else if (status_word == 0x6A84) {
                sems_lite_recovery_status_t recoveryStatus;
                sss_stat = sems_lite_check_AppletRecoveryStatus(sems_lite_agent_context, &recoveryStatus);
                if (sss_stat != kStatus_SSS_Success) {
                    LOG_E(
                        "SEMS Lite Check Status Word: Fail to get applet recovery "
                        "progress.");
                    return_code = kStatus_SEMS_Lite_ERR_General;
                }
                else if (recoveryStatus == sems_lite_recovery_not_started) {
                    LOG_E("SEMS Lite Check Status Word: Fatal Error.");
                    return_code = kStatus_SEMS_Lite_ERR_Fatal;
                }
                else {
                    LOG_E("SEMS Lite Check Status Word: Do Recovery.");
                    return_code = kStatus_SEMS_Lite_ERR_DoRecovery;
                }
            }
            else {
                LOG_E("SEMS Lite Check Status Word: Not Applicable.");
                return_code = kStatus_SEMS_Lite_ERR_NotApplicable;
            }
        }
    }

    return return_code;
}

sems_lite_status_t sems_lite_agent_dispatcher(
    iot_agent_dispatcher_context_t *dispatcher_context, pb_istream_t *input, pb_ostream_t *output)
{
    iot_agent_status_t iot_agent_ret = IOT_AGENT_FAILURE;

    iot_agent_ret = iot_agent_dispatcher(dispatcher_context, input, output);

    if (iot_agent_ret != IOT_AGENT_SUCCESS) {
        return kStatus_SEMS_Lite_ERR_General;
    }
    else {
        return kStatus_SEMS_Lite_Success;
    }
}

static sss_status_t sems_lite_agent_verify_elf_version(sems_lite_agent_ctx_t *context,
    const uint8_t *pAid,
    size_t aidLen,
    uint8_t *version,
    uint8_t *minPrevVersion,
    sems_lite_version_check_result_t *pass)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    sems_lite_SEAppInfoList_t getAppInfoList[3];
    bool skip_min_check = false;
    size_t i;
    size_t getAppInfoListLen = sizeof(getAppInfoList) / sizeof(getAppInfoList[0]);

    ENSURE_OR_GO_EXIT(
        (pAid != NULL) && (context != NULL) && (version != NULL) && (minPrevVersion != NULL) && (pass != NULL));

    if ((minPrevVersion[0] == SEMS_LITE_AGENT_INVLAID_VERSION_MSB) &&
        (minPrevVersion[1] == SEMS_LITE_AGENT_INVLAID_VERSION_LSB)) {
        // Invalid min previous version number.
        LOG_I("Skip min previous version verification.");
        sss_status     = kStatus_SSS_Success;
        skip_min_check = true;
    }

    // Get pkg info from SE.
    if (aidLen > UINT8_MAX) {
        LOG_E("aidLen can not be greater than 1 byte.");
        return kStatus_SSS_Fail;
    }
    sss_status = sems_lite_get_SEPkgInfo(context, pAid, (uint8_t)aidLen, getAppInfoList, &getAppInfoListLen);

    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    if (getAppInfoListLen > 1) {
        LOG_W("Find %lu App", getAppInfoListLen);
        LOG_MAU8_W("AID", pAid, aidLen);
    }

    // Verify min previous pkg version and version requirement.
    *pass = kStatus_SEMS_Lite_Version_Pass;

    // No App info is not acceptible for min version checking.
    if ((skip_min_check == false) && (getAppInfoListLen == 0)) {
        LOG_E("Not found version info");
        *pass = kStatus_SEMS_Lite_Version_ERR_MIN;
        goto exit;
    }

    sss_status = kStatus_SSS_Fail;
    for (i = 0; i < getAppInfoListLen; i++) {
        // For each elf in SE, compare with the required version
        if (getAppInfoList[i].pLoadFileVersionNumber) {
            LOG_MAU8_D(
                "Version Number", getAppInfoList[i].pLoadFileVersionNumber, getAppInfoList[i].LoadFileVersionNumberLen);

            if (getAppInfoList[i].LoadFileVersionNumberLen != SEMS_LITE_PKG_VERSION_LEN) {
                LOG_E("Length of version number doesn't match");
                *pass = kStatus_SEMS_Lite_Version_ERR_Downgrade;
                break;
            }

            // Verify min previous version
            if (skip_min_check == false) {
                if (getAppInfoList[i].pLoadFileVersionNumber[0] < minPrevVersion[0]) {
                    // MSB is smaller than required.
                    LOG_E("Min previous version check failed: %u.%u", minPrevVersion[0], minPrevVersion[1]);
                    *pass = kStatus_SEMS_Lite_Version_ERR_MIN;
                    goto exit;
                }
                else if ((getAppInfoList[i].pLoadFileVersionNumber[0] == minPrevVersion[0]) &&
                         (getAppInfoList[i].pLoadFileVersionNumber[1] < minPrevVersion[1])) {
                    // LSB is smaller than required.
                    LOG_E("Min previous version check failed: %u.%u", minPrevVersion[0], minPrevVersion[1]);
                    *pass = kStatus_SEMS_Lite_Version_ERR_MIN;
                    break;
                }
            }

            // Verify version
            if (version[0] < getAppInfoList[i].pLoadFileVersionNumber[0]) {
                // Package version is lower than current one.
                LOG_I("Version check failed: %u.%u", version[0], version[1]);
                *pass = kStatus_SEMS_Lite_Version_ERR_Downgrade;
                break;
            }
            else if ((version[0] == getAppInfoList[i].pLoadFileVersionNumber[0]) &&
                     (version[1] < getAppInfoList[i].pLoadFileVersionNumber[1])) {
                // MSB is same and LSB is larger than required.
                LOG_I("Version check failed: %u.%u", version[0], version[1]);
                *pass = kStatus_SEMS_Lite_Version_ERR_Downgrade;
                break;
            }
        }
        else {
            LOG_E("Not get version info from SE");
            // No version info is not acceptible for min version checking.
            // No version info is acceptible for version checking.
            if (skip_min_check == false) {
                *pass = kStatus_SEMS_Lite_Version_ERR_MIN;
                break;
            }
        }
    }

    sss_status = kStatus_SSS_Success;
exit:
    return sss_status;
}

sss_status_t sems_lite_agent_verify_all_elf_version(
    sems_lite_agent_ctx_t *context, multicast_package_t *pkgBuf, sems_lite_version_check_result_t *all_elf_pass)
{
    int count                                       = 0;
    sss_status_t sss_status                         = kStatus_SSS_Fail;
    struct _sub_component_metaData_t *pSubComponent = NULL;
    sems_lite_version_check_result_t elf_pass       = kStatus_SEMS_Lite_Version_ERR_MIN;
    multicast_package_t *pMultiPkgBuf;

    ENSURE_OR_GO_EXIT((pkgBuf != NULL) && (context != NULL) && (all_elf_pass != NULL));

    pMultiPkgBuf = (multicast_package_t *)pkgBuf;

    // By default, it will pass.
    // If there are no subcomponent or no aid, it will pass.
    *all_elf_pass = kStatus_SEMS_Lite_Version_Pass;
    pSubComponent = (struct _sub_component_metaData_t *)(pMultiPkgBuf->pSubComponentMetaData);

    while (pSubComponent != NULL) {
        count++;
        // Support 6 subcomponets at most.
        ENSURE_OR_GO_EXIT(count <= SEMS_LITE_MAX_SUBCOMPONENT_NUMBER);

        elf_pass = kStatus_SEMS_Lite_Version_ERR_MIN;

        // For all subcomponent in the package, verify the min version requirement.
        if (pSubComponent->pAid != NULL) {
            sss_status = sems_lite_agent_verify_elf_version(context,
                pSubComponent->pAid,
                pSubComponent->aidLen,
                pSubComponent->version,
                pSubComponent->minimumPreviousVersion,
                &elf_pass);

            ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

            if (elf_pass == kStatus_SEMS_Lite_Version_ERR_MIN) {
                LOG_E("One ELF doesn't meet min version requirement");
                *all_elf_pass = kStatus_SEMS_Lite_Version_ERR_MIN;
                break;
            }
            else if (elf_pass == kStatus_SEMS_Lite_Version_ERR_Downgrade) {
                LOG_E("One ELF doesn't meet version requirement");
                *all_elf_pass = kStatus_SEMS_Lite_Version_ERR_Downgrade;
                break;
            }
        }

        pSubComponent = pSubComponent->pNextSubComponentMetaData;
    }

    sss_status = kStatus_SSS_Success;
exit:
    return sss_status;
}

#endif /* SSS_HAVE_SSS > 1 */
