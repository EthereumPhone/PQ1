/*
*
* Copyright 2019-2020 NXP
* SPDX-License-Identifier: Apache-2.0
*/
#include <nxLog_App.h>

#include "global_platf.h"
#include "sems_lite_api.h"
#include "nxEnsure.h"
#include "smCom.h"
#include "string.h"

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */
#define SEMS_LITE_GETDATA_UUID_TAG 0xFE
#define SEMS_LITE_GETDATA_UUID_TAGLEN 0x18

#define SEMS_LITE_GETDATA_PUBLICKEY_TAG 0xC4

#define SEMS_LITE_GETDATA_APP_INFO 0xC2

#define SEMS_LITE_GETDATA_PACKAGE_INFO 0xC3

#define SEMS_LITE_GETDATA_CA_IDENTIFIER_TAG 0x42

#define SEMS_LITE_GETDATA_CHECKTEAR_TAG 0x46
#define SEMS_LITE_GETDATA_CHECKTEAR_TAGLEN 0x01

#define SEMS_LITE_GETDATA_SIGNATURE_LAST_SCRIPT_TAG 0x47

#define SEMS_LITE_GETDATA_APPLET_VERSION_TAG 0xDE

#define SEMS_LITE_GETDATA_UPGRADE_PROGRESS_TAG 0xC1
#define SEMS_LITE_GETDATA_ENC_ID_TAG 0x43

#define SEMS_LITE_GETDATA_UPGRADE_PROGRESS_TAG 0xC1
#define ELF_UPGRADE_INFO_TAG 0xA1
#define ELF_UPGRADE_SESSION_STATUS_TAG 0x90

#define SEMS_LITE_GETDATA_EC_DOMAIN_PARAM_TYPE_TAG 0xC5
#define SEMS_LITE_GETDATA_EC_DOMAIN_PARAM_TYPE_TAGLEN 0x01

#define SEMS_LITE_GETDATA_FIPS_INFO_TAG 0xC6
#define SEMS_LITE_GETDATA_FIPS_INFO_TAGLEN 0x01

#define IDX_TABLE_ENTRY_SIZE 0x10
#define IDX_TABLE_INCREMENT_SIZE 0x20

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */
#if SSS_HAVE_APPLET_SE05X_IOT
static sss_status_t sems_lite_get_Data(
    sems_lite_agent_ctx_t *pContext, uint8_t tag, uint8_t *pRspBuf, size_t *pRspBufLen);

static sss_status_t sems_lite_verify_GetDataResponse(uint8_t tag, uint8_t *pRspBuf, size_t *pRspBufLen);

static sss_status_t sems_lite_parse_AppletUpgradeProgressResp(uint8_t *pRspBuf,
    size_t *pRspBufLen,
    sems_lite_upgradeProgress_status_t *pUpgradeStatus,
    sems_lite_recovery_status_t *pRecoveryStatus);

static sss_status_t sems_lite_get_Data_BUF(sems_lite_agent_ctx_t *pContext,
    uint8_t tag_P1,
    uint8_t tag_P2,
    const uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *pRspBuf,
    size_t *pRspBufLen);

static sss_status_t sems_lite_get_Data_BUF_Recursive(sems_lite_agent_ctx_t *pContext,
    uint8_t tag_P2,
    const uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *pRspBuf,
    size_t *pRspBufLen);

static sss_status_t sems_lite_parse_card_contents(sems_lite_SEAppInfoList_t *pAppInfo);

static sss_status_t sems_lite_get_SEInfo_Int(sems_lite_agent_ctx_t *pContext,
    uint8_t tag_p2,
    const uint8_t *searchAID,
    uint8_t searchAidLen,
    sems_lite_SEAppInfoList_t *pAppInfo,
    size_t *pAppInfoLen);
#endif

#if SSS_HAVE_APPLET_SE05X_IOT
sss_status_t sems_lite_get_UUID(sems_lite_agent_ctx_t *pContext, uint8_t *pRspBuf, size_t *pRspBufLen)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(pContext != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBuf != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBufLen != NULL);

    // SEMS Lite session should be opened first.
    ENSURE_OR_GO_CLEANUP(pContext->session_opened == true);

    // P2 '0xFE' SEMS Lite UUID
    sss_stat = sems_lite_get_Data(pContext, SEMS_LITE_GETDATA_UUID_TAG, pRspBuf, pRspBufLen);
    if (sss_stat == kStatus_SSS_Success) {
        sss_stat = sems_lite_verify_GetDataResponse(SEMS_LITE_GETDATA_UUID_TAG, pRspBuf, pRspBufLen);
    }
cleanup:
    return sss_stat;
}

sss_status_t sems_lite_get_Publickey(sems_lite_agent_ctx_t *pContext, uint8_t *pRspBuf, size_t *pRspBufLen)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(pContext != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBuf != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBufLen != NULL);

    // SEMS Lite session should be opened first.
    ENSURE_OR_GO_CLEANUP(pContext->session_opened == true);

    // P2 '0xC4' SEMS Lite PUBLICKEY
    sss_stat = sems_lite_get_Data(pContext, SEMS_LITE_GETDATA_PUBLICKEY_TAG, pRspBuf, pRspBufLen);
    if (sss_stat == kStatus_SSS_Success) {
        sss_stat = sems_lite_verify_GetDataResponse(SEMS_LITE_GETDATA_PUBLICKEY_TAG, pRspBuf, pRspBufLen);
    }
cleanup:
    return sss_stat;
}

static sss_status_t sems_lite_get_SEInfoRAW_Int(sems_lite_agent_ctx_t *pContext,
    uint8_t tag,
    const uint8_t *searchAID,
    uint8_t searchAidLen,
    uint8_t *pRspBuf,
    size_t *pRspBufLen)
{
    sss_status_t sss_stat                          = kStatus_SSS_Fail;
    uint8_t cmdBuf[SEMS_LITE_GET_DATA_CMD_BUF_LEN] = {0x4F, 00};
    uint8_t cmdBufLen                              = 2;

    ENSURE_OR_GO_CLEANUP(pContext != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBuf != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBufLen != NULL);
    ENSURE_OR_GO_CLEANUP(*pRspBufLen > 0);

    // SEMS Lite session should be opened first.
    ENSURE_OR_GO_CLEANUP(pContext->session_opened == true);

    if (searchAidLen > 0) {
        //         4F  Len  searchAid
        ENSURE_OR_GO_CLEANUP((UINT8_MAX - 2) >= searchAidLen);
        cmdBufLen = 1 + 1 + searchAidLen;
        cmdBuf[1] = searchAidLen;
        memcpy(&cmdBuf[2], searchAID, searchAidLen);

        sss_stat = sems_lite_get_Data_BUF(pContext, 0x00, tag, cmdBuf, cmdBufLen, pRspBuf, pRspBufLen);
    }
    else {
        sss_stat = sems_lite_get_Data_BUF_Recursive(pContext, tag, cmdBuf, cmdBufLen, pRspBuf, pRspBufLen);
    }

    if (sss_stat == kStatus_SSS_Success) {
        /* Good */
    }
cleanup:
    return sss_stat;
}

sss_status_t sems_lite_get_SEAppInfoRAW(sems_lite_agent_ctx_t *pContext,
    const uint8_t *searchAID,
    uint8_t searchAidLen,
    uint8_t *pRspBuf,
    size_t *pRspBufLen)
{
    return sems_lite_get_SEInfoRAW_Int(
        pContext, SEMS_LITE_GETDATA_APP_INFO, searchAID, searchAidLen, pRspBuf, pRspBufLen);
}

sss_status_t sems_lite_get_SEPkgInfoRAW(sems_lite_agent_ctx_t *pContext,
    const uint8_t *searchAID,
    uint8_t searchAidLen,
    uint8_t *pRspBuf,
    size_t *pRspBufLen)
{
    return sems_lite_get_SEInfoRAW_Int(
        pContext, SEMS_LITE_GETDATA_PACKAGE_INFO, searchAID, searchAidLen, pRspBuf, pRspBufLen);
}

sss_status_t sems_lite_get_SEAppInfo(sems_lite_agent_ctx_t *pContext,
    const uint8_t *searchAID,
    uint8_t searchAidLen,
    sems_lite_SEAppInfoList_t *pAppInfo,
    size_t *pAppInfoLen)
{
    return sems_lite_get_SEInfo_Int(
        pContext, SEMS_LITE_GETDATA_APP_INFO, searchAID, searchAidLen, pAppInfo, pAppInfoLen);
}

sss_status_t sems_lite_get_SEPkgInfo(sems_lite_agent_ctx_t *pContext,
    const uint8_t *searchAID,
    uint8_t searchAidLen,
    sems_lite_SEAppInfoList_t *pAppInfo,
    size_t *pAppInfoLen)
{
    return sems_lite_get_SEInfo_Int(
        pContext, SEMS_LITE_GETDATA_PACKAGE_INFO, searchAID, searchAidLen, pAppInfo, pAppInfoLen);
}

static sss_status_t sems_lite_get_SEInfo_Int(sems_lite_agent_ctx_t *pContext,
    uint8_t tag_p2,
    const uint8_t *searchAID,
    uint8_t searchAidLen,
    sems_lite_SEAppInfoList_t *pAppInfo,
    size_t *pAppInfoLen)
{
    sss_status_t sss_stat                          = kStatus_SSS_Fail;
    uint8_t cmdBuf[SEMS_LITE_GET_DATA_CMD_BUF_LEN] = {0x4F, 00};
    uint8_t cmdBufLen                              = 2;
    uint8_t tag_P1                                 = 0x00;
    uint8_t i                                      = 0;
    size_t lastResponseLen                         = SEMS_LITE_GET_DATA_CMD_BUF_LEN;
    ENSURE_OR_GO_CLEANUP(pContext != NULL);
    ENSURE_OR_GO_CLEANUP(pAppInfo != NULL);
    ENSURE_OR_GO_CLEANUP(*pAppInfoLen > 0);

    // SEMS Lite session should be opened first.
    ENSURE_OR_GO_CLEANUP(pContext->session_opened == true);

    if (searchAidLen > 0) {
        // searchAidLen can't larger than size of cmdBuf - 2
        // As searchAidLen is uint8_t, it should never larger than 259.
        // But [SIMW-2640] reports compiling error. So we use size_t aid_len, it
        // can help to keep code unchange when SEMS_LITE_GET_DATA_CMD_BUF_LEN
        // is changed to some other value.
        size_t aid_len = (size_t)searchAidLen;
        if (aid_len > sizeof(cmdBuf) - 2) {
            LOG_E("Get SE Info Overflow!!!");
            sss_stat = kStatus_SSS_Fail;
            goto cleanup;
        }
        //         4F  Len  searchAid
        ENSURE_OR_GO_CLEANUP((UINT8_MAX - 2) >= searchAidLen);
        cmdBufLen = 1 + 1 + searchAidLen;
        cmdBuf[1] = searchAidLen;
        memcpy(&cmdBuf[2], searchAID, searchAidLen);
    }

    while (lastResponseLen > 2) {
        if (*pAppInfoLen > i) {
            memset(&pAppInfo[i], 0, sizeof(pAppInfo[i]));
            pAppInfo[i].rspBufLen = SEMS_LITE_GET_DATA_CMD_BUF_LEN;
            sss_stat              = sems_lite_get_Data_BUF(
                pContext, tag_P1, tag_p2, cmdBuf, cmdBufLen, pAppInfo[i].rspBuf, &pAppInfo[i].rspBufLen);

            lastResponseLen = pAppInfo[i].rspBufLen;
            if (sss_stat == kStatus_SSS_Success) {
                if (pAppInfo[i].rspBufLen > 2) {
                    sss_stat = sems_lite_parse_card_contents(&pAppInfo[i]);
                    if (sss_stat != kStatus_SSS_Success) {
                        goto cleanup;
                    }
                    i++;
                }
            }
            else {
                /* Fail */
                goto cleanup;
            }
        }
        else {
            LOG_E("InSufficient Buffer passed!!!");
            sss_stat = kStatus_SSS_Fail;
            goto cleanup;
        }
        /* For the next iteration make p1 to 0x01 */
        tag_P1 = 0x01;
    }
    *pAppInfoLen = i;
cleanup:
    return sss_stat;
}

sss_status_t sems_lite_check_Tear(sems_lite_agent_ctx_t *pContext, sems_lite_tearDown_status_t *pTearStatus)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;
    smStatus_t retStatus  = SM_NOT_OK;
    uint8_t rspBuf[16]    = {0};
    size_t rspBufLen      = sizeof(rspBuf);
    ENSURE_OR_GO_CLEANUP(pContext != NULL);

    // SEMS Lite session should be opened first.
    ENSURE_OR_GO_CLEANUP(pContext->session_opened == true);

    // P2 '0x46' Check Tear during script execution
    sss_stat = sems_lite_get_Data(pContext, SEMS_LITE_GETDATA_CHECKTEAR_TAG, rspBuf, &rspBufLen);
    if ((sss_stat == kStatus_SSS_Success) && (rspBufLen > 2)) {
        sss_stat  = kStatus_SSS_Fail;
        retStatus = (smStatus_t)((rspBuf[rspBufLen - 2] << 8) | (rspBuf[rspBufLen - 1]));
        if ((retStatus == SM_OK) && (rspBuf[0] == SEMS_LITE_GETDATA_CHECKTEAR_TAG) &&
            (rspBuf[1] == SEMS_LITE_GETDATA_CHECKTEAR_TAGLEN)) {
            sss_stat = kStatus_SSS_Success;
            if (rspBuf[2] == 0) {
                *pTearStatus = sems_lite_notear;
            }
            else if (rspBuf[2] == 1) {
                *pTearStatus = sems_lite_tear;
            }
        }
    }
    else {
        sss_stat = kStatus_SSS_Fail;
    }
cleanup:
    return sss_stat;
}

sss_status_t sems_lite_get_SignatureofLastScript(sems_lite_agent_ctx_t *pContext, uint8_t *pRspBuf, size_t *pRspBufLen)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;
    size_t getDataRspLen  = 0;
    smStatus_t retStatus  = SM_NOT_OK;
    ENSURE_OR_GO_CLEANUP(pContext != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBuf != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBufLen != NULL);

    // SEMS Lite session should be opened first.
    ENSURE_OR_GO_CLEANUP(pContext->session_opened == true);

    // P2 '0x47' _Get Signature of executed script
    sss_stat = sems_lite_get_Data(pContext, SEMS_LITE_GETDATA_SIGNATURE_LAST_SCRIPT_TAG, pRspBuf, pRspBufLen);
    if (sss_stat == kStatus_SSS_Success) {
        sss_stat = kStatus_SSS_Fail;
        /* Handle no tear signature is 0 bytes */
        if (*pRspBufLen == 4) {
            getDataRspLen = *pRspBufLen;
            retStatus     = (smStatus_t)((pRspBuf[getDataRspLen - 2] << 8) | (pRspBuf[getDataRspLen - 1]));
            if (retStatus == SM_OK) {
                if ((pRspBuf[0] == SEMS_LITE_GETDATA_SIGNATURE_LAST_SCRIPT_TAG) && (pRspBuf[1] == 0x00)) {
                    memset(pRspBuf, 0, *pRspBufLen);
                    *pRspBufLen = 0x00;
                    sss_stat    = kStatus_SSS_Success;
                }
            }
        }
        else {
            sss_stat =
                sems_lite_verify_GetDataResponse(SEMS_LITE_GETDATA_SIGNATURE_LAST_SCRIPT_TAG, pRspBuf, pRspBufLen);
        }
    }
cleanup:
    return sss_stat;
}

sss_status_t sems_lite_get_AppletVersion(sems_lite_agent_ctx_t *pContext, uint8_t *pRspBuf, size_t *pRspBufLen)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(pContext != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBuf != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBufLen != NULL);

    // SEMS Lite session should be opened first.
    ENSURE_OR_GO_CLEANUP(pContext->session_opened == true);

    // P2 '0xDE' SEMS Lite Applet Version
    sss_stat = sems_lite_get_Data(pContext, SEMS_LITE_GETDATA_APPLET_VERSION_TAG, pRspBuf, pRspBufLen);
    if (sss_stat == kStatus_SSS_Success) {
        sss_stat = sems_lite_verify_GetDataResponse(SEMS_LITE_GETDATA_APPLET_VERSION_TAG, pRspBuf, pRspBufLen);
    }
cleanup:
    return sss_stat;
}

sss_status_t sems_lite_check_AppletUpgradeProgress(
    sems_lite_agent_ctx_t *pContext, sems_lite_upgradeProgress_status_t *pUpgradeStatus)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;
    uint8_t rspBuf[256]   = {0};
    size_t rspBufLen      = sizeof(rspBuf);
    sems_lite_recovery_status_t recoveryStatus;

    ENSURE_OR_GO_CLEANUP(pContext != NULL);

    // SEMS Lite session should be opened first.
    ENSURE_OR_GO_CLEANUP(pContext->session_opened == true);

    // P2 '0xC1' SEMS Lite Applet Upgrade Progress
    sss_stat = sems_lite_get_Data(pContext, SEMS_LITE_GETDATA_UPGRADE_PROGRESS_TAG, rspBuf, &rspBufLen);
    if (sss_stat == kStatus_SSS_Success) {
        sss_stat = sems_lite_parse_AppletUpgradeProgressResp(rspBuf, &rspBufLen, pUpgradeStatus, &recoveryStatus);
    }
cleanup:
    return sss_stat;
}

sss_status_t sems_lite_check_AppletRecoveryStatus(
    sems_lite_agent_ctx_t *pContext, sems_lite_recovery_status_t *pRecoveryStatus)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;
    uint8_t rspBuf[256]   = {0};
    size_t rspBufLen      = sizeof(rspBuf);
    sems_lite_upgradeProgress_status_t upgradeStatus;

    ENSURE_OR_GO_CLEANUP(pContext != NULL);
    // SEMS Lite session should be opened first.
    ENSURE_OR_GO_CLEANUP(pContext->session_opened == true);

    // P2 '0xC1' SEMS Lite Applet Upgrade Progress
    sss_stat = sems_lite_get_Data(pContext, SEMS_LITE_GETDATA_UPGRADE_PROGRESS_TAG, rspBuf, &rspBufLen);
    if (sss_stat == kStatus_SSS_Success) {
        sss_stat = sems_lite_parse_AppletUpgradeProgressResp(rspBuf, &rspBufLen, &upgradeStatus, pRecoveryStatus);
    }
cleanup:
    return sss_stat;
}

sss_status_t sems_lite_get_ENCIdentifier(sems_lite_agent_ctx_t *pContext, uint8_t *pRspBuf, size_t *pRspBufLen)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(pContext != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBuf != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBufLen != NULL);

    // SEMS Lite session should be opened first.
    ENSURE_OR_GO_CLEANUP(pContext->session_opened == true);

    // P2 '0x43' SEMS Lite ENC Identifier
    sss_stat = sems_lite_get_Data(pContext, SEMS_LITE_GETDATA_ENC_ID_TAG, pRspBuf, pRspBufLen);
    if (sss_stat == kStatus_SSS_Success) {
        sss_stat = sems_lite_verify_GetDataResponse(SEMS_LITE_GETDATA_ENC_ID_TAG, pRspBuf, pRspBufLen);
    }
cleanup:
    return sss_stat;
}

static sss_status_t sems_lite_parse_card_contents(sems_lite_SEAppInfoList_t *pAppInfo)
{
    uint16_t i          = 0;
    sss_status_t status = kStatus_SSS_Fail;

    if ((pAppInfo->rspBuf[i]) == 0xE3) {
        /* Tag E3 */
        i = 2;
    }
    else {
        LOG_E("Wrong tag parsed incorrect information");
        goto exit;
    }

    if (pAppInfo->rspBuf[i++] == 0x4F) {
        /* 0x4F Aid tag*/
        pAppInfo->AIDLen = pAppInfo->rspBuf[i++];
        pAppInfo->pAID   = &pAppInfo->rspBuf[i];
        i += pAppInfo->AIDLen;
    }

    ENSURE_OR_GO_EXIT(i <= SEMS_LITE_GET_DATA_CMD_BUF_LEN - 3);
    if (pAppInfo->rspBuf[i] == 0x9F && pAppInfo->rspBuf[++i] == 0x70) {
        /* 9F70 Life Cycle tag */
        i += 1;
        pAppInfo->LifeCycleState = pAppInfo->rspBuf[++i];
        i += 1;
    }

    ENSURE_OR_GO_EXIT(i <= SEMS_LITE_GET_DATA_CMD_BUF_LEN - 3);
    if (pAppInfo->rspBuf[i] == 0xC5) {
        /* 0xC5 Privilages tag*/
        i += 1;
        pAppInfo->PriviledgesLen = pAppInfo->rspBuf[i++];
        pAppInfo->pPriviledges   = &pAppInfo->rspBuf[i];
        i += pAppInfo->PriviledgesLen;
    }

    ENSURE_OR_GO_EXIT(i <= SEMS_LITE_GET_DATA_CMD_BUF_LEN - 3);
    if (pAppInfo->rspBuf[i] == 0xC4) {
        /* 0xC4 Load file aid tag*/
        i += 1;
        pAppInfo->LoadFileAIDLen = pAppInfo->rspBuf[i++];
        pAppInfo->pLoadFileAID   = &pAppInfo->rspBuf[i];
        i += pAppInfo->LoadFileAIDLen;
    }

    ENSURE_OR_GO_EXIT(i <= SEMS_LITE_GET_DATA_CMD_BUF_LEN - 3);
    if (pAppInfo->rspBuf[i] == 0xCE) {
        /* 0xCE Load File Version Number tag*/
        i += 1;
        pAppInfo->LoadFileVersionNumberLen = pAppInfo->rspBuf[i++];
        pAppInfo->pLoadFileVersionNumber   = &pAppInfo->rspBuf[i];
        i += pAppInfo->LoadFileVersionNumberLen;
    }

    ENSURE_OR_GO_EXIT(i <= SEMS_LITE_GET_DATA_CMD_BUF_LEN - 3);
    if (pAppInfo->rspBuf[i] == 0xCC) {
        /* 0xCC Security Domain AID tag*/
        i += 1;
        pAppInfo->SecurityDomainAIDLen = pAppInfo->rspBuf[i++];
        pAppInfo->pSecurityDomainAID   = &pAppInfo->rspBuf[i];
        i += pAppInfo->SecurityDomainAIDLen;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

static sss_status_t sems_lite_get_Data(
    sems_lite_agent_ctx_t *pContext, uint8_t tag_P2, uint8_t *pRspBuf, size_t *pRspBufLen)
{
    const uint8_t tag_P1 = 0x00;
    return sems_lite_get_Data_BUF(pContext, tag_P1, tag_P2, NULL, 0, pRspBuf, pRspBufLen);
}

static sss_status_t sems_lite_get_Data_BUF(sems_lite_agent_ctx_t *pContext,
    uint8_t tag_P1,
    uint8_t tag_P2,
    const uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *pRspBuf,
    size_t *pRspBufLen)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;
    U32 respstat;

    uint8_t getDataCmd[SEMS_LITE_GET_DATA_CMD_BUF_LEN] = {
        0x80, // CLA '80' / '00' GlobalPlatform / ISO / IEC
        0xCA, // INS 'CA' GET DATA(IDENTIFY)
        0x00, // P1 '00' High order tag value
        0x00, // P2  - proprietary data coming from respective function
        0x00, // Lc is Le'00' Case 2 command
    };
    U16 getDataCmdLen = 5;
    U32 getDataRspLen;

    /* Copy the appropriate tag coming from respective function at P1 & P2 */
    getDataCmd[2] = tag_P1;
    getDataCmd[3] = tag_P2;

    ENSURE_OR_GO_CLEANUP(cmdBufLen < (SEMS_LITE_GET_DATA_CMD_BUF_LEN - 5));

    if (cmdBufLen > 0) {
        getDataCmdLen += (U16)cmdBufLen;
        getDataCmdLen++;
        memcpy(&getDataCmd[5], cmdBuf, cmdBufLen);
        getDataCmd[4] /* Lc */ = (uint8_t)cmdBufLen;
    }

    ENSURE_OR_GO_CLEANUP(*pRspBufLen > 0);

    getDataRspLen = (U32)*pRspBufLen;

#ifdef SEMS_LITE_AGENT_CHANNEL_1
    if (pContext->n_logical_channel == SEMS_LITE_AGENT_CHANNEL_0) {
        LOG_E("It is not permitted to use SEMS Lite APIs in Channel 0");
        LOG_E(
            "Before calling this API, SEMS Lite Context should have been "
            "initialized.");
        goto cleanup;
    }
    else {
        getDataCmd[0] = getDataCmd[0] | SEMS_LITE_AGENT_CHANNEL_1;
    }
#endif

    respstat = smCom_TransceiveRaw(
        pContext->pS05x_Ctx->conn_ctx, (uint8_t *)getDataCmd, getDataCmdLen, pRspBuf, &getDataRspLen);
    if (respstat != SM_OK) {
        LOG_E("Could not get requested Data!!!");
        goto cleanup;
    }

    if ((tag_P2 == SEMS_LITE_GETDATA_APP_INFO) || (tag_P2 == SEMS_LITE_GETDATA_PACKAGE_INFO)) {
        // Get App Info and Get Package Info return code 0x6A82/0x6A83 when no more data.
        // If get 0x6A82/0x6A83, they should not be taken as failure if no response data.
        if (getDataRspLen == 2) {
            if ((pRspBuf[getDataRspLen - 2] == 0x6A && pRspBuf[getDataRspLen - 1] == 0x82) ||
                (pRspBuf[getDataRspLen - 2] == 0x6A && pRspBuf[getDataRspLen - 1] == 0x83) ||
                (pRspBuf[getDataRspLen - 2] == 0x90 && pRspBuf[getDataRspLen - 1] == 0x00)) {
                sss_stat = kStatus_SSS_Success;
            }
            else
                sss_stat = kStatus_SSS_Fail;
        }
        else {
            ENSURE_OR_GO_CLEANUP(getDataRspLen > 2);
            if (pRspBuf[getDataRspLen - 2] == 0x90 && pRspBuf[getDataRspLen - 1] == 0x00) {
                /* 0x9000*/
                sss_stat = kStatus_SSS_Success;
            }
            else {
                sss_stat = kStatus_SSS_Fail;
            }
        }
    }
    else {
        ENSURE_OR_GO_CLEANUP(getDataRspLen >= 2);
        if (pRspBuf[getDataRspLen - 2] == 0x90 && pRspBuf[getDataRspLen - 1] == 0x00) {
            /* 0x9000*/
            sss_stat = kStatus_SSS_Success;
        }
        else {
            sss_stat = kStatus_SSS_Fail;
        }
    }

    if (*pRspBufLen > getDataRspLen) {
        *pRspBufLen = (size_t)getDataRspLen;
    }
    else {
        LOG_E("InSufficient Buffer passed!!!");
        sss_stat = kStatus_SSS_Fail;
    }

cleanup:
    return sss_stat;
}

/*
 * NOTE 2: App/Pkg AID can be present full/partial or empty. When all the app/pkg are to be
 * retrieved, provide empty AID. Refer to the command format provided in the above table. Stop when
 * SW 9000/6A82/6A83 is received without response data. Ref: GET STATUS command in section
 * 11.4 of GP Card Spec v1.3 for response information.
 * only for Full package info or full app info (cmdBufLen == 2)
 */

static sss_status_t sems_lite_get_Data_BUF_Recursive(sems_lite_agent_ctx_t *pContext,
    uint8_t tag_P2,
    const uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *pRspBuf,
    size_t *pRspBufLen)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;

    U32 respstat;

    uint8_t getDataCmd[SEMS_LITE_GET_DATA_CMD_BUF_LEN] = {
        0x80, // CLA '80' / '00' GlobalPlatform / ISO / IEC
        0xCA, // INS 'CA' GET DATA(IDENTIFY)
        0x00, // P1 '00' High order tag value
        0x00, // P2  - proprietary data coming from respective function
        0x00, // Lc is Le'00' Case 2 command
    };
    U16 getDataCmdLen = 5;
    U32 getDataRspLen;
    U32 getDataCompleteRspLen = 0;

    /* Copy the appropriate tag coming from respective function at P2 */
    getDataCmd[3] = tag_P2;

    ENSURE_OR_GO_CLEANUP(cmdBufLen < (255 - 5));

    if (cmdBufLen > 0) {
        getDataCmdLen += (U16)cmdBufLen;
        getDataCmdLen++;
        memcpy(&getDataCmd[5], cmdBuf, cmdBufLen);
        getDataCmd[4] /* Lc */ = (uint8_t)cmdBufLen;
    }
    else {
        sss_stat = kStatus_SSS_Fail;
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP(*pRspBufLen > 0);

    getDataRspLen = (U32)*pRspBufLen;

#ifdef SEMS_LITE_AGENT_CHANNEL_1
    if (pContext->n_logical_channel == SEMS_LITE_AGENT_CHANNEL_0) {
        LOG_E("It is not permitted to use SEMS Lite APIs in Channel 0");
        LOG_E(
            "Before calling this API, SEMS Lite Context should have been "
            "initialized.");
        goto cleanup;
    }
    else {
        getDataCmd[0] = getDataCmd[0] | SEMS_LITE_AGENT_CHANNEL_1;
    }
#endif
    while (getDataRspLen > 2) {
        respstat = smCom_TransceiveRaw(pContext->pS05x_Ctx->conn_ctx,
            (uint8_t *)getDataCmd,
            getDataCmdLen,
            pRspBuf + getDataCompleteRspLen,
            &getDataRspLen);
        if (respstat != SM_OK) {
            LOG_E("Could not get requested Data!!!");
            goto cleanup;
        }
        if (getDataRspLen > 2) {
            getDataCompleteRspLen += getDataRspLen;
            if (pRspBuf[getDataCompleteRspLen - 2] == 0x90 && pRspBuf[getDataCompleteRspLen - 1] == 0x00) {
                /* 0x9000*/
                sss_stat = kStatus_SSS_Success;
            }
            else {
                sss_stat = kStatus_SSS_Fail;
                goto cleanup;
            }

            if (*pRspBufLen > getDataCompleteRspLen) {
                getDataRspLen = (U32)*pRspBufLen - getDataRspLen;
            }
            else {
                LOG_E("InSufficient Buffer passed!!!");
                sss_stat = kStatus_SSS_Fail;
                goto cleanup;
            }
        }
        else if (getDataRspLen == 2) {
            getDataCompleteRspLen += getDataRspLen;
            if (pRspBuf[getDataCompleteRspLen - 2] == 0x90 && pRspBuf[getDataCompleteRspLen - 1] == 0x00) {
                /* 0x9000*/
                sss_stat = kStatus_SSS_Success;
            }
            else if (pRspBuf[getDataCompleteRspLen - 2] == 0x6A && pRspBuf[getDataCompleteRspLen - 1] == 0x82) {
                /* 0x6A82*/
                sss_stat = kStatus_SSS_Success;
            }
            else if (pRspBuf[getDataCompleteRspLen - 2] == 0x6A && pRspBuf[getDataCompleteRspLen - 1] == 0x83) {
                /* 0x6A83*/
                sss_stat = kStatus_SSS_Success;
            }
            else {
                sss_stat = kStatus_SSS_Fail;
                goto cleanup;
            }
            *pRspBufLen = (size_t)getDataCompleteRspLen;
        }

        /* For the next iteration make p1 to 0x01 */
        getDataCmd[2] = 0x01;
    }

cleanup:
    return sss_stat;
}

static sss_status_t sems_lite_verify_GetDataResponse(uint8_t tag_P2, uint8_t *pRspBuf, size_t *pRspBufLen)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;
    size_t getDataRspLen  = 0;
    smStatus_t retStatus  = SM_NOT_OK;
    if (*pRspBufLen >= 4) { // Response should include Tag + Len + Data + SW1 + SW2.
        getDataRspLen = *pRspBufLen;
        retStatus     = (smStatus_t)((pRspBuf[getDataRspLen - 2] << 8) | (pRspBuf[getDataRspLen - 1]));
        if (retStatus == SM_OK) {
            if (pRspBuf[0] == tag_P2) {
                // pRspBuf[1] is data length. It should be less than response buffer - tag - lenght - SW1SW2 field.
                if (pRspBuf[1] <= getDataRspLen - 4) {
                    *pRspBufLen = (size_t)(pRspBuf[1]);
                    memmove(pRspBuf, pRspBuf + 2, pRspBuf[1]);
                    sss_stat = kStatus_SSS_Success;
                    LOG_MAU8_D("Response:-", pRspBuf, *pRspBufLen);
                }
                else {
                    memset(pRspBuf, 0, *pRspBufLen);
                    *pRspBufLen = 0;
                }
            }
        }
    }
    return sss_stat;
}

static sss_status_t sems_lite_parse_AppletUpgradeProgressResp(uint8_t *pRspBuf,
    size_t *pRspBufLen,
    sems_lite_upgradeProgress_status_t *pUpgradeStatus,
    sems_lite_recovery_status_t *pRecoveryStatus)
{
    sss_status_t sss_stat              = kStatus_SSS_Fail;
    smStatus_t retStatus               = SM_NOT_OK;
    size_t bufIndex                    = 0;
    size_t length_upgrade_confirmation = 0;
    size_t length_upgrade_session_info = 0;

    /* AMD-H Manage ELF Upgrad Response Table 4-6 */
    /* Format:
        *   Length of Upgrade Confirmation
        *   Upgrade Confirmation
        *   Length of ELF Upgrade Session Info
        *   ELF Upgrade Session Info
        */
    /* Length of Upgrade Confirmation */
    if (pRspBuf[bufIndex] <= 0x7FU) {
        length_upgrade_confirmation = *pRspBuf;
        bufIndex += 1 + length_upgrade_confirmation; // 1 Byte and Length of itself
    }
    else if (pRspBuf[bufIndex] == 0x81) {
        length_upgrade_confirmation = *(pRspBuf + 1);
        bufIndex += (1 + 1) + length_upgrade_confirmation; // 2 Bytes and Length of itself
    }
    else if (pRspBuf[bufIndex] == 0x82) {
        length_upgrade_confirmation = *(pRspBuf + 1);
        length_upgrade_confirmation = (length_upgrade_confirmation << 8) | *(pRspBuf + 2);
        bufIndex += (1 + 2) + length_upgrade_confirmation; // 3 Bytes and Length of itself
    }
    else {
        LOG_E("Length of Upgrade Confirmation Unsupported!!!");
        goto cleanup;
    }

    /* Length of ELF Upgrade Session Info */
    if (pRspBuf[bufIndex] <= 0x7FU) {
        length_upgrade_session_info = *(pRspBuf + bufIndex);
        bufIndex += 1; // 1 Byte and Length of itself
    }
    else if (pRspBuf[bufIndex] == 0x81) {
        length_upgrade_session_info = *(pRspBuf + 1);
        bufIndex += (1 + 1); // 2 Bytes and Length of itself
    }
    else if (pRspBuf[bufIndex] == 0x82) {
        length_upgrade_session_info = *(pRspBuf + 1);
        length_upgrade_session_info = (length_upgrade_session_info << 8) | *(pRspBuf + 2);
        bufIndex += (1 + 2); // 3 Bytes and Length of itself
    }
    else {
        LOG_E("Length of ELF Upgrade Session Info Unsupported!!!");
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP(
        (size_t)(length_upgrade_session_info + bufIndex) < (size_t)(1UL << ((sizeof(size_t) * 4) - 1UL)));
    if (length_upgrade_session_info + bufIndex > *pRspBufLen) {
        LOG_E("Invalid Length of ELF Upgrade Session Info!!!");
        goto cleanup;
    }

    retStatus = (smStatus_t)(
        (pRspBuf[length_upgrade_session_info + bufIndex] << 8) | (pRspBuf[length_upgrade_session_info + bufIndex + 1]));

    /* ELF Upgrade Session Info */
    if (pRspBuf[bufIndex] == ELF_UPGRADE_INFO_TAG) {
        /* Length of Tag  0xA1*/
        bufIndex++;
        /* Length of value */
        bufIndex++;
        if (pRspBuf[bufIndex] == ELF_UPGRADE_SESSION_STATUS_TAG) {
            /* Length of Tag  0x90*/
            bufIndex++;
            /* Length of value */
            bufIndex++;
            if ((pRspBuf[bufIndex] == 0x00) || (pRspBuf[bufIndex] == 0x01)) {
                *pUpgradeStatus  = sems_lite_upgrade_not_inProgress;
                *pRecoveryStatus = sems_lite_recovery_not_started;
            }
            else if (pRspBuf[bufIndex] == 0x04) {
                *pUpgradeStatus  = sems_lite_upgrade_inProgress;
                *pRecoveryStatus = sems_lite_recovery_started;
            }
            else {
                *pUpgradeStatus  = sems_lite_upgrade_inProgress;
                *pRecoveryStatus = sems_lite_recovery_not_started;
            }

            if (retStatus == SM_OK) {
                sss_stat = kStatus_SSS_Success;
            }
        }
    }
cleanup:
    return sss_stat;
}

sss_status_t sems_lite_get_available_mem(sems_lite_agent_ctx_t *pContext, uint8_t *pAvailableMem)
{
    sems_lite_available_mem_t *pMemInfo = (sems_lite_available_mem_t *)pAvailableMem;
    sss_status_t sss_stat               = kStatus_SSS_Fail;
    U32 respstat;
    uint8_t selectSDCmd[]   = {0x00, 0xA4, 0x04, 0x00, 0x00};
    size_t selectSDCmdLen   = sizeof(selectSDCmd);
    uint8_t getMemDataCmd[] = {
        0x80, // CLA '80' / '00' GlobalPlatform / ISO / IEC
        0xCA, // INS 'CA' GET DATA(IDENTIFY)
        0x00, // P1 '00' High order tag value
        0xFE, // P2  - proprietary data coming from respective function
        0x02, // Lc is Le'00' Case 2 command
        0xDF,
        0x25,
        0x00,
    };
    size_t getMemDataCmdLen           = sizeof(getMemDataCmd);
    uint8_t rspBuf[256]               = {0};
    U32 rspBufLen                     = (U32)(sizeof(rspBuf));
    uint32_t freePHeapIntheIndexTable = 0;

    ENSURE_OR_GO_CLEANUP(pMemInfo != NULL);

    // Send select SD command
    respstat = smCom_TransceiveRaw(
        pContext->pS05x_Ctx->conn_ctx, (uint8_t *)selectSDCmd, (U16)selectSDCmdLen, rspBuf, &rspBufLen);
    if (respstat != SM_OK) {
        LOG_E("Could not get requested Data!!!");
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP(rspBufLen >= 2);
    if (rspBuf[rspBufLen - 2] == 0x90 && rspBuf[rspBufLen - 1] == 0x00) {
        /* 0x9000*/
        sss_stat = kStatus_SSS_Success;
    }
    else {
        sss_stat = kStatus_SSS_Fail;
        LOG_E("Select SD Failed!!!");
        goto cleanup;
    }

    // Send get memory info command
    rspBufLen = (U32)(sizeof(rspBuf));
    respstat  = smCom_TransceiveRaw(
        pContext->pS05x_Ctx->conn_ctx, (uint8_t *)getMemDataCmd, (U16)getMemDataCmdLen, rspBuf, &rspBufLen);
    if (respstat != SM_OK) {
        LOG_E("Could not get requested Data!!!");
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP(rspBufLen >= 2);
    if (rspBuf[rspBufLen - 2] == 0x90 && rspBuf[rspBufLen - 1] == 0x00) {
        /* 0x9000*/
        sss_stat = kStatus_SSS_Success;
    }
    else {
        sss_stat = kStatus_SSS_Fail;
        LOG_E("Get Memory Usage Failed!!!");
        goto cleanup;
    }

    pMemInfo->availableCODMemory        = (rspBuf[7] << 24 | rspBuf[8] << 16 | rspBuf[9] << 8 | rspBuf[10]);
    pMemInfo->availableCORMemory        = (rspBuf[13] << 24 | rspBuf[14] << 16 | rspBuf[15] << 8 | rspBuf[16]);
    pMemInfo->availablePersistentMemory = (rspBuf[19] << 24 | rspBuf[20] << 16 | rspBuf[21] << 8 | rspBuf[22]);
    pMemInfo->availableIDX              = (rspBuf[25] << 24 | rspBuf[26] << 16 | rspBuf[27] << 8 | rspBuf[28]);

    if (pMemInfo->availableIDX < 10) {
        /*
        * If the index table has no more free entries currently, we assume that at least one idx object
        * will be created, causing the idx table to extend by it's increment size.
        */
        pMemInfo->availableIDX = IDX_TABLE_INCREMENT_SIZE;
    }

    freePHeapIntheIndexTable = pMemInfo->availableIDX * IDX_TABLE_ENTRY_SIZE;
    /*
    * freePHeapCentralGap is the value that has to be compared against the SEMS Lite script metadata field,
    * which indicates the needed pHeap (including overhead) for the SEMS Lite script execution.
    */
    if (pMemInfo->availablePersistentMemory >= freePHeapIntheIndexTable) {
        pMemInfo->freePHeapCentralGap = pMemInfo->availablePersistentMemory - freePHeapIntheIndexTable;
    }
    else {
        pMemInfo->freePHeapCentralGap = 0;
    }

    pMemInfo->freeTransient = pMemInfo->availableCODMemory;

    LOG_D("availableCODMemory %u", pMemInfo->availableCODMemory);
    LOG_D("availableCORMemory %u", pMemInfo->availableCORMemory);
    LOG_D("availablePersistentMemory %u", pMemInfo->availablePersistentMemory);
    LOG_D("availableIDX %u", pMemInfo->availableIDX);
    LOG_D("Free PHeap Central Gap %u", pMemInfo->freePHeapCentralGap);
    LOG_D("Free freeTransient %u", pMemInfo->freeTransient);

cleanup:
    return sss_stat;
}

sss_status_t sems_lite_get_CA_identifier(sems_lite_agent_ctx_t *pContext, uint8_t *pRspBuf, size_t *pRspBufLen)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(pContext != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBuf != NULL);
    ENSURE_OR_GO_CLEANUP(pRspBufLen != NULL);

    // SEMS Lite session should be opened first.
    ENSURE_OR_GO_CLEANUP(pContext->session_opened == true);

    // P2 '0xC4' SEMS Lite PUBLICKEY
    sss_stat = sems_lite_get_Data(pContext, SEMS_LITE_GETDATA_CA_IDENTIFIER_TAG, pRspBuf, pRspBufLen);
    if (sss_stat == kStatus_SSS_Success) {
        sss_stat = sems_lite_verify_GetDataResponse(SEMS_LITE_GETDATA_CA_IDENTIFIER_TAG, pRspBuf, pRspBufLen);
    }
cleanup:
    return sss_stat;
}

sss_status_t sems_lite_get_FIPS_EC_parameter_type(sems_lite_agent_ctx_t *pContext, uint8_t *pParamType)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;
    smStatus_t retStatus  = SM_NOT_OK;
    uint8_t rspBuf[16]    = {0};
    size_t rspBufLen      = sizeof(rspBuf);

    ENSURE_OR_GO_CLEANUP(pContext != NULL);

    // SEMS Lite session should be opened first.
    ENSURE_OR_GO_CLEANUP(pContext->session_opened == true);

    // P2 '0xC5' Get Configured EC domain parameter type
    sss_stat = sems_lite_get_Data(pContext, SEMS_LITE_GETDATA_EC_DOMAIN_PARAM_TYPE_TAG, rspBuf, &rspBufLen);
    if ((sss_stat == kStatus_SSS_Success) && (rspBufLen == 5)) {
        sss_stat  = kStatus_SSS_Fail;
        retStatus = (smStatus_t)((rspBuf[rspBufLen - 2] << 8) | (rspBuf[rspBufLen - 1]));
        if ((retStatus == SM_OK) && (rspBuf[0] == SEMS_LITE_GETDATA_EC_DOMAIN_PARAM_TYPE_TAG) &&
            (rspBuf[1] == SEMS_LITE_GETDATA_EC_DOMAIN_PARAM_TYPE_TAGLEN)) {
            sss_stat    = kStatus_SSS_Success;
            *pParamType = rspBuf[2];
        }
    }
    else {
        sss_stat = kStatus_SSS_Fail;
    }
cleanup:
    return sss_stat;
}

sss_status_t sems_lite_get_FIPS_info(sems_lite_agent_ctx_t *pContext, uint8_t *pFIPSInfo)
{
    sss_status_t sss_stat = kStatus_SSS_Fail;
    smStatus_t retStatus  = SM_NOT_OK;
    uint8_t rspBuf[16]    = {0};
    size_t rspBufLen      = sizeof(rspBuf);

    ENSURE_OR_GO_CLEANUP(pContext != NULL);
    // SEMS Lite session should be opened first.
    ENSURE_OR_GO_CLEANUP(pContext->session_opened == true);

    // P2 '0xC6' Get Configured FIPS Information
    sss_stat = sems_lite_get_Data(pContext, SEMS_LITE_GETDATA_FIPS_INFO_TAG, rspBuf, &rspBufLen);
    if ((sss_stat == kStatus_SSS_Success) && (rspBufLen == 5)) {
        sss_stat  = kStatus_SSS_Fail;
        retStatus = (smStatus_t)((rspBuf[rspBufLen - 2] << 8) | (rspBuf[rspBufLen - 1]));
        if ((retStatus == SM_OK) && (rspBuf[0] == SEMS_LITE_GETDATA_FIPS_INFO_TAG) &&
            (rspBuf[1] == SEMS_LITE_GETDATA_FIPS_INFO_TAGLEN)) {
            sss_stat   = kStatus_SSS_Success;
            *pFIPSInfo = rspBuf[2];
        }
    }
    else {
        sss_stat = kStatus_SSS_Fail;
    }
cleanup:
    return sss_stat;
}

#endif /* #if SSS_HAVE_APPLET_SE05X_IOT */
