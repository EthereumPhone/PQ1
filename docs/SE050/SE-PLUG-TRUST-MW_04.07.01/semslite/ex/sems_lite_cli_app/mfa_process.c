/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "mfa_process.h"

#include <nxEnsure.h>
#include <nxLog_App.h>

#include "mfa_utils.h"
#include "nxp_mfa_utils.h"
#include "nxp_iot_agent.h"
#include "nxp_iot_agent_keystore_sss_se05x.h"
#include "smCom.h"
#include <limits.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define SEMS_LITE_GETDATA_BUF_SIZE 256
#define SEMS_LITE_UID_SIZE 18
#define SEMS_LITE_GETDATA_CA_IDENTIFIER_TAG 0x42
#define SEMS_LITE_GETDATA_CA_KEY_IDENTIFIER_TAG 0x45
#define SEMS_LITE_GETDATA_CA_IDENTIFIER_TAGLEN 0x10
#define SEMS_LITE_GETDATA_CA_KEY_IDENTIFIER_TAGLEN 0x08

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

sems_lite_agent_ctx_t g_sems_lite_agent_load_ctx = {0};
ex_sss_boot_ctx_t gfeature_app_sems_lite_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */
static void mfa_print_infoSE(sems_lite_SEAppInfoList_t *pInofList);
/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

//ISO 7816-4 Annex D.
static int mfa_tlv_get_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SEMS_LITE_BIN_PKG_TAG_t tag, uint8_t *rsp, size_t *pRspLen)
{
    int retVal      = 1;
    uint8_t *pBuf   = 0;
    uint8_t got_tag = 0;
    size_t extendedLen;
    size_t rspLen;
    //size_t len;

    if (bufLen < 2) {
        goto cleanup;
    }

    if ((*pBufIndex) > (bufLen - 2) /* Tag + len */) {
        goto cleanup;
    }

    pBuf   = buf + (*pBufIndex);
    got_tag = *pBuf++;

    if (got_tag != tag)
        goto cleanup;
    rspLen = *pBuf++;

    if (rspLen <= 0x7FU) {
        extendedLen = rspLen;
        *pBufIndex += (1 + 1);
    }
    else if (rspLen == 0x81) {
        if ((*pBufIndex) > (bufLen - 3)) {
            goto cleanup;
        }
        extendedLen = *pBuf;
        *pBufIndex += (1 + 1 + 1);
    }
    else if (rspLen == 0x82) {
        if ((*pBufIndex) > (bufLen - 4)) {
            goto cleanup;
        }
        extendedLen = *((uint16_t *)pBuf);
        *pBufIndex += (1 + 1 + 2);
    }
    else if (rspLen == 0x84) {
        if ((*pBufIndex) > (bufLen - 6)) {
            goto cleanup;
        }
        extendedLen = *((uint32_t *)pBuf);
        *pBufIndex += (1 + 1 + 4);
    }
    else {
        goto cleanup;
    }

    if (extendedLen > *pRspLen)
        goto cleanup;

    if (extendedLen > bufLen)
        goto cleanup;

    if ((*pBufIndex) > (SIZE_MAX - extendedLen)) {
        goto cleanup;
    }

    *pRspLen = extendedLen;
    *pBufIndex += extendedLen;
    while (extendedLen-- > 0) {
        *rsp++ = *pBuf++;
    }
    retVal = 0;
cleanup:
    return retVal;
}

//ISO 7816-4 Annex D.
static int mfa_tlv_get_value_pointer(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SEMS_LITE_BIN_PKG_TAG_t tag, size_t *pEndBufIndex)
{
    int retVal      = 1;
    uint8_t *pBuf   = 0;
    uint8_t got_tag = 0;
    size_t extendedLen;
    size_t rspLen;
    //size_t len;

    if (bufLen < 2) {
        goto cleanup;
    }

    if ((*pBufIndex) > (bufLen - 2) /* Tag + len */) {
        goto cleanup;
    }

    pBuf   = buf + (*pBufIndex);
    got_tag = *pBuf++;

    if (got_tag != tag)
        goto cleanup;
    rspLen = *pBuf++;

    if (rspLen <= 0x7FU) {
        extendedLen = rspLen;
        *pBufIndex += (1 + 1);
    }
    else if (rspLen == 0x81) {
        if ((*pBufIndex) > (bufLen - 3)) {
            goto cleanup;
        }
        extendedLen = *pBuf;
        *pBufIndex += (1 + 1 + 1);
    }
    else if (rspLen == 0x82) {
        if ((*pBufIndex) > (bufLen - 4)) {
            goto cleanup;
        }
        extendedLen = *((uint16_t *)pBuf);
        *pBufIndex += (1 + 1 + 2);
    }
    else if (rspLen == 0x84) {
        if ((*pBufIndex) > (bufLen - 6)) {
            goto cleanup;
        }
        extendedLen = *((uint32_t *)pBuf);
        *pBufIndex += (1 + 1 + 4);
    }
    else {
        goto cleanup;
    }

    if (extendedLen > bufLen) {
        goto cleanup;
    }

    if ((*pEndBufIndex) > (SIZE_MAX - *pBufIndex - extendedLen)) {
        goto cleanup;
    }
    *pEndBufIndex += *pBufIndex + extendedLen;

    retVal = 0;
cleanup:
    return retVal;
}

sss_status_t mfa_process_parse_binary(uint8_t * buffer,
    size_t buffer_size,
    multicast_package_t * package,
    sub_component_metaData_t * subcomponent)
{
    int tlvRet       = 0;
    size_t bufferIndex = 0;
    size_t bufferEndIndex = 0;
    size_t elementSize = 0;
    sss_status_t sss_stat = kStatus_SSS_Fail;

    tlvRet = mfa_tlv_get_value_pointer(buffer, &bufferIndex, buffer_size, SEMS_LITE_TAG_MULTTICAST_PACKAGE, &bufferEndIndex);
    if (0 != tlvRet) {
        goto cleanup;
    }

    elementSize = sizeof(package->semsLiteAPIVersion);
    tlvRet = mfa_tlv_get_u8buf(buffer, &bufferIndex, buffer_size, SEMS_LITE_TAG_MULTICAST_PACKAGE_FORMAT_VERSION, (uint8_t *)(&(package->semsLiteAPIVersion)), &elementSize);
    if (0 != tlvRet) {
        goto cleanup;
    }

    elementSize = sizeof(package->targetEntityID);
    tlvRet = mfa_tlv_get_u8buf(buffer, &bufferIndex, buffer_size, SEMS_LITE_TAG_TARGET_ENTITY_ID, package->targetEntityID, &elementSize);
    if (0 != tlvRet) {
        goto cleanup;
    }

    if (*(buffer + bufferIndex) == SEMS_LITE_TAG_TARGET_12_NC) {
        // Target12nc is only supported for MulticastPackageFormatVersion 1.2 and later.
        elementSize = sizeof(package->target12Nc);
        tlvRet = mfa_tlv_get_u8buf(buffer, &bufferIndex, buffer_size, SEMS_LITE_TAG_TARGET_12_NC, package->target12Nc, &elementSize);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }

    if (*(buffer + bufferIndex) == SEMS_LITE_TAG_CA_PUB_KEY) {
        // PkSemsCaAut is only supported for MulticastPackageFormatVersion 1.3 and later.
        bufferEndIndex = 0;
        tlvRet = mfa_tlv_get_value_pointer(buffer, &bufferIndex, buffer_size, SEMS_LITE_TAG_CA_PUB_KEY, &bufferEndIndex);
        if (0 != tlvRet) {
            goto cleanup;
        }
        ENSURE_OR_GO_CLEANUP(bufferEndIndex >= bufferIndex);
        package->pkSemsCaAutLen = bufferEndIndex - bufferIndex;
        package->pPkSemsCaAut = buffer + bufferIndex;
        bufferIndex = bufferEndIndex;
    }
    else {
        package->pkSemsCaAutLen = 0;
        package->pPkSemsCaAut = NULL;
    }

    elementSize = sizeof(package->requiredFreeBytesNonVolatileMemory);
    tlvRet = mfa_tlv_get_u8buf(buffer, &bufferIndex, buffer_size, SEMS_LITE_TAG_REQUIRED_FREE_BYTES_NON_VOLATILE_MEMORY, (uint8_t *)(&(package->requiredFreeBytesNonVolatileMemory)), &elementSize);
    if (0 != tlvRet) {
        goto cleanup;
    }

    elementSize = sizeof(package->requiredFreeBytesTransientMemory);
    tlvRet = mfa_tlv_get_u8buf(buffer, &bufferIndex, buffer_size, SEMS_LITE_TAG_REQUIRED_FREE_BYTES_TRANSIENT_MEMORY, (uint8_t *)(&(package->requiredFreeBytesTransientMemory)), &elementSize);
    if (0 != tlvRet) {
        goto cleanup;
    }

    bufferEndIndex = 0;
    tlvRet = mfa_tlv_get_value_pointer(buffer, &bufferIndex, buffer_size, SEMS_LITE_TAG_MULTICAST_PACKAGE_NAME, &bufferEndIndex);
    if (0 != tlvRet) {
        goto cleanup;
    }
    ENSURE_OR_GO_CLEANUP(bufferEndIndex >= bufferIndex);
    package->multicastPackageNameLen = bufferEndIndex - bufferIndex;
    package->pMulticastPackageName = (char *)(buffer + bufferIndex);
    bufferIndex = bufferEndIndex;

    elementSize = sizeof(package->multicastPackageVersion);
    tlvRet = mfa_tlv_get_u8buf(buffer, &bufferIndex, buffer_size, SEMS_LITE_TAG_MULTICAST_PACKAGE_VERSION, package->multicastPackageVersion, &elementSize);
    if (0 != tlvRet) {
        goto cleanup;
    }

    bufferEndIndex = 0;
    tlvRet = mfa_tlv_get_value_pointer(buffer, &bufferIndex, buffer_size, SEMS_LITE_TAG_SUBCOMPONENT_META_DATA, &bufferEndIndex);
    if (0 != tlvRet) {
        goto cleanup;
    }
    else {
        int subcomponentIndex = 0;
        size_t subcompBufferIndex = bufferIndex;
        size_t subcompBufferEndIndex = bufferEndIndex;
        uint8_t * subcomponent_end;
        subcomponent_end = buffer + subcompBufferEndIndex;

        package->pSubComponentMetaData = NULL;
        while (buffer + subcompBufferIndex < subcomponent_end) {

            if (subcomponentIndex >= SEMS_LITE_MAX_SUBCOMPONENT_NUMBER) {
                LOG_E("MFA not enough subcomponent");
                goto cleanup;
            }

            // Add to the link
            if (subcomponentIndex == 0)
                package->pSubComponentMetaData = subcomponent;
            else
                subcomponent[subcomponentIndex - 1].pNextSubComponentMetaData = &subcomponent[subcomponentIndex];

            // Find subcomponent name
            subcompBufferEndIndex = 0;
            tlvRet = mfa_tlv_get_value_pointer(buffer,
                &subcompBufferIndex,
                buffer_size,
                SEMS_LITE_TAG_SUBCOMPONENT_META_DATA_NAME,
                &subcompBufferEndIndex);
            if (0 != tlvRet) {
                goto cleanup;
            }
            subcomponent[subcomponentIndex].pName = (char *)(buffer + subcompBufferIndex);
            subcomponent[subcomponentIndex].nameLen = subcompBufferEndIndex - subcompBufferIndex;
            subcompBufferIndex = subcompBufferEndIndex;

            // Find subcomponent name
            subcompBufferEndIndex = 0;
            tlvRet = mfa_tlv_get_value_pointer(buffer,
                &subcompBufferIndex,
                buffer_size,
                SEMS_LITE_TAG_SUBCOMPONENT_META_DATA_AID,
                &subcompBufferEndIndex);
            if (0 != tlvRet) {
                goto cleanup;
            }
            subcomponent[subcomponentIndex].pAid = (buffer + subcompBufferIndex);
            subcomponent[subcomponentIndex].aidLen = subcompBufferEndIndex - subcompBufferIndex;
            subcompBufferIndex = subcompBufferEndIndex;

            // Find subcomponent version
            elementSize = sizeof(subcomponent[subcomponentIndex].version);
            tlvRet = mfa_tlv_get_u8buf(buffer,
                &subcompBufferIndex, buffer_size,
                SEMS_LITE_TAG_SUBCOMPONENT_META_DATA_VERSION,
                (uint8_t *)(&(subcomponent[subcomponentIndex].version)),
                &elementSize);
            if (0 != tlvRet) {
                goto cleanup;
            }

            // SWContentRegister is only supported for MulticastPackageFormatVersion 1.3 and later.
            if (*(buffer + subcompBufferIndex) == SEMS_LITE_TAG_SUBCOMPONENT_SW_CONTENT_REGISTER) {
                // Find subcomponent SWContentRegister
                subcompBufferEndIndex = 0;
                tlvRet = mfa_tlv_get_value_pointer(buffer,
                    &subcompBufferIndex,
                    buffer_size,
                    SEMS_LITE_TAG_SUBCOMPONENT_SW_CONTENT_REGISTER,
                    &subcompBufferEndIndex);
                if (0 != tlvRet) {
                    goto cleanup;
                }
                subcomponent[subcomponentIndex].pSWContentRegister = (char *)(buffer + subcompBufferIndex);
                subcomponent[subcomponentIndex].swContentRegisterLen = subcompBufferEndIndex - subcompBufferIndex;
                subcompBufferIndex = subcompBufferEndIndex;
            }
            else {
                subcomponent[subcomponentIndex].pSWContentRegister = NULL;
                subcomponent[subcomponentIndex].swContentRegisterLen = 0;
            }

            // Find subcomponent min prev version
            elementSize = sizeof(subcomponent[subcomponentIndex].minimumPreviousVersion);
            tlvRet = mfa_tlv_get_u8buf(buffer,
                &subcompBufferIndex, buffer_size,
                SEMS_LITE_TAG_SUBCOMPONENT_MINI_PREVIOUS_VERSION,
                (uint8_t *)(&(subcomponent[subcomponentIndex].minimumPreviousVersion)),
                &elementSize);
            if (0 != tlvRet) {
                goto cleanup;
            }

            subcomponentIndex++;
        }

        if (subcomponentIndex != 0)
            subcomponent[subcomponentIndex - 1].pNextSubComponentMetaData = NULL;
    }
    bufferIndex = bufferEndIndex;

    bufferEndIndex = 0;
    tlvRet = mfa_tlv_get_value_pointer(buffer, &bufferIndex, buffer_size, SEMS_LITE_TAG_SIGNATURE_OVER_COMMANDS, &bufferEndIndex);
    if (0 != tlvRet) {
        goto cleanup;
    }
    ENSURE_OR_GO_CLEANUP(bufferEndIndex >= bufferIndex);
    package->signatureOverCommandsLen = bufferEndIndex - bufferIndex;
    package->pSignatureOverCommands = buffer + bufferIndex;
    bufferIndex = bufferEndIndex;

    bufferEndIndex = 0;
    tlvRet = mfa_tlv_get_value_pointer(buffer, &bufferIndex, buffer_size, SEMS_LITE_TAG_MULTICAST_COMMANDS, &bufferEndIndex);
    if (0 != tlvRet) {
        goto cleanup;
    }
    ENSURE_OR_GO_CLEANUP(bufferEndIndex >= bufferIndex);
    package->multicastCommandsLen = bufferEndIndex - bufferIndex;
    package->pMulticastCommands = buffer + bufferIndex;
    bufferIndex = bufferEndIndex;

    sss_stat = kStatus_SSS_Success;
cleanup:
    return sss_stat;
}

void mfa_process_loadpkg(const char *pkgname)
{
    sems_lite_status_t status = kStatus_SEMS_Lite_ERR_Fatal;
    FILE *fp = NULL;
    long int numbytes = 0;
    uint8_t *buffer = NULL;
    multicast_package_t package;
    sub_component_metaData_t subcomponent[SEMS_LITE_MAX_SUBCOMPONENT_NUMBER];
    size_t readSize = 0;

    if (strstr(pkgname, "..") != NULL) {
        LOG_W("Potential directory traversal");
    }

    fp = fopen(pkgname, "rb");
    if (fp == NULL) {
        printf("File not found");
        exit(2);
    }
    if (fseek(fp, 0L, SEEK_END) != 0) {
        LOG_E("fseek failed");
        goto cleanup;
    }
    numbytes = ftell(fp);
    if (numbytes < 0) {
        printf("ftell failed");
        goto cleanup;
    }

    buffer = (uint8_t *)malloc(numbytes); /* Total binary file size */
    if (buffer == NULL) {
        printf("malloc failed !!!");
        if (fclose(fp) != 0) {
            LOG_E("Error in closing file.");
        }
        exit(2);
    }

    if (fseek(fp, 0L, SEEK_SET) != 0) {
        LOG_E("fseek failed");
        goto cleanup;
    }
    readSize = fread(buffer, numbytes, 1, fp);
    if (readSize == 0 && ferror(fp)) {
        printf("fread failed");
        goto cleanup;
    }

    if (mfa_process_parse_binary(buffer, numbytes, &package, subcomponent) != kStatus_SSS_Success){
        LOG_E("Parse binary file failed");
        goto cleanup;
    }

    // Load package
    status = sems_lite_agent_load_package(
        &g_sems_lite_agent_load_ctx, &package);
    printSEMSLiteStatusCode(status);

cleanup:
    if (fp != NULL) {
        if (fclose(fp) != 0) {
            LOG_E("Error in closing file.");
        }
    }
    if (buffer != NULL) {
        free(buffer);
    }
}

void mfa_process_getuid()
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint8_t uid[SEMS_LITE_GETDATA_BUF_SIZE];
    size_t uidLen = SEMS_LITE_GETDATA_BUF_SIZE;
    sss_status = sems_lite_get_UUID(&g_sems_lite_agent_load_ctx, uid, &uidLen);
    print_SSS_StatusCode(sss_status);
    if (sss_status == kStatus_SSS_Success) {
        print_hex_contents((const char *)"uid", uid, uidLen);
    }
}

void mfa_process_getappcontents(const char *appAid)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint8_t *aidhex = NULL;
    size_t aidhexLen = 0;
    sems_lite_SEAppInfoList_t getAppInfoList[50];
    size_t i;
    size_t getAppInfoListLen =
        sizeof(getAppInfoList) / sizeof(getAppInfoList[0]);

    if (appAid) {
        aidhex = hexstr_to_bytes(appAid, &aidhexLen);
        if (aidhex == NULL) {
            LOG_E("invalid hexstr in [%s]\n", appAid);
            return;
        }
    }
    if (aidhexLen > UINT8_MAX) {
        LOG_E("aidhexLen can not be greater than 1 byte.");
        free(aidhex);
        return;
    }
    sss_status = sems_lite_get_SEAppInfo(
        &g_sems_lite_agent_load_ctx, aidhex, (uint8_t)aidhexLen, getAppInfoList, &getAppInfoListLen);

    print_SSS_StatusCode(sss_status);
    if (sss_status == kStatus_SSS_Success) {
        for (i = 0; i < getAppInfoListLen; i++) {
            mfa_print_infoSE(&getAppInfoList[i]);
        }
    }
    if (aidhex != NULL) {
        free(aidhex);
    }
}

void mfa_process_getpkgcontents(const char *pkgAid)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint8_t *aidhex         = NULL;
    size_t aidhexLen        = 0;
    sems_lite_SEAppInfoList_t getAppInfoList[50];
    size_t i;
    size_t getAppInfoListLen = sizeof(getAppInfoList) / sizeof(getAppInfoList[0]);

    if (pkgAid) {
        aidhex = hexstr_to_bytes(pkgAid, &aidhexLen);
        if (aidhex == NULL) {
            LOG_E("invalid hexstr in [%s]\n", pkgAid);
            return;
        }
    }

    if (aidhexLen > UINT8_MAX) {
        LOG_E("aidhexLen can not be greater than 1 byte.");
        free(aidhex);
        return;
    }
    sss_status = sems_lite_get_SEPkgInfo(
        &g_sems_lite_agent_load_ctx, aidhex, (uint8_t)aidhexLen, getAppInfoList, &getAppInfoListLen);

    print_SSS_StatusCode(sss_status);
    if (sss_status == kStatus_SSS_Success) {
        for (i = 0; i < getAppInfoListLen; i++) {
            mfa_print_infoSE(&getAppInfoList[i]);
        }
    }

    if (aidhex != NULL) {
        free(aidhex);
    }
}

void mfa_process_getPbkeyId()
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint8_t pbKey[SEMS_LITE_GETDATA_BUF_SIZE];
    size_t pbKeyLen = SEMS_LITE_GETDATA_BUF_SIZE;

    sss_status = sems_lite_get_Publickey(&g_sems_lite_agent_load_ctx, pbKey, &pbKeyLen);
    print_SSS_StatusCode(sss_status);
    if (sss_status == kStatus_SSS_Success) {
        print_hex_contents((const char *)"PbkeyId", pbKey, pbKeyLen);
    }
}

void mfa_process_semslitegetversion()
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint8_t appletVer[SEMS_LITE_GETDATA_BUF_SIZE];
    size_t appletVerLen = SEMS_LITE_GETDATA_BUF_SIZE;
    sss_status =
        sems_lite_get_AppletVersion(&g_sems_lite_agent_load_ctx, appletVer, &appletVerLen);
    print_SSS_StatusCode(sss_status);
    if (sss_status == kStatus_SSS_Success) {
        print_hex_contents((const char *)"appletVer", appletVer, appletVerLen);
    }
}

void mfa_process_getsignature(const char *filename)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    FILE *fp = NULL;
    uint8_t sig[SEMS_LITE_GETDATA_BUF_SIZE];
    size_t sigLen = SEMS_LITE_GETDATA_BUF_SIZE;

    if (filename != NULL) {
        fp = fopen(filename, "wb");
        if (fp == NULL) {
            LOG_E("File open failed");
            return;
        }
    }
    else {
        LOG_W("Not output file specified.");
    }

    sss_status =
        sems_lite_get_SignatureofLastScript(&g_sems_lite_agent_load_ctx, sig, &sigLen);
    print_SSS_StatusCode(sss_status);
    if (sss_status == kStatus_SSS_Success) {
        print_hex_contents((const char *)"signature", sig, sigLen);
        if (fp != NULL)
            fwrite(sig, 1, sigLen, fp);
    }
    if (fp != NULL)
        if (fclose(fp) != 0) {
            LOG_E("fclose error");
        }
}

void mfa_process_checkTear()
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    sems_lite_tearDown_status_t tearStatus;
    sss_status = sems_lite_check_Tear(&g_sems_lite_agent_load_ctx, &tearStatus);
    print_SSS_StatusCode(sss_status);
    if (sss_status == kStatus_SSS_Success) {
        printf("Tear Status: %d\n", tearStatus);
    }
}

void mfa_process_checkUpgradeProgress()
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    sems_lite_upgradeProgress_status_t upgradeStatus;

    sss_status =
        sems_lite_check_AppletUpgradeProgress(&g_sems_lite_agent_load_ctx, &upgradeStatus);
    print_SSS_StatusCode(sss_status);
    if (sss_status == kStatus_SSS_Success) {
        printf("Upgrade Status: %d\n", upgradeStatus);
    }
}

void mfa_process_getENCIdentifier()
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint8_t rspBuf[SEMS_LITE_GETDATA_BUF_SIZE] = {0};
    size_t rspBufLen = sizeof(rspBuf);
    sss_status =
        sems_lite_get_ENCIdentifier(&g_sems_lite_agent_load_ctx, rspBuf, &rspBufLen);
    print_SSS_StatusCode(sss_status);
    if (sss_status == kStatus_SSS_Success) {
        print_hex_contents((const char *)"EnckeyId", rspBuf, rspBufLen);
    }
}

static sss_status_t mfa_process_getData(sems_lite_agent_ctx_t *pContext,
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

    /* Copy the appropriate tag coming from respective function at P2 */
    getDataCmd[3] = tag_P2;

    if (!(cmdBufLen < (255 - 5))) {
        goto cleanup;
    }

    if (cmdBufLen > 0) {
        getDataCmdLen += (U16)cmdBufLen;
        getDataCmdLen++;
        memcpy(&getDataCmd[5], cmdBuf, cmdBufLen);
        getDataCmd[4] /* Lc */ = (uint8_t)cmdBufLen;
    }

    if (!(*pRspBufLen > 0)){
        goto cleanup;
    }

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

    respstat = smCom_TransceiveRaw(pContext->pS05x_Ctx->conn_ctx,
        (uint8_t *)getDataCmd,
        getDataCmdLen,
        pRspBuf,
        &getDataRspLen);
    if (respstat != SM_OK) {
        LOG_E("Could not get requested Data!!!");
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP(getDataRspLen >= 2);
    if (pRspBuf[getDataRspLen - 2] == 0x90 &&
        pRspBuf[getDataRspLen - 1] == 0x00) {
        /* 0x9000*/
        sss_stat = kStatus_SSS_Success;
    }
    else {
        sss_stat = kStatus_SSS_Fail;
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

void mfa_process_getCAIdentifier()
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_status_t sss_status = kStatus_SSS_Fail;
    smStatus_t retStatus = SM_NOT_OK;
    uint8_t rspBuf[24] = {0};
    size_t rspBufLen = sizeof(rspBuf);

    // P2 '0x46' Check Tear during script execution
    sss_status =
        mfa_process_getData(&g_sems_lite_agent_load_ctx, SEMS_LITE_GETDATA_CA_IDENTIFIER_TAG, NULL, 0, rspBuf, &rspBufLen);

    status = sems_lite_agent_session_close(&g_sems_lite_agent_load_ctx);
    if (status != kStatus_SSS_Success) {
        LOG_E("SEMS Lite close session failed!!!");
    }

    print_SSS_StatusCode(sss_status);
    if ((sss_status == kStatus_SSS_Success) && (rspBufLen > 2)) {
        sss_status = kStatus_SSS_Fail;
        retStatus = (smStatus_t)((rspBuf[rspBufLen - 2] << 8) | (rspBuf[rspBufLen - 1]));
        if ((retStatus == SM_OK) && (rspBuf[0] == SEMS_LITE_GETDATA_CA_IDENTIFIER_TAG) &&
            (rspBuf[1] == SEMS_LITE_GETDATA_CA_IDENTIFIER_TAGLEN)) {
            print_hex_contents((const char *)"CA-SEMS Identifier", &rspBuf[2], rspBuf[1]);
            sss_status = kStatus_SSS_Success;
        }
    }

    return;
}

void mfa_process_getCAKeyIdentifier()
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_status_t sss_status = kStatus_SSS_Fail;
    smStatus_t retStatus = SM_NOT_OK;
    uint8_t rspBuf[24] = {0};
    size_t rspBufLen = sizeof(rspBuf);

    // P2 '0x46' Check Tear during script execution
    sss_status =
        mfa_process_getData(&g_sems_lite_agent_load_ctx, SEMS_LITE_GETDATA_CA_KEY_IDENTIFIER_TAG, NULL, 0, rspBuf, &rspBufLen);

    status = sems_lite_agent_session_close(&g_sems_lite_agent_load_ctx);
    if (status != kStatus_SSS_Success) {
        LOG_E("SEMS Lite close session failed!!!");
    }

    print_SSS_StatusCode(sss_status);
    if ((sss_status == kStatus_SSS_Success) && (rspBufLen > 2)) {
        sss_status = kStatus_SSS_Fail;
        retStatus = (smStatus_t)((rspBuf[rspBufLen - 2] << 8) | (rspBuf[rspBufLen - 1]));
        if ((retStatus == SM_OK) && (rspBuf[0] == SEMS_LITE_GETDATA_CA_KEY_IDENTIFIER_TAG) &&
            (rspBuf[1] == SEMS_LITE_GETDATA_CA_KEY_IDENTIFIER_TAGLEN)) {
            print_hex_contents((const char *)"CA-SEMS Key Identifier", &rspBuf[2], rspBuf[1]);
            sss_status = kStatus_SSS_Success;
        }
    }

    return;
}

void mfa_process_getPkgVerion(const char *pkgAid)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint8_t *aidhex = NULL;
    size_t aidhexLen = 0;
    sems_lite_SEAppInfoList_t getAppInfoList[50] = {0};
	size_t i;
    size_t getAppInfoListLen = sizeof(getAppInfoList) / sizeof(getAppInfoList[0]);

    if (pkgAid) {
        aidhex = hexstr_to_bytes(pkgAid, &aidhexLen);
        if (aidhex == NULL) {
            LOG_E("invalid hexstr in [%s]\n", pkgAid);
            return;
        }
    }

    if (aidhexLen > UINT8_MAX) {
        LOG_E("aidhexLen can not be greater than 1 byte.");
        free(aidhex);
        return;
    }
    sss_status = sems_lite_get_SEPkgInfo(
        &g_sems_lite_agent_load_ctx, aidhex, (uint8_t)aidhexLen, getAppInfoList, &getAppInfoListLen);
    print_SSS_StatusCode(sss_status);

    for (i = 0; i < getAppInfoListLen; i++) {
        LOG_W("===============================");
        if (getAppInfoList[i].pAID) {
            LOG_MAU8_I("AID", getAppInfoList[i].pAID, getAppInfoList[i].AIDLen);
        }
        if (getAppInfoList[i].pLoadFileVersionNumber) {
            LOG_MAU8_I("Version Number",
                getAppInfoList[i].pLoadFileVersionNumber,
                getAppInfoList[i].LoadFileVersionNumberLen);
        }
    }
    if (aidhex != NULL) {
        free(aidhex);
    }
}

void mfa_process_getFreePHeap()
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_status_t sss_status = kStatus_SSS_Fail;
    sems_lite_available_mem_t memInfo = {0};

    sss_status =
        sems_lite_get_available_mem(&g_sems_lite_agent_load_ctx, (uint8_t *)&memInfo);

    if (sss_status == kStatus_SSS_Success) {
        LOG_I("availableCODMemory %u", memInfo.availableCODMemory);
        LOG_I("availableCORMemory %u", memInfo.availableCORMemory);
        LOG_I("availablePersistentMemory %u", memInfo.availablePersistentMemory);
        LOG_I("availableIDX %u", memInfo.availableIDX);
        LOG_I("Free PHeap Central Gap %u", memInfo.freePHeapCentralGap);
        LOG_I("Free freeTransient %u", memInfo.freeTransient);
    }

    status = sems_lite_agent_session_close(&g_sems_lite_agent_load_ctx);
    if (status != kStatus_SSS_Success) {
        LOG_E("SEMS Lite close session failed!!!");
    }

    print_SSS_StatusCode(sss_status);

    return;
}

/* ************************************************************************** */
/* Static function definitions                                               */
/* ************************************************************************** */
static void mfa_print_infoSE(sems_lite_SEAppInfoList_t *pInofList)
{
    LOG_W("===============================");
    if (pInofList->pAID) {
        LOG_MAU8_I("AID", pInofList->pAID, pInofList->AIDLen);
    }
    if (pInofList->LifeCycleState) {
        LOG_I("Life Cycle State: 0x%02X", pInofList->LifeCycleState);
    }
    if (pInofList->pLoadFileVersionNumber) {
        LOG_MAU8_I("Version Number",
            pInofList->pLoadFileVersionNumber,
            pInofList->LoadFileVersionNumberLen);
    }
    if (pInofList->pPriviledges) {
        LOG_MAU8_I(
            "Privileges", pInofList->pPriviledges, pInofList->PriviledgesLen);
    }
    if (pInofList->pLoadFileAID) {
        LOG_MAU8_I("Load File AID",
            pInofList->pLoadFileAID,
            pInofList->LoadFileAIDLen);
    }
    if (pInofList->pSecurityDomainAID) {
        LOG_MAU8_I("Security Domain AID",
            pInofList->pSecurityDomainAID,
            pInofList->SecurityDomainAIDLen);
    }
}

void mfa_process_getECParameter()
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint8_t EC_parameter;
    sss_status = sems_lite_get_FIPS_EC_parameter_type(&g_sems_lite_agent_load_ctx, &EC_parameter);
    print_SSS_StatusCode(sss_status);
    if (sss_status == kStatus_SSS_Success) {
        printf("Configured EC domain parameter type: %u\n", EC_parameter);
    }
}

void mfa_process_getFIPSInfo()
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint8_t FIPS_info;
    sss_status = sems_lite_get_FIPS_info(&g_sems_lite_agent_load_ctx, &FIPS_info);
    print_SSS_StatusCode(sss_status);
    if (sss_status == kStatus_SSS_Success) {
        printf("Configured FIPS Information: %u\n", FIPS_info);
    }
}

