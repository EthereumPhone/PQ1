/* Copyright 2021,2024 NXP
 *
 * This software is owned or controlled by NXP and may only be used
 * strictly in accordance with the applicable license terms.  By expressly
 * accepting such terms or by downloading, installing, activating and/or
 * otherwise using the software, you are agreeing that you have read, and
 * that you agree to comply with and are bound by, such license terms.  If
 * you do not agree to be bound by the applicable license terms, then you
 * may not retain, install, activate or otherwise use the software.
 */

#include "nxScp03_Const.h"
#include "smCom.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <nxEnsure.h>
#include <string.h>
#include "nxLog_hostLib.h"
#include "sus_APDU.h"
#if defined(USE_RTOS) && USE_RTOS == 1
#include "FreeRTOS.h"
#else
#include <malloc.h>
#endif

#define EXPECTED_APPLET_VERSION_A693 (0x101)
static smStatus_t select_applet(
    pSe05xSession_t session_ctx, uint8_t *selectCmd, uint16_t selectCmdLen, uint16_t *pAppletVersion);
static size_t getRdsTlvLen(se_plainRDS *pRdsData);
static void *SUS_MemMalloc(size_t size);
static void SUS_MemFree(void *buf);

/* clang-format off */
#define SUS_APPLET_AID_FIRA_NON_COMPLIANT { \
        0xA0, 0x00, 0x00, 0x03, 0x96, \
        0x54, 0x53, 0x00, 0x00, 0x00, \
        0x01, 0x04, 0x02, 0x00, 0x00, \
        0x00,}

#define SUS_APPLET_AID_FIRA_COMPLIANT { \
        0xA0, 0x00, 0x00, 0x08, 0x67, 0x53, 0x55, 0x53, 0x00 \
    }

#define SUS_CLIENT_APPLET_AID { \
        0xA0, 0x00, 0x00, 0x03, 0x96,  \
        0x54, 0x53, 0x00, 0x00, 0x00,  \
        0x01, 0x04, 0xF2, 0x00, 0x00,  \
        0x00,}

/* clang-format on */

#define SUS_INS_INITIATE_BINDING (0x20)
#define SUS_CLIENT_MAX_RDS_PAYLOADLEN (223)
#define SUS_INS_WRAP_DATA (0xA0)
#define SIZEOFTLV(cmdLen) (cmdLen == 0 ? 0 : ((1 + (cmdLen <= 0x7f ? 1 : (cmdLen <= 0xFF ? 2 : 3)) + cmdLen)))

smStatus_t SUS_API_Init(pSe05xSession_t session_ctx, uint8_t isSusClient, uint8_t logical_channel)
{
    smStatus_t respstat = SM_NOT_OK;
    uint8_t openCmd[]   = {0x00, 0x70, 0x00, 0x00, logical_channel};
    U16 openCmdLen      = sizeof(openCmd);
    uint8_t resp[50]    = {0x00};
    U32 respLen         = sizeof(resp);
    U16 rv              = SM_NOT_OK;
    U16 appletNameLen   = 0;
    U16 appletVersion   = 0;

    ENSURE_OR_GO_EXIT(session_ctx);
    ENSURE_OR_GO_EXIT(session_ctx->conn_ctx);
    // open logical channel
    respstat = (smStatus_t)smCom_TransceiveRaw(session_ctx->conn_ctx, openCmd, openCmdLen, resp, &respLen);
    ENSURE_OR_GO_EXIT(respstat == SM_OK);

    session_ctx->logical_channel = logical_channel;

    respstat = SM_NOT_OK;

    if (respLen == 3 && resp[0] == logical_channel) {
        rv = (resp[respLen - 2] << 8) | (resp[respLen - 1]);
        ENSURE_OR_GO_EXIT(rv == SM_OK);

        if (isSusClient) {
            uint8_t appletName[] = SUS_CLIENT_APPLET_AID;
            appletNameLen        = sizeof(appletName);
            respstat             = select_applet(session_ctx, appletName, appletNameLen, &appletVersion);
        }
        else {
            uint8_t appletName_firaCompliant[] = SUS_APPLET_AID_FIRA_COMPLIANT;
            appletNameLen                      = sizeof(appletName_firaCompliant);
            respstat = select_applet(session_ctx, appletName_firaCompliant, appletNameLen, &appletVersion);
            if (SM_OK == respstat) {
                LOG_I("Fira Consortium Compliant SUS applet is present and selected");
            }
            else {
                uint8_t appletName[] = SUS_APPLET_AID_FIRA_NON_COMPLIANT;
                appletNameLen        = sizeof(appletName);
                respstat             = select_applet(session_ctx, appletName, appletNameLen, &appletVersion);
                if (SM_OK == respstat) {
                    LOG_W("Fira Consortium Non Compliant SUS applet is present and selected");
                    if (appletVersion != EXPECTED_APPLET_VERSION_A693) {
                        LOG_E("For A693 applet version less than 1.1 wrapped RDS does not work");
                        LOG_E("update the applet by using demo_semslite_SUS_A693");
                        respstat = SM_NOT_OK;
                    }
                }
                else {
                    LOG_E("SUS applet is not present");
                }
            }
        }
    }
    ENSURE_OR_GO_EXIT(respstat == SM_OK);
exit:
    return respstat;
}

smStatus_t SUS_API_GetData(pSe05xSession_t session_ctx, uint8_t getDataTag, uint8_t *pOutData, size_t *pOutDataLen)
{
    smStatus_t retStatus                 = SM_NOT_OK;
    uint8_t cmdBuf[SUS_MAX_BUF_SIZE_CMD] = {0};
    uint8_t *pCmdbuf                     = &cmdBuf[0];
    size_t cmdbufLen                     = 0;
    uint8_t respBuf[SUS_MAX_BUF_SIZE_RSP];
    U32 u32RXLen = (U32)SUS_MAX_BUF_SIZE_RSP;
    U16 rv       = SM_NOT_OK;

    *pCmdbuf++ = CLA_GP_7816 | session_ctx->logical_channel;
    *pCmdbuf++ = INS_GP_GET_DATA;
    *pCmdbuf++ = 0x00;
    *pCmdbuf++ = getDataTag;

    cmdbufLen = 4; //header
    pCmdbuf   = &cmdBuf[0];

    ENSURE_OR_GO_EXIT(session_ctx);
    ENSURE_OR_GO_EXIT(session_ctx->conn_ctx);
    ENSURE_OR_GO_EXIT(pOutData);
    ENSURE_OR_GO_EXIT(pOutDataLen);

    retStatus =
        (smStatus_t)smCom_TransceiveRaw(session_ctx->conn_ctx, pCmdbuf, (uint16_t)cmdbufLen, respBuf, &u32RXLen);
    if ((retStatus == SM_OK) && (u32RXLen >= 2)) {
        rv = (respBuf[u32RXLen - 2] << 8) | (respBuf[u32RXLen - 1]);
        if (rv == SM_OK) {
            if (*pOutDataLen >= u32RXLen - 2) {
                *pOutDataLen = u32RXLen - 2;
                memcpy(pOutData, respBuf, *pOutDataLen);
            }
            else {
                retStatus    = SM_NOT_OK;
                *pOutDataLen = u32RXLen - 2;
                LOG_E("Out put buffer size is not sufficient");
            }
        }
        else {
            retStatus = SM_NOT_OK;
            LOG_E("Command Failed!!!");
        }
    }
exit:
    return retStatus;
}

smStatus_t SUS_API_InitiateBinding(pSe05xSession_t session_ctx,
    uint8_t heliosLC,
    uint8_t brkIdentifier,
    uint8_t *pBindinData,
    size_t bindinDataLen,
    uint8_t *pOutData,
    size_t *pOutDataLen)
{
    smStatus_t retStatus                 = SM_NOT_OK;
    uint8_t cmdBuf[SUS_MAX_BUF_SIZE_CMD] = {0};
    uint8_t *pCmdbuf                     = &cmdBuf[0];
    size_t cmdbufLen                     = 0;
    uint8_t respBuf[SUS_MAX_BUF_SIZE_RSP];
    U32 u32RXLen = (U32)SUS_MAX_BUF_SIZE_RSP;
    U16 rv       = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(session_ctx);
    ENSURE_OR_GO_EXIT(session_ctx->conn_ctx);
    ENSURE_OR_GO_EXIT(pBindinData);
    ENSURE_OR_GO_EXIT(pOutData);
    ENSURE_OR_GO_EXIT(pOutDataLen);

    *pCmdbuf++ = CLA_GP_7816 | session_ctx->logical_channel;
    *pCmdbuf++ = SUS_INS_INITIATE_BINDING;
    *pCmdbuf++ = heliosLC;
    *pCmdbuf++ = brkIdentifier | 0x80;

    ENSURE_OR_GO_EXIT(bindinDataLen <= UINT8_MAX);
    *pCmdbuf++ = (uint8_t)bindinDataLen; // Lc

    cmdbufLen = 4 + 1; // header + Lc byte
    if ((SUS_MAX_BUF_SIZE_CMD - cmdbufLen) < bindinDataLen) {
        LOG_E("bindinDataLen is greater than max SUS Buffer");
        return retStatus;
    }
    memcpy(pCmdbuf, pBindinData, bindinDataLen);
    cmdbufLen = cmdbufLen + bindinDataLen;

    pCmdbuf = &cmdBuf[0];
    retStatus =
        (smStatus_t)smCom_TransceiveRaw(session_ctx->conn_ctx, pCmdbuf, (uint16_t)cmdbufLen, respBuf, &u32RXLen);
    if ((retStatus == SM_OK) && (u32RXLen >= 2)) {
        rv = (respBuf[u32RXLen - 2] << 8) | (respBuf[u32RXLen - 1]);
        if (rv == SM_OK) {
            if (*pOutDataLen >= u32RXLen - 2) {
                *pOutDataLen = u32RXLen - 2;
                memcpy(pOutData, respBuf, *pOutDataLen);
            }
            else {
                retStatus    = SM_NOT_OK;
                *pOutDataLen = u32RXLen - 2;
                LOG_E("Out put buffer size is not sufficient");
            }
        }
        else {
            retStatus = SM_NOT_OK;
            LOG_E("Command Failed!!!");
        }
    }
exit:
    return retStatus;
}

static size_t getRdsTlvLen(se_plainRDS *pRdsData)
{
    size_t sizeoftlv = 0;
    ENSURE_OR_GO_EXIT(pRdsData);

    sizeoftlv = SIZEOFTLV(pRdsData->rangingSessionKeyLen) + SIZEOFTLV(pRdsData->rspndrRangingKeyLen) +
                SIZEOFTLV(pRdsData->clientDataLen) + SIZEOFTLV(pRdsData->transactionIdLen) +
                SIZEOFTLV(pRdsData->KeyIdLen) + SIZEOFTLV(pRdsData->arbtDataLen) + SIZEOFTLV(pRdsData->appletAidLen) +
                SIZEOFTLV(pRdsData->sessionIdLen);

    // ToDo
    // check if these can be zero
    if (pRdsData->proxDistance != 0) {
        if ((SIZE_MAX - 4) < sizeoftlv) {
            sizeoftlv = 0;
            goto exit;
        }
        sizeoftlv += 4;
    }

    if (pRdsData->AoA != 0) {
        if ((SIZE_MAX - 4) < sizeoftlv) {
            sizeoftlv = 0;
            goto exit;
        }
        sizeoftlv += 4;
    }
exit:
    return sizeoftlv;
}

smStatus_t SUS_API_WrapData(pSe05xSession_t session_ctx, se_plainRDS *pRdsData, uint8_t *pOutData, size_t *pOutDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    uint8_t *pCmdbuf     = NULL;
    uint8_t *ptCmd       = NULL;
    size_t cmdbufLen     = 0;
    size_t payloadLen;
    int tlvRet = 0;
    uint8_t respBuf[SUS_MAX_WRAPPED_RDS_RSP_SIZE];
    U32 u32RXLen = (U32)SUS_MAX_WRAPPED_RDS_RSP_SIZE;
    /* payloadLen < 0xFF so lc and Le as below*/
    size_t lcLen = 1;
    size_t leLen = 0;
    U16 rv       = SM_NOT_OK;

    ENSURE_OR_GO_CLEANUP(session_ctx);
    ENSURE_OR_GO_CLEANUP(session_ctx->conn_ctx);
    ENSURE_OR_GO_CLEANUP(pRdsData);
    ENSURE_OR_GO_CLEANUP(pOutData);
    ENSURE_OR_GO_CLEANUP(pOutDataLen);

    payloadLen = getRdsTlvLen(pRdsData);
    if (payloadLen > SUS_CLIENT_MAX_RDS_PAYLOADLEN) {
        LOG_E(
            "Plain RDS Payload TLV is greater than maximum JCOP response buffer, it will return failure from "
            "JCOP/Applet");
        LOG_E("Max Plain RDS Payload TLV size: %d bytes", SUS_CLIENT_MAX_RDS_PAYLOADLEN);
        goto cleanup;
    }

    pCmdbuf = SUS_MemMalloc(4 + lcLen + payloadLen + leLen); // Header + LC Length + payload  + le length
    ENSURE_OR_GO_CLEANUP(pCmdbuf);
    ptCmd = pCmdbuf;

    *pCmdbuf++ = CLA_GP_7816 | session_ctx->logical_channel;
    *pCmdbuf++ = SUS_INS_WRAP_DATA;
    *pCmdbuf++ = 0x00;
    *pCmdbuf++ = 0x00;

    cmdbufLen = 4; //header

    *pCmdbuf++ = (uint8_t)payloadLen;
    cmdbufLen += 1; // LC 1 byte

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= pRdsData->rangingSessionKeyLen);
    ENSURE_OR_GO_CLEANUP((cmdbufLen + pRdsData->rangingSessionKeyLen) <= payloadLen);
    tlvRet = TLVSET_u8bufOptional("rangingSessionKey",
        &pCmdbuf,
        &cmdbufLen,
        kSE05x_SUS_TAG_RANGING_SESSION_KEY,
        pRdsData->pRangingSessionKey,
        pRdsData->rangingSessionKeyLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= pRdsData->rspndrRangingKeyLen);
    ENSURE_OR_GO_CLEANUP((cmdbufLen + pRdsData->rspndrRangingKeyLen) <= payloadLen);
    tlvRet = TLVSET_u8bufOptional("responder_ranging_key",
        &pCmdbuf,
        &cmdbufLen,
        kSE05x_SUS_TAG_RESPONDER_RANGING_KEY,
        pRdsData->pRspndrRangingKey,
        pRdsData->rspndrRangingKeyLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= pRdsData->proxDistance);
    ENSURE_OR_GO_CLEANUP((cmdbufLen + pRdsData->proxDistance) <= payloadLen);
    tlvRet = TLVSET_U16Optional(
        "Proximity_Distance", &pCmdbuf, &cmdbufLen, kSE05x_SUS_TAG_PROXIMITY_DISTANCE, pRdsData->proxDistance);
    if (0 != tlvRet) {
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP(pRdsData->AoA >= 0);
    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= (size_t)pRdsData->AoA);
    ENSURE_OR_GO_CLEANUP((cmdbufLen + pRdsData->AoA) <= payloadLen);
    tlvRet = TLVSET_U16Optional(
        "angle_of_arrival", &pCmdbuf, &cmdbufLen, kSE05x_SUS_TAG_ANGLE_OF_ARRIVAL, (uint16_t)pRdsData->AoA);
    if (0 != tlvRet) {
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= pRdsData->clientDataLen);
    ENSURE_OR_GO_CLEANUP((cmdbufLen + pRdsData->clientDataLen) <= payloadLen);
    tlvRet = TLVSET_u8bufOptional("client_data",
        &pCmdbuf,
        &cmdbufLen,
        kSE05x_SUS_TAG_CLIENT_DATA,
        pRdsData->pClientData,
        pRdsData->clientDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= pRdsData->transactionIdLen);
    ENSURE_OR_GO_CLEANUP((cmdbufLen + pRdsData->transactionIdLen) <= payloadLen);
    tlvRet = TLVSET_u8bufOptional("transaction_identifier",
        &pCmdbuf,
        &cmdbufLen,
        kSE05x_SUS_TAG_TRANSACTION_IDENTIFIER,
        pRdsData->pTransactionId,
        pRdsData->transactionIdLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= pRdsData->KeyIdLen);
    ENSURE_OR_GO_CLEANUP((cmdbufLen + pRdsData->KeyIdLen) <= payloadLen);
    tlvRet = TLVSET_u8bufOptional(
        "key_identifier", &pCmdbuf, &cmdbufLen, kSE05x_SUS_TAG_KEY_IDENTIFIER, pRdsData->pKeyId, pRdsData->KeyIdLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= pRdsData->arbtDataLen);
    ENSURE_OR_GO_CLEANUP((cmdbufLen + pRdsData->arbtDataLen) <= payloadLen);
    tlvRet = TLVSET_u8bufOptional("aribtary_data",
        &pCmdbuf,
        &cmdbufLen,
        kSE05x_SUS_TAG_ARIBTARY_DATA,
        pRdsData->pArbtData,
        pRdsData->arbtDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= pRdsData->appletAidLen);
    ENSURE_OR_GO_CLEANUP((cmdbufLen + pRdsData->appletAidLen) <= payloadLen);
    tlvRet = TLVSET_u8bufOptional("finalization_applet_aid",
        &pCmdbuf,
        &cmdbufLen,
        kSE05x_SUS_TAG_FINALIZATION_APPLET_AID,
        pRdsData->pAppletAid,
        pRdsData->appletAidLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= pRdsData->sessionIdLen);
    ENSURE_OR_GO_CLEANUP((cmdbufLen + pRdsData->sessionIdLen) <= payloadLen);
    tlvRet = TLVSET_u8bufOptional(
        "session_id", &pCmdbuf, &cmdbufLen, kSE05x_SUS_TAG_SESSION_ID, pRdsData->pSessionId, pRdsData->sessionIdLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP(cmdbufLen <= UINT16_MAX);
    retStatus = (smStatus_t)smCom_TransceiveRaw(session_ctx->conn_ctx, ptCmd, (uint16_t)cmdbufLen, respBuf, &u32RXLen);
    if ((retStatus == SM_OK) && (u32RXLen >= 2)) {
        rv = (respBuf[u32RXLen - 2] << 8) | (respBuf[u32RXLen - 1]);
        if (rv == SM_OK) {
            if (*pOutDataLen >= u32RXLen - 2) {
                *pOutDataLen = u32RXLen - 2;
                if (*pOutDataLen <= SUS_MAX_WRAPPED_RDS_RSP_SIZE) {
                    memcpy(pOutData, respBuf, *pOutDataLen);
                }
                else {
                    retStatus = SM_NOT_OK;
                    LOG_E("Out put buffer size is not sufficient");
                }
            }
            else {
                retStatus    = SM_NOT_OK;
                *pOutDataLen = u32RXLen - 2;
                LOG_E("Out put buffer size is not sufficient");
            }
        }
        else {
            retStatus = SM_NOT_OK;
            LOG_E("Command Failed !!!");
        }
    }
cleanup:
    if (ptCmd != NULL)
        SUS_MemFree(ptCmd);
    return retStatus;
}

static smStatus_t select_applet(
    pSe05xSession_t session_ctx, uint8_t *appletName, uint16_t appletNameLen, uint16_t *pAppletVersion)
{
    smStatus_t rv                        = SM_NOT_OK;
    uint8_t cmdBuf[SUS_MAX_BUF_SIZE_CMD] = {0};
    uint8_t rspBuf[50]                   = {0};
    U32 respLen                          = sizeof(rspBuf);
    uint16_t tx_len;
    U16 ret = SM_NOT_OK;

    ENSURE_OR_GO_CLEANUP(session_ctx);
    ENSURE_OR_GO_CLEANUP(session_ctx->conn_ctx);
    ENSURE_OR_GO_CLEANUP(appletName);
    /* cla+ins+p1+p2+lc+appletNameLen+le */
    ENSURE_OR_GO_CLEANUP(SUS_MAX_BUF_SIZE_CMD > (6 + appletNameLen));

    cmdBuf[0] = CLA_ISO7816 | session_ctx->logical_channel;
    cmdBuf[1] = INS_GP_SELECT;
    cmdBuf[2] = 4;
    cmdBuf[3] = 0;

    tx_len = 0   /* for indentation */
             + 1 /* CLA */
             + 1 /* INS */
             + 1 /* P1 */
             + 1 /* P2 */;
    if (appletNameLen > 0) {
        cmdBuf[4] = (uint8_t)appletNameLen; // We have done ENSURE_OR_GO_CLEANUP(appletNameLen < 255);
        tx_len    = tx_len + 1              /* Lc */
                 + appletNameLen            /* Payload */
                 + 1 /* Le */;
        memcpy(&cmdBuf[5], appletName, appletNameLen);
    }
    else {
        tx_len = tx_len /* for indentation */
                 + 0    /* No Lc */
                 + 1 /* Le */;
    }
    cmdBuf[tx_len - 1] = 0; /* Le */

    rv = (smStatus_t)smCom_TransceiveRaw(session_ctx->conn_ctx, cmdBuf, tx_len, rspBuf, &respLen);

    if (rv != SM_OK) {
        LOG_E("Error in smCom_TransceiveRaw !!!");
        goto cleanup;
    }
    else {
        rv = SM_NOT_OK;
        if (respLen >= 2) {
            ret = (rspBuf[respLen - 2] << 8) | (rspBuf[respLen - 1]);
            if (ret != SM_OK) {
                LOG_MAU8_W("Select Command Response", rspBuf, respLen);
                goto cleanup;
            }
            else {
                rv = SM_OK;
                if (respLen > 2) {
                    U32 i = 0;
                    LOG_MAU8_I("Select Command Response", rspBuf, respLen - 2);
                    for (i = 0; i < respLen; i++) {
                        if ((rspBuf[i] == 0x9F) && (rspBuf[i + 1] == 0x7E)) {
                            if (respLen >= (i + 4)) {
                                *pAppletVersion = rspBuf[i + 3] << 8;
                                *pAppletVersion |= rspBuf[i + 4];
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
cleanup:
    return rv;
}

static void *SUS_MemMalloc(size_t size)
{
#if defined(USE_RTOS) && USE_RTOS == 1
    return pvPortMalloc(size);
#else
    return malloc(size);
#endif
}

static void SUS_MemFree(void *buf)
{
    ENSURE_OR_GO_EXIT(buf != NULL);
#if defined(USE_RTOS) && USE_RTOS == 1
    vPortFree(buf);
#else
    free(buf);
#endif
exit:
    return;
}
