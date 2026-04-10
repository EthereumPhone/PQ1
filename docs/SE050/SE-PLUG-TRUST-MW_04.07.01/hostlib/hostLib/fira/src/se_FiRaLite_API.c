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

#ifndef SE_FIRALITE_API_H
#define SE_FIRALITE_API_H

#include "nxScp03_Const.h"
#include "smCom.h"
#include <se05x_tlv.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <se05x_const.h>
#include <se05x_enums.h>
#include <nxEnsure.h>
#include <string.h>
#include "nxLog_hostLib.h"
#include "se_FiRaLite_API.h"

#if defined(USE_RTOS) && USE_RTOS == 1
#include "FreeRTOSConfig.h"
#include "FreeRTOS.h"
#endif

#if (SSS_HAVE_APPLET_SE051_UWB)
/* OK */
#else
#error "Only with SE051W based build"
#endif //SSS_HAVE_APPLET_SE051_UWB

#ifndef NEWLINE
#define NEWLINE must be already defined
#endif

#define SE_FIRALITE_INS_SELECT_ADF (0xA5)
#define SE_FIRALITE_INS_INITIATE_TRANSACTION (0x12)
#define SE_FIRALITE_INS_DISPATCH (0xC2)
#define SE_FIRALITE_INS_TUNNEL (0x14)
#define SE_FIRALITE_INS_GETDATA_APPLET_LOCAL (0xCA)
#define SE_FIRALITE_INS_GETDATA_ADF_REMOTE (0xCB)
#define SE_FIRALITE_INS_PUTDATA (0xDB)
#define SE_FIRALITE_P1_GETPUT (0x3F)
#define SE_FIRALITE_P2_GETPUT (0xFF)

/* clang-format off */
#define FIRALITE_APPLET_AID_FIRA_NON_COMPLIANT { \
        0xA0, 0x00, 0x00, 0x03, 0x96, \
        0x54, 0x53, 0x00, 0x00, 0x00, \
        0x01, 0x04, 0x50, 0x00, 0x00, \
        0x00,}

#define FIRALITE_APPLET_AID_FIRA_COMPLIANT { \
        0xA0, 0x00, 0x00, 0x08, 0x67, 0x45, 0x41, 0x50, 0x00 \
    }

#define FIRALITE_APPLET_AID_FIRA_CSML_COMPLIANT { \
        0xA0, 0x00, 0x00, 0x08, 0x67, 0x46, 0x41, 0x50, 0x00 \
    }
/* clang-format on */

#define SIZEOFTLV(cmdLen) (cmdLen == 0 ? 0 : ((1 + (cmdLen <= 0x7f ? 1 : (cmdLen <= 0xFF ? 2 : 3)) + cmdLen)))

static smStatus_t select_applet(pSe05xSession_t session_ctx, uint8_t *appletName, uint16_t appletNameLen);
static smStatus_t se_FiRaLite_API_DispatchTunnel(const uint8_t ins,
    pSe05xSession_t session_ctx,
    uint8_t *pinBuf,
    const size_t inBufLen,
    uint8_t *pRspData,
    size_t *pRspDataLen);

static smStatus_t se_FiRaLite_API_GetPutData(
    const uint8_t ins, const uint8_t *pInBuf, const size_t inBufLen, uint8_t *pRspData, size_t *pRspDataLen);

smStatus_t se_FiRaLite_API_Select(pSe05xSession_t session_ctx, uint8_t logical_channel)
{
    smStatus_t respstat                     = SM_NOT_OK;
    uint8_t openLcCmd[]                     = {0x00, 0x70, 0x00, 0x00, logical_channel};
    U16 openLcCmdLen                        = sizeof(openLcCmd);
    uint8_t resp[FIRALITE_MAX_BUF_SIZE_RSP] = {0};
    U32 respLen                             = sizeof(resp);
    uint8_t aid_fira_csml_compliant[]       = FIRALITE_APPLET_AID_FIRA_CSML_COMPLIANT;
    uint8_t aid_fira_compliant[]            = FIRALITE_APPLET_AID_FIRA_COMPLIANT;
    uint8_t aid_non_fira_compliant[]        = FIRALITE_APPLET_AID_FIRA_NON_COMPLIANT;
    U16 aidLen                              = 0;
    U16 rv                                  = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(session_ctx);
    ENSURE_OR_GO_EXIT(session_ctx->conn_ctx);
    // open logical channel

    respstat = (smStatus_t)smCom_TransceiveRaw(session_ctx->conn_ctx, openLcCmd, openLcCmdLen, resp, &respLen);
    ENSURE_OR_GO_EXIT(respstat == SM_OK);

    session_ctx->logical_channel = logical_channel;

    respstat = SM_NOT_OK;
    rv       = (resp[respLen - 2] << 8) | (resp[respLen - 1]);
    ENSURE_OR_GO_EXIT(rv == SM_OK);

    aidLen   = sizeof(aid_fira_csml_compliant);
    respstat = select_applet(session_ctx, aid_fira_csml_compliant, aidLen);
    if (SM_OK == respstat) {
        LOG_W("Fira AID Consortium CSML Compliant FiraLite applet is selected");
        goto exit;
    }

    aidLen   = sizeof(aid_fira_compliant);
    respstat = select_applet(session_ctx, aid_fira_compliant, aidLen);
    if (SM_OK == respstat) {
        LOG_W("Fira AID non CSML Compliant FiraLite applet is selected");
        goto exit;
    }

    aidLen   = sizeof(aid_non_fira_compliant);
    respstat = select_applet(session_ctx, aid_non_fira_compliant, aidLen);
    if (SM_OK == respstat) {
        LOG_W("Fira Non Compliant AID FiraLite applet is selected");
        goto exit;
    }
    else {
        LOG_E("Fira Lite applet is not present");
    }

exit:
    return respstat;
}

smStatus_t se_FiRaLite_API_SelectADF(pSe05xSession_t session_ctx,
    const se_firalite_optsa_t optsA,
    se_firelite_oid_entry *oid_entries,
    const size_t oid_entries_count,
    uint8_t *pRspData,
    size_t *pRspDataLen)
{
    smStatus_t retStatus                       = SM_NOT_OK;
    uint8_t cmdBuf[FIRALITE_MAX_BUF_SIZE_CMD]  = {0};
    uint8_t respBuf[FIRALITE_MAX_BUF_SIZE_RSP] = {0};
    U32 u32RXLen                               = sizeof(respBuf);
    uint8_t *pCmdbuf;
    size_t cmdbufLen;
    int tlvRet;
    size_t payloadLen;
    se_firelite_oid_entry *pOIDEntry;
    size_t lcLen = 0;
    size_t leLen = 0;
    U16 rv       = SM_NOT_OK;

    ENSURE_OR_GO_CLEANUP(session_ctx);
    ENSURE_OR_GO_CLEANUP(session_ctx->conn_ctx);
    ENSURE_OR_GO_CLEANUP(oid_entries);
    ENSURE_OR_GO_CLEANUP(oid_entries_count != 0u);
    ENSURE_OR_GO_CLEANUP(pRspData);
    ENSURE_OR_GO_CLEANUP(pRspDataLen);

    /* optsA */
    payloadLen = SIZEOFTLV(1);

    pOIDEntry = oid_entries;
    for (size_t i = 0u; i < oid_entries_count; i++) {
        ENSURE_OR_GO_CLEANUP(pOIDEntry->OIDDataLen != 0u);
        ENSURE_OR_GO_CLEANUP((SIZE_MAX - payloadLen) >= SIZEOFTLV(pOIDEntry->OIDDataLen));
        payloadLen += SIZEOFTLV(pOIDEntry->OIDDataLen);
        pOIDEntry++;
    }

    lcLen = payloadLen < 0xFFu ? 1u : 3u;
    leLen = lcLen == 3u ? 2u : 1u;

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - payloadLen) >= (lcLen + leLen));
    if ((payloadLen + lcLen + leLen) > FIRALITE_MAX_BUF_SIZE_CMD) {
        LOG_E("Data is greater than max command buffer");
        LOG_E("Max command buffer TLV size: %d bytes", FIRALITE_MAX_BUF_SIZE_CMD);
        goto cleanup;
    }

    pCmdbuf    = &cmdBuf[0];
    *pCmdbuf++ = CLA_GP_7816 | session_ctx->logical_channel;
    *pCmdbuf++ = SE_FIRALITE_INS_SELECT_ADF;
    *pCmdbuf++ = 0x04;
    *pCmdbuf++ = 0x00;

    if (lcLen > 1) {
        *pCmdbuf++ = 0x00;
        *pCmdbuf++ = 0xFFu & (payloadLen >> 8);
        *pCmdbuf++ = 0xFFu & (payloadLen);
        cmdbufLen  = 7u;
    }
    else {
        *pCmdbuf++ = (uint8_t)payloadLen;
        cmdbufLen  = 5u;
    }

    tlvRet = TLVSET_U8("TAG1", &pCmdbuf, &cmdbufLen, kSE05x_FIRALITE_OPTSA_TAG, optsA);
    if (0 != tlvRet) {
        goto cleanup;
    }

    pOIDEntry = oid_entries;
    for (size_t i = 0u; i < oid_entries_count; i++) {
        tlvRet = TLVSET_u8buf(
            "OID", &pCmdbuf, &cmdbufLen, kSE05x_FIRALITE_OID_TAG, pOIDEntry->pOIDData, pOIDEntry->OIDDataLen);
        if (0 != tlvRet) {
            goto cleanup;
        }

        pOIDEntry++;
    }

    ENSURE_OR_GO_CLEANUP(cmdbufLen < FIRALITE_MAX_BUF_SIZE_CMD);
    pCmdbuf = &pCmdbuf[cmdbufLen];
    for (size_t i = 0u; i < leLen; i++) {
        *pCmdbuf++ = 0x00;
    }

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= leLen);
    cmdbufLen += leLen;

    ENSURE_OR_GO_CLEANUP(cmdbufLen <= UINT16_MAX);
    retStatus = (smStatus_t)smCom_TransceiveRaw(session_ctx->conn_ctx, cmdBuf, (uint16_t)cmdbufLen, respBuf, &u32RXLen);
    if (retStatus == SM_OK) {
        rv = (respBuf[u32RXLen - 2] << 8) | (respBuf[u32RXLen - 1]);
        if (rv == SM_OK) {
            if (*pRspDataLen >= u32RXLen - 2) {
                *pRspDataLen = u32RXLen - 2;
                memcpy(pRspData, respBuf, *pRspDataLen);
            }
            else {
                retStatus    = SM_NOT_OK;
                *pRspDataLen = u32RXLen - 2;
                LOG_E("Output buffer size is not sufficient");
            }
        }
        else {
            retStatus = SM_NOT_OK;
            LOG_E("Command Failed!!!");
        }
    }
cleanup:
    return retStatus;
}

smStatus_t se_FiRaLite_API_InitiateTransaction(pSe05xSession_t session_ctx,
    se_firelite_oid_entry *oid_entries,
    const size_t oid_entries_count,
    uint8_t *pSessionId,
    const size_t sessionIdLen,
    uint8_t *pRspData,
    size_t *pRspDataLen)
{
    return se_FiRaLite_API_InitiateTransaction_extended(
        session_ctx, oid_entries, oid_entries_count, pSessionId, sessionIdLen, pRspData, pRspDataLen, 0, NULL, 0);
}

smStatus_t se_FiRaLite_API_InitiateTransaction_extended(pSe05xSession_t session_ctx,
    se_firelite_oid_entry *oid_entries,
    const size_t oid_entries_count,
    uint8_t *pSessionId,
    const size_t sessionIdLen,
    uint8_t *pRspData,
    size_t *pRspDataLen,
    uint8_t P1_value,
    uint8_t *pChallenge1,
    const size_t challenge1Len)
{
    smStatus_t retStatus                       = SM_NOT_OK;
    uint8_t cmdBuf[FIRALITE_MAX_BUF_SIZE_CMD]  = {0};
    uint8_t respBuf[FIRALITE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pCmdbuf;
    size_t cmdbufLen = 0;
    U32 u32RXLen     = sizeof(respBuf);
    int tlvRet;
    size_t payloadLen;
    se_firelite_oid_entry *pOIDEntry;
    size_t lcLen = 0;
    size_t leLen = 0;
    U16 rv       = SM_NOT_OK;

    ENSURE_OR_GO_CLEANUP(session_ctx);
    ENSURE_OR_GO_CLEANUP(session_ctx->conn_ctx);
    ENSURE_OR_GO_CLEANUP(oid_entries);
    ENSURE_OR_GO_CLEANUP(oid_entries_count != 0u);
    ENSURE_OR_GO_CLEANUP(pRspData);
    ENSURE_OR_GO_CLEANUP(pRspDataLen);

    payloadLen = 0u;
    if (NULL != pSessionId) {
        ENSURE_OR_GO_CLEANUP(sessionIdLen == 4u);
        payloadLen += SIZEOFTLV(sessionIdLen);
    }

    pOIDEntry = oid_entries;
    for (size_t i = 0u; i < oid_entries_count; i++) {
        ENSURE_OR_GO_CLEANUP(pOIDEntry);
        ENSURE_OR_GO_CLEANUP(pOIDEntry->pOIDData);
        ENSURE_OR_GO_CLEANUP(pOIDEntry->OIDDataLen != 0u);
        ENSURE_OR_GO_CLEANUP((SIZE_MAX - payloadLen) >= SIZEOFTLV(pOIDEntry->OIDDataLen));
        payloadLen += SIZEOFTLV(pOIDEntry->OIDDataLen);
        pOIDEntry++;
    }

    if (NULL != pChallenge1) {
        ENSURE_OR_GO_CLEANUP(challenge1Len == 16u);
        ENSURE_OR_GO_CLEANUP((SIZE_MAX - payloadLen) >= SIZEOFTLV(challenge1Len));
        payloadLen += SIZEOFTLV(challenge1Len);
    }

    lcLen = payloadLen < 0xFFu ? 1u : 3u;
    leLen = lcLen == 3u ? 2u : 1u;

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - payloadLen) >= (lcLen + leLen));
    if ((payloadLen + lcLen + leLen) > FIRALITE_MAX_BUF_SIZE_CMD) {
        LOG_E("Data is greater than max command buffer");
        LOG_E("Max command buffer TLV size: %d bytes", FIRALITE_MAX_BUF_SIZE_CMD);
        goto cleanup;
    }

    pCmdbuf    = &cmdBuf[0];
    *pCmdbuf++ = CLA_GP_7816 | session_ctx->logical_channel;
    *pCmdbuf++ = SE_FIRALITE_INS_INITIATE_TRANSACTION;
    *pCmdbuf++ = P1_value;
    *pCmdbuf++ = 0x00;

    if (lcLen > 1) {
        *pCmdbuf++ = 0x00;
        *pCmdbuf++ = 0xFFu & (payloadLen >> 8);
        *pCmdbuf++ = 0xFFu & (payloadLen);
        cmdbufLen  = 7u;
    }
    else {
        *pCmdbuf++ = (uint8_t)payloadLen;
        cmdbufLen  = 5u;
    }

    if (NULL != pSessionId) {
        tlvRet =
            TLVSET_u8buf("SessionId", &pCmdbuf, &cmdbufLen, kSE05x_FIRALITE_SESSION_ID_TAG, pSessionId, sessionIdLen);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }

    pOIDEntry = oid_entries;
    for (size_t i = 0u; i < oid_entries_count; i++) {
        tlvRet = TLVSET_u8buf(
            "OID", &pCmdbuf, &cmdbufLen, kSE05x_FIRALITE_OID_TAG, pOIDEntry->pOIDData, pOIDEntry->OIDDataLen);
        if (0 != tlvRet) {
            goto cleanup;
        }

        pOIDEntry++;
    }

    if (NULL != pChallenge1) {
        tlvRet = TLVSET_u8buf(
            "Challenge1", &pCmdbuf, &cmdbufLen, kSE05x_FIRALITE_TAG_CHALLENGE1, pChallenge1, challenge1Len);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }

    ENSURE_OR_GO_CLEANUP(cmdbufLen < FIRALITE_MAX_BUF_SIZE_CMD);
    pCmdbuf = &pCmdbuf[cmdbufLen];
    for (size_t i = 0u; i < leLen; i++) {
        *pCmdbuf++ = 0x00;
    }

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= leLen);
    cmdbufLen += leLen;

    ENSURE_OR_GO_CLEANUP(cmdbufLen <= UINT16_MAX);
    retStatus = (smStatus_t)smCom_TransceiveRaw(session_ctx->conn_ctx, cmdBuf, (uint16_t)cmdbufLen, respBuf, &u32RXLen);
    if (retStatus == SM_OK) {
        rv = (respBuf[u32RXLen - 2] << 8) | (respBuf[u32RXLen - 1]);
        if (rv == SM_OK) {
            if (*pRspDataLen >= u32RXLen - 2) {
                *pRspDataLen = u32RXLen - 2;
                memcpy(pRspData, respBuf, *pRspDataLen);
            }
            else {
                retStatus    = SM_NOT_OK;
                *pRspDataLen = u32RXLen - 2;
                LOG_E("Output buffer size is not sufficient");
            }
        }
        else {
            retStatus = SM_NOT_OK;
            LOG_E("Command Failed!!!");
        }
    }

cleanup:
    return retStatus;
}

static smStatus_t se_FiRaLite_API_DispatchTunnel(const uint8_t ins,
    pSe05xSession_t session_ctx,
    uint8_t *pinBuf,
    const size_t inBufLen,
    uint8_t *pRspData,
    size_t *pRspDataLen)
{
    smStatus_t retStatus                       = SM_NOT_OK;
    uint8_t cmdBuf[FIRALITE_MAX_BUF_SIZE_CMD]  = {0};
    uint8_t respBuf[FIRALITE_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pCmdbuf;
    size_t cmdbufLen = 0;
    U32 u32RXLen     = sizeof(respBuf);
    int tlvRet;
    size_t payloadLen  = 0;
    size_t lcLen       = 0;
    size_t leLen       = 0;
    size_t innerTagLen = 0;
    U16 rv             = SM_NOT_OK;

    ENSURE_OR_GO_CLEANUP(session_ctx);
    ENSURE_OR_GO_CLEANUP(session_ctx->conn_ctx);
    ENSURE_OR_GO_CLEANUP(pinBuf);
    ENSURE_OR_GO_CLEANUP(inBufLen);
    ENSURE_OR_GO_CLEANUP(pRspData);
    ENSURE_OR_GO_CLEANUP(pRspDataLen);

    innerTagLen = SIZEOFTLV(inBufLen);
    payloadLen  = innerTagLen;
    payloadLen  = SIZEOFTLV(payloadLen); // nested tag

    lcLen = payloadLen < 0xFFu ? 1u : 3u;
    leLen = lcLen == 3u ? 2u : 1u;

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - payloadLen) >= (lcLen + leLen));
    if ((payloadLen + lcLen + leLen) > FIRALITE_MAX_BUF_SIZE_CMD) {
        LOG_E("Data is greater than max command buffer");
        LOG_E("Max command buffer TLV size: %d bytes", FIRALITE_MAX_BUF_SIZE_CMD);
        goto cleanup;
    }

    pCmdbuf    = &cmdBuf[0];
    *pCmdbuf++ = CLA_GP_7816 | session_ctx->logical_channel;
    *pCmdbuf++ = ins;
    *pCmdbuf++ = 0x00;
    *pCmdbuf++ = 0x00;

    if (lcLen > 1) {
        *pCmdbuf++ = 0x00;
        *pCmdbuf++ = 0xFFu & (payloadLen >> 8);
        *pCmdbuf++ = 0xFFu & (payloadLen);
        cmdbufLen  = 7u;
    }
    else {
        *pCmdbuf++ = (uint8_t)payloadLen;
        cmdbufLen  = 5u;
    }

    /* outer tag */
    *pCmdbuf++ = kSE05x_FIRALITE_PROPRIETARY_CMD_TAG;
    cmdbufLen++;

    if (innerTagLen <= 0x7Fu) {
        *pCmdbuf++ = (uint8_t)innerTagLen;
        cmdbufLen++;
    }
    else if (innerTagLen <= 0xFFu) {
        *pCmdbuf++ = (uint8_t)(0x80 /* Extended */ | 0x01 /* Additional Length */);
        *pCmdbuf++ = (uint8_t)((innerTagLen >> 0 * 8) & 0xFF);
        cmdbufLen += 2u;
    }
    else if (innerTagLen <= 0xFFFFu) {
        *pCmdbuf++ = (uint8_t)(0x80 /* Extended */ | 0x02 /* Additional Length */);
        *pCmdbuf++ = (uint8_t)((innerTagLen >> 1 * 8) & 0xFF);
        *pCmdbuf++ = (uint8_t)((innerTagLen >> 0 * 8) & 0xFF);
        cmdbufLen += 3u;
    }
    else {
        goto cleanup;
    }

    pCmdbuf = &cmdBuf[cmdbufLen];

    tlvRet = TLVSET_u8buf("C-R APDU", &pCmdbuf, &cmdbufLen, kSE05x_FIRALITE_DISPATCH_TAG, pinBuf, inBufLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    ENSURE_OR_GO_CLEANUP(cmdbufLen < FIRALITE_MAX_BUF_SIZE_CMD);
    pCmdbuf = &pCmdbuf[cmdbufLen];
    for (size_t i = 0u; i < leLen; i++) {
        *pCmdbuf++ = 0x00;
    }

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= leLen);
    cmdbufLen += leLen;

    ENSURE_OR_GO_CLEANUP(cmdbufLen <= UINT16_MAX);
    retStatus = (smStatus_t)smCom_TransceiveRaw(session_ctx->conn_ctx, cmdBuf, (uint16_t)cmdbufLen, respBuf, &u32RXLen);
    if (retStatus == SM_OK) {
        rv = (respBuf[u32RXLen - 2] << 8) | (respBuf[u32RXLen - 1]);
        if (rv == SM_OK) {
            if (*pRspDataLen >= u32RXLen - 2) {
                *pRspDataLen = u32RXLen - 2;
                memcpy(pRspData, respBuf, *pRspDataLen);
            }
            else {
                retStatus    = SM_NOT_OK;
                *pRspDataLen = u32RXLen - 2;
                LOG_E("Out put buffer size is not sufficient");
            }
        }
        else {
            retStatus = SM_NOT_OK;
            LOG_E("Command Failed!!!");
        }
    }

cleanup:
    return retStatus;
}

smStatus_t se_FiRaLite_API_Dispatch(
    pSe05xSession_t session_ctx, uint8_t *pinBuf, const size_t inBufLen, uint8_t *pRspData, size_t *pRspDataLen)
{
    return se_FiRaLite_API_DispatchTunnel(
        SE_FIRALITE_INS_DISPATCH, session_ctx, pinBuf, inBufLen, pRspData, pRspDataLen);
}

smStatus_t se_FiRaLite_API_Tunnel(
    pSe05xSession_t session_ctx, uint8_t *pinBuf, const size_t inBufLen, uint8_t *pRspData, size_t *pRspDataLen)
{
    return se_FiRaLite_API_DispatchTunnel(SE_FIRALITE_INS_TUNNEL, session_ctx, pinBuf, inBufLen, pRspData, pRspDataLen);
}

smStatus_t se_FiRaLite_API_RemoteGetData(
    const uint8_t *pInBuf, const size_t inBufLen, uint8_t *pRspData, size_t *pRspDataLen)
{
    return se_FiRaLite_API_GetPutData(SE_FIRALITE_INS_GETDATA_ADF_REMOTE, pInBuf, inBufLen, pRspData, pRspDataLen);
}

smStatus_t se_FiRaLite_API_RemotePutData(
    const uint8_t *pInBuf, const size_t inBufLen, uint8_t *pRspData, size_t *pRspDataLen)
{
    return se_FiRaLite_API_GetPutData(SE_FIRALITE_INS_PUTDATA, pInBuf, inBufLen, pRspData, pRspDataLen);
}

smStatus_t se_FiRaLite_API_LocalGetData(
    pSe05xSession_t session_ctx, uint8_t tagMSB, uint8_t tagLSB, uint8_t *pRspData, size_t *pRspDataLen)
{
    smStatus_t retStatus                       = SM_NOT_OK;
    uint8_t cmdBuf[FIRALITE_MAX_BUF_SIZE_CMD]  = {0};
    uint8_t respBuf[FIRALITE_MAX_BUF_SIZE_RSP] = {0};
    size_t cmdbufLen                           = sizeof(cmdBuf);
    size_t respLen                             = sizeof(respBuf);
    U16 rv                                     = SM_NOT_OK;
    uint8_t i                                  = 0;

    ENSURE_OR_GO_CLEANUP(session_ctx);
    ENSURE_OR_GO_CLEANUP(session_ctx->conn_ctx);
    ENSURE_OR_GO_CLEANUP(pRspData);
    ENSURE_OR_GO_CLEANUP(pRspDataLen);

    cmdBuf[i++] = CLA_GP_7816 | session_ctx->logical_channel;
    cmdBuf[i++] = (uint8_t)SE_FIRALITE_INS_GETDATA_APPLET_LOCAL;
    cmdBuf[i++] = tagMSB;
    cmdBuf[i++] = tagLSB;
    cmdbufLen   = i;
    retStatus =
        (smStatus_t)smCom_TransceiveRaw(session_ctx->conn_ctx, cmdBuf, (uint16_t)cmdbufLen, respBuf, (U32 *)&respLen);
    if (retStatus == SM_OK) {
        rv = (respBuf[respLen - 2] << 8) | (respBuf[respLen - 1]);
        if (rv == SM_OK) {
            if (*pRspDataLen >= respLen - 2) {
                *pRspDataLen = respLen - 2;
                memcpy(pRspData, respBuf, *pRspDataLen);
            }
            else {
                retStatus    = SM_NOT_OK;
                *pRspDataLen = respLen - 2;
                LOG_E("Out put buffer size is not sufficient");
            }
        }
        else {
            retStatus = SM_NOT_OK;
            LOG_E("Command Failed!!!");
        }
    }

cleanup:
    return retStatus;
}

smStatus_t se_FiRaLite_API_LocalPutData(pSe05xSession_t session_ctx, const uint8_t *pInBuf, const size_t inBufLen)
{
    smStatus_t retStatus                       = SM_NOT_OK;
    smStatus_t smStatus                        = SM_NOT_OK;
    uint8_t cmdBuf[FIRALITE_MAX_BUF_SIZE_CMD]  = {0};
    uint8_t respBuf[FIRALITE_MAX_BUF_SIZE_RSP] = {0};
    size_t cmdbufLen                           = sizeof(cmdBuf);
    size_t respLen                             = sizeof(respBuf);
    U16 rv                                     = SM_NOT_OK;

    ENSURE_OR_GO_CLEANUP(session_ctx);
    ENSURE_OR_GO_CLEANUP(session_ctx->conn_ctx);

    smStatus = se_FiRaLite_API_GetPutData(SE_FIRALITE_INS_PUTDATA, pInBuf, inBufLen, cmdBuf, &cmdbufLen);
    if (smStatus != SM_OK) {
        goto cleanup;
    }

    cmdBuf[0] = CLA_GP_7816 | session_ctx->logical_channel;

    ENSURE_OR_GO_CLEANUP(cmdbufLen <= UINT16_MAX);
    retStatus =
        (smStatus_t)smCom_TransceiveRaw(session_ctx->conn_ctx, cmdBuf, (uint16_t)cmdbufLen, respBuf, (U32 *)&respLen);
    if (retStatus == SM_OK) {
        rv = (smStatus_t)(respBuf[respLen - 2] << 8) | (respBuf[respLen - 1]);
        if (rv == SM_OK) {
            if (0u != respLen - 2u) {
                retStatus = SM_NOT_OK;
                LOG_E("Unexpected response data");
            }
        }
        else {
            retStatus = SM_NOT_OK;
            LOG_E("Command Failed!!!");
        }
    }

cleanup:
    return retStatus;
}

static smStatus_t se_FiRaLite_API_GetPutData(
    const uint8_t ins, const uint8_t *pInBuf, const size_t inBufLen, uint8_t *pRspData, size_t *pRspDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    size_t cmdbufLen;
    uint8_t *pCmdbuf;
    size_t payloadLen;
    size_t leLen = 0;
    size_t lcLen = 0;

    ENSURE_OR_GO_CLEANUP(pInBuf);
    ENSURE_OR_GO_CLEANUP(inBufLen != 0u);
    ENSURE_OR_GO_CLEANUP(pRspData);
    ENSURE_OR_GO_CLEANUP(pRspDataLen);

    payloadLen = inBufLen;

    lcLen = payloadLen < 0xFFu ? 1u : 3u;
    leLen = lcLen == 3u ? 2u : 1u;

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - payloadLen) >= (4 + lcLen + leLen));
    ENSURE_OR_GO_CLEANUP(*pRspDataLen >= 4u + lcLen + payloadLen + leLen);

    pCmdbuf    = pRspData;
    *pCmdbuf++ = 0x00U;
    *pCmdbuf++ = ins;
    *pCmdbuf++ = SE_FIRALITE_P1_GETPUT;
    *pCmdbuf++ = SE_FIRALITE_P2_GETPUT;

    if (lcLen > 1) {
        *pCmdbuf++ = 0x00;
        *pCmdbuf++ = 0xFFu & (payloadLen >> 8);
        *pCmdbuf++ = 0xFFu & (payloadLen);
        cmdbufLen  = 7u;
    }
    else {
        *pCmdbuf++ = (uint8_t)payloadLen;
        cmdbufLen  = 5u;
    }

    memcpy(pCmdbuf, pInBuf, inBufLen);
    ENSURE_OR_GO_CLEANUP((SIZE_MAX - inBufLen) >= cmdbufLen);
    cmdbufLen += inBufLen;
    ENSURE_OR_GO_CLEANUP(cmdbufLen < (*pRspDataLen));
    pCmdbuf = &pCmdbuf[cmdbufLen];

    for (size_t i = 0u; i < leLen; i++) {
        *pCmdbuf++ = 0x00;
    }

    ENSURE_OR_GO_CLEANUP((SIZE_MAX - cmdbufLen) >= leLen);
    cmdbufLen += leLen;
    *pRspDataLen = cmdbufLen;

    retStatus = SM_OK;

cleanup:
    return retStatus;
}

static smStatus_t select_applet(pSe05xSession_t session_ctx, uint8_t *appletName, uint16_t appletNameLen)
{
    smStatus_t rv                                = SM_NOT_OK;
    uint8_t cmdBuf[FIRALITE_SELECT_BUF_SIZE_CMD] = {0};
    uint8_t rspBuf[FIRALITE_SELECT_BUF_SIZE_RSP] = {0};
    U32 respLen                                  = sizeof(rspBuf);
    uint16_t tx_len;
    U16 ret = SM_NOT_OK;

    ENSURE_OR_GO_CLEANUP(session_ctx);
    ENSURE_OR_GO_CLEANUP(session_ctx->conn_ctx);
    ENSURE_OR_GO_CLEANUP(appletName);
    /* cla+ins+p1+p2+lc+appletNameLen+le */
    ENSURE_OR_GO_CLEANUP(FIRALITE_MAX_BUF_SIZE_RSP > (6 + appletNameLen));

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
        if (respLen >= 2) {
            rv  = SM_NOT_OK;
            ret = (rspBuf[respLen - 2] << 8) | (rspBuf[respLen - 1]);
            if (ret != SM_OK) {
                LOG_MAU8_W("Select Command Response", rspBuf, respLen);
                goto cleanup;
            }
            else {
                rv = SM_OK;
                if (respLen > 2) {
                    LOG_MAU8_I("Select Command Response", rspBuf, respLen - 2);
                }
            }
        }
    }

cleanup:
    return rv;
}

#endif /* #ifndef SE_FIRALITE_API_H */
