/*
 *
 * Copyright 2018,2020,2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */
#if (__ARM_FEATURE_CMSE & 1) == 0
#error "Need ARMv8-M security extensions"
#elif (__ARM_FEATURE_CMSE & 2) == 0
#error "Compile with --cmse"
#endif

#include "stdint.h"
#include "arm_cmse.h"
#include "veneer_table.h"
#include "fsl_debug_console.h"
#include "smCom.h"
#include "nxEnsure.h"
#include "fsl_sss_se05x_types.h"
#include "nxScp03_Apis.h"
#include "veneer_smcom_table.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define MAX_STRING_LENGTH 0x400
extern sss_session_t *pBaseSession;

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
/* strnlen function implementation for arm compiler */
#if defined(__arm__)
size_t strnlen(const char *s, size_t maxLength)
{
    size_t length = 0;
    while ((length <= maxLength) && (*s)) {
        s++;
        length++;
    }
    return length;
}
#endif

__attribute__((cmse_nonsecure_entry)) void DbgConsole_Printf_NSE(char const *s)
{
    size_t string_length;
    /* Access to non-secure memory from secure world has to be properly validated */
    /* Check whether string is properly terminated */
    string_length = strnlen(s, MAX_STRING_LENGTH);
    if ((string_length == MAX_STRING_LENGTH) && (s[string_length] != '\0')) {
        PRINTF("String too long or invalid string termination!\r\n");
        abort();
    }

    /* Check whether string is located in non-secure memory */
    if (cmse_check_address_range((void *)s, string_length, CMSE_NONSECURE | CMSE_MPU_READ) == NULL) {
        PRINTF("String is not located in normal world!\r\n");
        abort();
    }

    PRINTF(s);
}

/* Non-secure callable (entry) function */
__attribute__((cmse_nonsecure_entry)) smStatus_t encrypt_plainFrame_NSE(
    const tlvHeader_t *hdr, const size_t cmdApduBufLen, nseTxFrame_t *ptxframe)
{
    smStatus_t apduStatus   = SM_NOT_OK;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint8_t macToAdd[16];
    size_t macLen  = 16;
    int i          = 0;
    uint8_t hasle  = 0;
    uint8_t *txBuf = NULL;
    // PRINTF("\r\n Inside transform_scp_NSE in Secure World \r\n");
    Se05xApdu_t se05xApdu = {0};

    if (cmse_check_address_range((void *)hdr, sizeof(tlvHeader_t), CMSE_NONSECURE | CMSE_MPU_READ) == NULL) {
        PRINTF("TLV Header is not located in normal world!\r\n");
        abort();
    }
    if (cmse_check_address_range((void *)ptxframe, sizeof(nseTxFrame_t), CMSE_NONSECURE | CMSE_MPU_READ) == NULL) {
        PRINTF("Tx Frame is not located in normal world!\r\n");
        abort();
    }

    hasle  = ptxframe->hasle;
    txBuf = ptxframe->txBuf;

    se05xApdu.se05xTxBuf    = ptxframe->txBuf;
    se05xApdu.se05xTxBufLen = ptxframe->txBufLen;
    se05xApdu.se05xCmd_hdr  = hdr;
    se05xApdu.se05xCmd      = ptxframe->cmdApduBuf;
    se05xApdu.se05xCmdLen   = cmdApduBufLen;
    struct Se05xSession *pSession;

    sss_se05x_session_t *tempSess = (sss_se05x_session_t *)pBaseSession;

    pSession = &tempSess->s_ctx;

    sss_status = nxSCP03_Encrypt_CommandAPDU(pSession->pdynScp03Ctx, se05xApdu.se05xCmd, &(se05xApdu.se05xCmdLen));
    if (sss_status != kStatus_SSS_Success) {
        goto cleanup;
    }

    /* If there is no session create the tx buffer with SE05X command only*/
    se05xApdu.se05xCmdLC  = se05xApdu.se05xCmdLen + SCP_GP_IU_CARD_CRYPTOGRAM_LEN;
    se05xApdu.se05xCmdLCW = (se05xApdu.se05xCmdLC == 0) ? 0 : (((se05xApdu.se05xCmdLC < 0xFF) && !(hasle)) ? 1 : 3);

    se05xApdu.dataToMac    = &txBuf[i]; /* Mac is calculated from this data */
    se05xApdu.dataToMacLen = sizeof(*(se05xApdu.se05xCmd_hdr)) + se05xApdu.se05xCmdLCW + se05xApdu.se05xCmdLC -
                             SCP_GP_IU_CARD_CRYPTOGRAM_LEN;

    if (ptxframe->txBufLen - i < sizeof(*se05xApdu.se05xCmd_hdr)) {
        PRINTF("Insufficient buffer. Aborting\r\n");
        goto cleanup;
    }
    memcpy(&txBuf[i], se05xApdu.se05xCmd_hdr, sizeof(*se05xApdu.se05xCmd_hdr));
    txBuf[i] |= 0x4;
    i += sizeof(*se05xApdu.se05xCmd_hdr);

    if (se05xApdu.se05xCmdLCW > 0) {
        if (se05xApdu.se05xCmdLCW == 1) {
            if (ptxframe->txBufLen - i < 1) {
                PRINTF("Insufficient buffer. Aborting\r\n");
                goto cleanup;
            }
            txBuf[i++] = (uint8_t)se05xApdu.se05xCmdLC;
        }
        else {
            if (ptxframe->txBufLen - i < 3) {
                PRINTF("Insufficient buffer. Aborting\r\n");
                goto cleanup;
            }
            txBuf[i++] = 0x00;
            txBuf[i++] = 0xFFu & (se05xApdu.se05xCmdLC >> 8);
            txBuf[i++] = 0xFFu & (se05xApdu.se05xCmdLC);
        }
    }
    if (ptxframe->txBufLen - i < se05xApdu.se05xCmdLen) {
        PRINTF("Insufficient buffer. Aborting\r\n");
        goto cleanup;
    }

    memcpy(&txBuf[i], se05xApdu.se05xCmd, se05xApdu.se05xCmdLen);
    i += se05xApdu.se05xCmdLen;

    ///*Calculate MAC over encrypted APDU */
    sss_status = nxpSCP03_CalculateMac_CommandAPDU(
        pSession->pdynScp03Ctx, se05xApdu.dataToMac, se05xApdu.dataToMacLen, macToAdd, &macLen);
    if (sss_status != kStatus_SSS_Success) {
        goto cleanup;
    }
    if (ptxframe->txBufLen - i < SCP_GP_IU_CARD_CRYPTOGRAM_LEN) {
        PRINTF("Insufficient buffer. Aborting\r\n");
        goto cleanup;
    }

    memcpy(&txBuf[i], macToAdd, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
    i += SCP_GP_IU_CARD_CRYPTOGRAM_LEN;

    se05xApdu.se05xTxBufLen = i;
    ptxframe->txBufLen      = se05xApdu.se05xTxBufLen;
    apduStatus              = SM_OK;
cleanup:
    return apduStatus;
}

__attribute__((cmse_nonsecure_entry)) smStatus_t transmit_scpFrame_NSE(
    uint8_t *pcmdBuf, size_t cmdBufLen, uint8_t *prsp, uint32_t *prspLen)
{
    smStatus_t ret = SM_NOT_OK;
    struct Se05xSession *pSession;
    sss_se05x_session_t *tempSess = (sss_se05x_session_t *)pBaseSession;
    pSession                      = &tempSess->s_ctx;
    // PRINTF("Calling smCom_TransceiveRaw in Secure World\r\n");
 
    if (cmse_check_address_range((void *)pcmdBuf, cmdBufLen, CMSE_NONSECURE | CMSE_MPU_READ) == NULL) {
        PRINTF("Command buffer is not located in normal world!\r\n");
        abort();
    }
    if (cmse_check_address_range(prsp, *prspLen, CMSE_NONSECURE | CMSE_MPU_READ) == NULL) {
        PRINTF("Response buffer is not located in normal world!\r\n");
        abort();
    }

    ret = (smStatus_t)smCom_TransceiveRaw(pSession->conn_ctx, pcmdBuf, (uint16_t)cmdBufLen, prsp, prspLen);
    return ret;
}

__attribute__((cmse_nonsecure_entry)) uint16_t decrypt_scpFrame_NSE(
    size_t cmd_cmacLen, uint8_t *rsp, size_t *rspLength, uint8_t hasle)
{
    uint16_t rv = SM_NOT_OK;
    struct Se05xSession *pSessionCtx;
    sss_se05x_session_t *tempSess = (sss_se05x_session_t *)pBaseSession;
    pSessionCtx                   = &tempSess->s_ctx;
    // PRINTF("\r\n Inside decrypt_scpFrame_NSE in Secure World \r\n");

    if (cmse_check_address_range((void *)rsp, *rspLength, CMSE_NONSECURE | CMSE_MPU_READ) == NULL) {
        PRINTF("Response buffer is not located in normal world!\r\n");
        abort();
    }

    rv = rsp[(*rspLength) - 2] << 8 | rsp[(*rspLength) - 1];
    if ((rv == SM_OK) && (pSessionCtx->pdynScp03Ctx)) {
        rv = nxpSCP03_Decrypt_ResponseAPDU(pSessionCtx->pdynScp03Ctx, cmd_cmacLen, rsp, rspLength, hasle);
    }
    else { /*Counter to be increment only in case of authentication is all kind of SCP
          and response is not 9000 */
        if ((rv != SM_OK) && (pSessionCtx->pdynScp03Ctx != NULL)) {
            if (((pSessionCtx->pdynScp03Ctx->authType == kSSS_AuthType_SCP03) && (cmd_cmacLen - 8) > 0)) {
                nxpSCP03_Inc_CommandCounter(pSessionCtx->pdynScp03Ctx);
            }
        }
    }
    return rv;
}
