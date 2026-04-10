/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ns_channel.h"
#include "nxLog_hostLib.h"
#include "nxEnsure.h"

#include "veneer_table.h"
#include "fsl_sss_se05x_types.h"

sss_se05x_session_t gSecureWorldSession;

smStatus_t nsChannel_ToSW_TXn(struct Se05xSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle)
{
    smStatus_t ret = SM_NOT_OK;
    U16 rv         = SM_NOT_OK;

    uint8_t txBuf[1024] = {
        0,
    };
    size_t txBufLen = sizeof(txBuf);
    nseTxFrame_t tx;
    uint32_t u32rspLen = (uint32_t)*rspLen;

    tx.txBuf      = txBuf;
    tx.txBufLen   = txBufLen;
    tx.cmdApduBuf = cmdBuf;

    // DbgConsole_Printf_NSE("Sending plain data to Secure World for SCP encryption!!!!\r\n");
    ret = encrypt_plainFrame_NSE(hdr, cmdBufLen, &tx);
    ENSURE_OR_GO_EXIT(ret == SM_OK);
    txBufLen = tx.txBufLen;

    // DbgConsole_Printf_NSE("Sending SCP frame to SE via Secure World!!!!\r\n");
    ret = SM_NOT_OK;
    ret = transmit_scpFrame_NSE(txBuf, (uint16_t)txBufLen, rsp, &u32rspLen);
    ENSURE_OR_GO_EXIT(ret == SM_OK);
    *rspLen = u32rspLen;

    // DbgConsole_Printf_NSE("Decrypt SCP frame received from SE in Secure World!!!!\r\n");
    ret = SM_NOT_OK;
    if (*rspLen >= 2) {
        rv = decrypt_scpFrame_NSE(cmdBufLen, rsp, rspLen, hasle);
    }

    if (rv == SM_OK) {
        ret = SM_OK;
    }
exit:
    return ret;
}

sss_status_t nsChannel_context_init(sss_tunnel_t *pChannelCtx)
{
    sss_status_t retval = kStatus_SSS_Fail;
    sss_se05x_tunnel_context_t *pSe05xCtx;
    ENSURE_OR_GO_CLEANUP(pChannelCtx);

    pSe05xCtx                        = (sss_se05x_tunnel_context_t *)pChannelCtx;
    pSe05xCtx->se05x_session         = &gSecureWorldSession;
    gSecureWorldSession.subsystem    = kType_SSS_SE_SE05x;
    gSecureWorldSession.s_ctx.fp_TXn = &nsChannel_ToSW_TXn;

    retval = kStatus_SSS_Success;

cleanup:
    return retval;
}
