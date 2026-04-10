/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include "smComNxpNfcRdLib.h"
#include "nxLog_smCom.h"
#include "nxEnsure.h"

/* ------------------------------------------------------------------------- */

NPNxpNfcRdLibCtx_t gsmComRdLibCtx;

static phStatus_t AppMain(const char *com_port, const char *front_end);
static phStatus_t np_TypeA_Init(NPNxpNfcRdLibCtx_t *pRdCtx);
static phStatus_t np_TypeA_Demo(NPNxpNfcRdLibCtx_t *pRdCtx);
U32 smComNxpNfcRdLib_Transceive(void* conn_ctx, apdu_t *pApdu);
U32 smComNxpNfcRdLib_TransceiveRaw(void* conn_ctx, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen);

/** TODO */
U16 smComNxpNfcRdLib_OpenVCOM(void **conn_ctx, const char * vPortName) {
    phStatus_t ret = AppMain(vPortName, "RC663");
    if (ret == PH_ERR_SUCCESS) {
        smCom_Init(&smComNxpNfcRdLib_Transceive, &smComNxpNfcRdLib_TransceiveRaw);
    }

    return (U16)ret;
}

void smComNxpNfcRdLib_Close(void)
{
    phbalReg_ClosePort(gsmComRdLibCtx.pBal);
}

U32 smComNxpNfcRdLib_Transceive(void* conn_ctx, apdu_t *pApdu)
{
    U32 respLen = 256;
    U32 retCode = SMCOM_COM_FAILED;

    ENSURE_OR_GO_EXIT(pApdu != NULL);

    retCode = smComNxpNfcRdLib_TransceiveRaw(conn_ctx, (U8 *)pApdu->pBuf, pApdu->buflen, pApdu->pBuf, &respLen);

    pApdu->rxlen = (U16)respLen;
exit:
    return retCode;
}

U32 smComNxpNfcRdLib_TransceiveRaw(void * conn_ctx, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen)
{
    uint16_t u16RxLen = 0; //*pRxLen;
    phStatus_t status;
    uint8_t *ppRx = NULL;
    LOG_MAU8_I("L4 Command:", pTx, txLen);
    status = phpalI14443p4_Exchange(&gsmComRdLibCtx.sType4Pal, PH_EXCHANGE_DEFAULT, pTx, txLen, &ppRx, &u16RxLen);
    if (status == PH_ERR_SUCCESS) {
        *pRxLen = u16RxLen;
        memcpy(pRx, ppRx, u16RxLen);
        LOG_MAU8_I("L4 Reponse:", pRx, u16RxLen);
        return SMCOM_OK;
    }
    else {
        LOG_W("TX Failed with status %04X", status);
        return SMCOM_SND_FAILED;
    }
}

static phStatus_t AppMain(const char *com_port, const char *front_end)
{
    phStatus_t status = PH_ERR_SUCCESS;

    PH_CHECK_SUCCESS_FCT(status, np_NxpNfcRdLib_CheckComPortName(com_port, &gsmComRdLibCtx.sBalCtx));
    PH_CHECK_SUCCESS_FCT(status, np_NxpNfcRdLib_CheckFrontEndName(front_end, &gsmComRdLibCtx));
    PH_CHECK_SUCCESS_FCT(status, np_NxpNfcRdLib_Init(&gsmComRdLibCtx));
    PH_CHECK_SUCCESS_FCT(status, np_TypeA_Init(&gsmComRdLibCtx));

    //// Example Starts /////
    {
        int count = 0;
        LOG_I("Performing filed on-off.\n");
        while (count++ < 2) {
            PH_CHECK_SUCCESS_FCT(status, phhalHw_FieldOn(gsmComRdLibCtx.pHal));
            Sleep(50);
            PH_CHECK_SUCCESS_FCT(status, phhalHw_FieldOff(gsmComRdLibCtx.pHal));
            Sleep(100);
        }
        status = np_TypeA_Demo(&gsmComRdLibCtx);
    }
    //// Example Ends /////

    return status;
}

static phStatus_t np_TypeA_Init(NPNxpNfcRdLibCtx_t *pRdCtx)
{
    phStatus_t status;
    PH_CHECK_SUCCESS_FCT(status, phpalI14443p3a_Sw_Init(&pRdCtx->sType3APal, sizeof(pRdCtx->sType3APal), pRdCtx->pHal));
    PH_CHECK_SUCCESS_FCT(status, phpalI14443p4a_Sw_Init(&pRdCtx->sType4APal, sizeof(pRdCtx->sType4APal), pRdCtx->pHal));
    PH_CHECK_SUCCESS_FCT(status, phpalI14443p4_Sw_Init(&pRdCtx->sType4Pal, sizeof(pRdCtx->sType4Pal), pRdCtx->pHal));
    return status;
}

phStatus_t np_TypeA_Demo(NPNxpNfcRdLibCtx_t *pRdCtx)
{
    phStatus_t status = PH_ERR_CUSTOM_BEGIN;
    uint8_t aUid[10] = {0};
    uint8_t uidLen = 0;
    uint8_t bSak;
    uint8_t bMoreCardsAvailable;

    int retryCount = 1000;
    while (status != PH_ERR_SUCCESS && retryCount-- >= 0) {
        PH_CHECK_SUCCESS_FCT(status, phhalHw_FieldReset(pRdCtx->pHal));
        status = phpalI14443p3a_ActivateCard(&pRdCtx->sType3APal, NULL, 0, aUid, &uidLen, &bSak, &bMoreCardsAvailable);
        if (status != PH_ERR_SUCCESS) {
            printf("%c\r", "/-\\+"[retryCount % 4]);
        }
    }
    if (status != PH_ERR_SUCCESS) {
        LOG_E("Could not detect any TYPE A Card.\n");
        return status;
    }
    LOG_MAU8_I("UID after L3 Activation", aUid, sizeof(aUid));

    if (bSak == 0x20 || bSak == 0x28) // DESFIre
    {
        uint8_t pAts[256] = {0};
        uint8_t PH_MEMLOC_REM bCidEnabled;
        uint8_t PH_MEMLOC_REM bCid;
        uint8_t PH_MEMLOC_REM bNadSupported;
        uint8_t PH_MEMLOC_REM bFwi;
        uint8_t PH_MEMLOC_REM bFsdi;
        uint8_t PH_MEMLOC_REM bFsci;

        // activate till level 4
        PH_CHECK_SUCCESS_FCT(status,
            phpalI14443p4a_ActivateCard(&pRdCtx->sType4APal,
                0x08,
                0, // CID = 0
                (uint8_t)PHHAL_HW_RF_DATARATE_106,
                (uint8_t)PHHAL_HW_RF_DATARATE_106,
                pAts));
        LOG_MAU8_I("ATS after L4 Activation", pAts, pAts[0]);
        PH_CHECK_SUCCESS_FCT(status,
            phpalI14443p4a_GetProtocolParams(
                &pRdCtx->sType4APal, &bCidEnabled, &bCid, &bNadSupported, &bFwi, &bFsdi, &bFsci));
        PH_CHECK_SUCCESS_FCT(status,
            phpalI14443p4_SetProtocol(
                &pRdCtx->sType4Pal, bCidEnabled, bCid, bNadSupported, pRdCtx->sType4Pal.bNad, bFwi, bFsdi, bFsci));
    }
    else if (bSak == 0x00) // Mifare Ultralight
    {
        status = PH_ERR_UNSUPPORTED_COMMAND;
        LOG_W("Do not support SAK==0");
    }
    else {
        LOG_E("SAK=0x%02X is not processed by this example", bSak);
        status = PH_ERR_UNSUPPORTED_COMMAND;
    }
    return status;
}
