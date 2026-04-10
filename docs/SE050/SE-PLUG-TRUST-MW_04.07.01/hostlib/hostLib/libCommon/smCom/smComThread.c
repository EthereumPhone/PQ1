/**
 *
 * Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 *****************************************************************************/

#include <string.h>
#include <stdio.h>

#include "smComThread.h"

#ifdef FLOW_VERBOSE
#define NX_LOG_ENABLE_SMCOM_DEBUG 1
#endif

#include <nxLog_smCom.h>
#include "nxEnsure.h"

#ifdef SMCOM_THREAD

#include "ew_util.h" //"ew_util.h"


static U32 smComThread_Transceive(apdu_t *pApdu);

static U32 smComThread_TransceiveRaw(U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen);

//
// Keep static context here if needed.
// Give your own type.

U16 smComThread_Close()
{
    uart_close();
    pipe_close();
    return SW_OK;
}

//
// smComSCI2C_Init is deprecated, please use smComSCI2C_Open
//
#ifndef TGT_A71CH
void smComThread_Init()
{
    smCom_Init(&smComThread_Transceive, &smComThread_TransceiveRaw);
}
#endif

U16 smComThread_Open(U8 *Threadatr, U16 *ThreadatrLen)
{
    U16 rv = SMCOM_COM_FAILED;
    printf("calling smComThread_Open()\n");
    if (-1 == uart_open())
        return SMCOM_COM_FAILED;
    if (-1 == pipe_open())
        return SMCOM_COM_FAILED;

    int n;

    ENSURE_OR_GO_EXIT(Threadatr != NULL);
    ENSURE_OR_GO_EXIT(ThreadatrLen != NULL);
    n = uart_send(SECURED_SENSOR_TAG, 0x00, 0, NULL);
    if (n < 0)
        return SMCOM_COM_FAILED;
    n = uart_recv(SECURED_SENSOR_TAG, Threadatr);
    if (n < 0)
        return SMCOM_COM_FAILED;
    *ThreadatrLen = n;
    smCom_Init(&smComThread_Transceive, &smComThread_TransceiveRaw);

    printf("ATR:");
    for (int i = 0; i < n; ++i) {
        printf("%X ", Threadatr[i]);
    }
    printf("\n");

    rv = SMCOM_OK;
exit:
    return rv;
}

static U32 smComThread_Transceive(apdu_t *pApdu)
{
    U32 respLen;
    U32 retCode = SMCOM_COM_FAILED;

    ENSURE_OR_GO_EXIT(pApdu != NULL);
    retCode = smComThread_TransceiveRaw((U8 *)pApdu->pBuf, pApdu->buflen, pApdu->pBuf, &respLen);
    pApdu->rxlen = (U16)respLen;
exit:
    return retCode;
}

static U32 smComThread_TransceiveRaw(U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen)
{
    U32 rv = SMCOM_COM_FAILED;
    LOG_MAU8_D("Tx>", pTx, txLen);

    /* Send and receive */
    int n;

    ENSURE_OR_GO_EXIT(pTx != NULL);
    ENSURE_OR_GO_EXIT(pRx != NULL);
    ENSURE_OR_GO_EXIT(pRxLen != NULL);
    n = uart_send(SECURED_SENSOR_TAG, 0x00, txLen, pTx);
    if (n < 0)
        return SMCOM_COM_FAILED;
    n = uart_recv(SECURED_SENSOR_TAG, pRx);
    if (n < 0)
        return SMCOM_COM_FAILED;
    *pRxLen = n;
    LOG_MAU8_D("<Rx", pRx, *pRxLen);

    rv = SMCOM_OK;
exit:
    return rv;
}

#endif //SMCOM_THREAD
