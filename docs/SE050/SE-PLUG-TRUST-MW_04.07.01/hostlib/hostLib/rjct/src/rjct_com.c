/**
* @file rjct_com.c
* @author NXP Semiconductors
* @version 1.0
* @par License
*
* Copyright 2016,2020 NXP
* SPDX-License-Identifier: Apache-2.0
*
* @par Description
* This file implements basic communication functionality between Host and
* Secure element.
* @par History
* 1.0   26-march-2014 : Initial version
*
*****************************************************************************/
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "rjct.h"
#include <limits.h>

// #ifdef __gnu_linux__
#ifdef TDA8029_UART
#include "smComAlpar.h"
#include "smUart.h"
#endif
#if defined(SCI2C)
#include "smComSCI2C.h"
#endif
#if defined(SPI)
#include "smComSCSPI.h"
#endif
#if defined(PCSC)
#include "smComPCSC.h"
#endif
#if defined(SMCOM_JRCP_V2)
#include "smComJRCP.h"
#endif
#if defined(RJCT_VCOM)
#include "smComSerial.h"
#endif
#if defined(T1oI2C)
#include "smComT1oI2C.h"
#endif
#if defined(SMCOM_PN7150)
#include "smComPN7150.h"
#endif
#if defined(SMCOM_THREAD)
#include "smComThread.h"
#endif

#include "global_platf.h"

#ifndef FLOW_VERBOSE
#define FLOW_VERBOSE
#endif

#ifdef FLOW_VERBOSE
#define FPRINTF(...) printf (__VA_ARGS__)
#else
#define FPRINTF(...)
#endif

/**
 * SM_ConnectRjct
 * @param[in] commState
 * @param[out] atr
 * @param[in,out] atrLen
 * @return ::ERR_CONNECT_LINK_FAILED    No communication with TDA chip (and/or) Secure Module
 * @return ::SMCOM_COM_FAILED           Cannot open communication channel on the Host
 * @return ::SMCOM_PROTOCOL_FAILED      No communication with Secure Module
 * @return 0x9000                       OK
 */
U16 SM_ConnectRjct(SmCommStateRjct_t *commState, U8 *atr, U16 *atrLen)
{
    U16 sw = SW_OK;
    U16 uartBR = 0;
    U16 t1BR = 0;
#ifdef TDA8029_UART
    U32 status = 0;
#elif defined(SCI2C) || defined(T1oI2C)
    U8 dummyAtr[64];
    U16 dummyAtrLen = sizeof(dummyAtr);
    U8 precookedI2cATR[] = {
        0x3B, 0xFB, 0x18, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x45, 0x50, 0x4C, 0x41, 0x43, 0x45, 0x48, 0x4F, 0x4C,
        0x44, 0x45, 0x52, 0xAB};
#endif

#ifndef A71_IGNORE_PARAM_CHECK
    if ((commState == NULL) || (atr == NULL) || (atrLen == 0)) {
        return ERR_API_ERROR;
    }
#endif

#ifdef TDA8029_UART
    if ((*atrLen) <= 33) return ERR_API_ERROR;

    smComAlpar_Init();
    status = smComAlpar_AtrT1Configure(ALPAR_T1_BAUDRATE_MAX, atr, atrLen, &uartBR, &t1BR);
    if (status != SMCOM_ALPAR_OK )
    {
        commState->param1 = 0;
        commState->param2 = 0;
        FPRINTF("smComAlpar_AtrT1Configure failed: 0x%08X\n", status);
        return ERR_CONNECT_LINK_FAILED;
    }
#elif defined SMCOM_PN7150
    sw = smComPN7150_Open(0, 0x00, atr, atrLen);
#elif defined(SCI2C)
    // The smComSCI2C_Open function returns an SCI2C compliant ATR value.
    // This value can not be used as is as ATR parameter to the SM_Connect function because it is
    // not ISO7816-3 compliant. Instead a pre-cooked value is used.
    // In case no SCI2C ATR can be retrieved by smComSCI2C_Open, no Secure Element is attached.
    sw = smComSCI2C_Open(NULL, ESTABLISH_SCI2C, 0x00, dummyAtr, &dummyAtrLen);
#elif defined(PCSC)
    sw = smComPCSC_Open(0, atr, atrLen);
#elif defined(T1oI2C)
    // sw = smComT1oI2C_Open(NULL, ESE_MODE_NORMAL, 0x00, atr, atrLen);
    sw = smComT1oI2C_Open(NULL, ESE_MODE_NORMAL, 0x00, dummyAtr, &dummyAtrLen);
#elif defined(SMCOM_JRCP_V2)
    if (atrLen != NULL)
        *atrLen = 0;
    AX_UNUSED_ARG(atr);
    AX_UNUSED_ARG(atrLen);
#endif
    commState->param1 = t1BR;
    commState->param2 = uartBR;
#if defined(SCI2C)
    if (sw == SW_OK)
    {
        if (dummyAtrLen == 0)
        {
            FPRINTF("smComSCI2C_Open failed. No secure module attached");
            *atrLen = 0;
            return ERR_CONNECT_LINK_FAILED;
        }
        else
        {
            int i = 0;
            FPRINTF("SCI2C_ATR=0x");
            for (i=0; i<dummyAtrLen; i++) FPRINTF("%02X.", dummyAtr[i]);
            FPRINTF("\n");
        }

        memcpy(atr, precookedI2cATR, sizeof(precookedI2cATR));
        *atrLen = sizeof(precookedI2cATR);
    }
#endif
#if defined(T1oI2C)
    if (sw == SW_OK)
    {
        if (dummyAtrLen == 0)
        {
            FPRINTF("smComT1oI2C_Open failed. No secure module attached");
            *atrLen = 0;
            return ERR_CONNECT_LINK_FAILED;
        }
        else
        {
            int i = 0;
            FPRINTF("T1oI2C_ATR=0x");
            for (i=0; i<dummyAtrLen; i++) FPRINTF("%02X.", dummyAtr[i]);
            FPRINTF("\n");
        }
        FPRINTF("Replacing T1oI2C_ATR by default ATR.\n");
        memcpy(atr, precookedI2cATR, sizeof(precookedI2cATR));
        *atrLen = sizeof(precookedI2cATR);
    }
#endif

    return sw;
}


U16 SM_SendAPDURjct(U8 *cmd, U16 cmdLen, U8 *resp, U16 *respLen)
{
    U32 status = 0;
    U32 respLenLocal = *respLen;

    status = smCom_TransceiveRaw(NULL, cmd, cmdLen, resp, &respLenLocal);
    if (respLenLocal > UINT16_MAX) {
        return status;
    }
    *respLen = (U16)respLenLocal;

    return (U16) status;
}

U16 SM_CloseRjct(U8 mode)
{
    U16 sw = SW_OK;

#if defined(SCI2C)
    sw = smComSCI2C_Close(mode);
#endif
#if defined(SPI)
    sw = smComSCSPI_Close(mode);
#endif
#if defined(PCSC)
    sw = smComPCSC_Close(mode);
#endif
#if defined(T1oI2C)
    sw = smComT1oI2C_Close(NULL, mode);
#endif
#if defined(SMCOM_JRCP_V1)
    AX_UNUSED_ARG(mode);
    sw = smComSocket_Close();
#endif
#if defined(SMCOM_JRCP_V2)
    AX_UNUSED_ARG(mode);
    sw = smComJRCP_Close(NULL, mode);
#endif
#if defined(RJCT_VCOM)
    AX_UNUSED_ARG(mode);
    sw = smComVCom_Close(NULL);
#endif
#if defined(SMCOM_THREAD)
    AX_UNUSED_ARG(mode);
    sw = smComThread_Close();
#endif
    smCom_DeInit();

    return sw;
}
