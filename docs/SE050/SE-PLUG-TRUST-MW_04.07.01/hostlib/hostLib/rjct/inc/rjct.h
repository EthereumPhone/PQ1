/**
 * @file rjct.h
 * @author NXP Semiconductors
 * @version 1.0
 * @section LICENSE
 * ----------------------------------------------------------------------------
 *
 * Copyright 2016 NXP
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------------
 * @section DESCRIPTION
 * This file defines the API of the RemoteJCTerminal implementation.
 * ----------------------------------------------------------------------------
 * @section HISTORY
 * 1.0   06-may-2014 : Initial version
 *
 *****************************************************************************/
#ifndef _REMOTE_JC_TERMINAL_H_
#define _REMOTE_JC_TERMINAL_H_

#include "sm_types.h"

typedef struct {
    U16 param1;
    U16 param2;
} SmCommStateRjct_t;

U16 SM_ConnectRjct(SmCommStateRjct_t *commState, U8 *atr, U16 *atrLen);
U16 SM_SendAPDURjct(U8 *cmd, U16 cmdLen, U8 *resp, U16 *respLen);
U16 SM_CloseRjct(U8 mode);

#define WAIT_FOR_CARD       0x00
#define APDU_DATA           0x01
#define STATUS              0x02
#define ERROR_MSG           0x03
#define TERMINAL_INFO       0x04
#define INITIALIZATION_DATA 0x05
#define INFORMATION_TEXT    0x06
#define DEBUG_INFORMATION   0x07

#define RJCT_OK       0x0000
#define RJCT_ARG_FAIL 0x6000

U16 rjctPackageApduResponse(U8 messageType, U8 nodeAddress, U8 *payload, U16 payloadLen, U8 *targetBuf, U16 *targetBufLen);

#endif // _REMOTE_JC_TERMINAL_H_
