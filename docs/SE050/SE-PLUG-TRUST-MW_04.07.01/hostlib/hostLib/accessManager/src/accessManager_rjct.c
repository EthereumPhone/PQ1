/**
 * @file rjct.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Connection Oriented TCP/IP Server implementing Remote JCTerminal Protocol.
 * The server can connect to the card via the
 * - TDA-UART protocol
 * - SCI2C
 * - PCSC
 * @par History
 *
 *****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "accessManager.h"

U16 amPackageApduResponse(U8 messageType, U8 nodeAddress, U8 *payload, U16 payloadLen, U8 *targetBuf, U16 *targetBufLen)
{
    if ((UINT16_MAX - 4) < payloadLen) {
        printf("payloadLen is long");
        return AM_ARG_FAIL;
    }

    if (*targetBufLen < (4 + payloadLen)) {
        printf("Target buffer provided too small.\n");
        return AM_ARG_FAIL;
    }

    targetBuf[0] = messageType;
    targetBuf[1] = nodeAddress;
    targetBuf[2] = (payloadLen >> 8) & 0x00FF;
    targetBuf[3] = payloadLen & 0x00FF;
    memcpy(&targetBuf[4], payload, payloadLen);
    *targetBufLen = 4 + payloadLen;
    return AM_OK;
}
