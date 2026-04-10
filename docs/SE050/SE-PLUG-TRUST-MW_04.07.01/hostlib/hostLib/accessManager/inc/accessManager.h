/**
 * @file accessManager.h
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017,2020,2025 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 *
 * @par History
 *
 *****************************************************************************/
#include "sm_types.h"

#define AM_LOCK_UNLOCK_SUPPORT

#define SERVERPORT              8040

#define MSG_SIZE                2048
#define MSG_HEADER_SIZE            4

// General Message Format
//
// [MTY]:[NAD]:[LNH]:[LNL]:[D0]:...[Dn]
// MTY: Message Type
#define	MTY_WAIT_FOR_CARD       0x00
#define	MTY_APDU_DATA           0x01
#define	MTY_STATUS              0x02
#define	MTY_ERROR_MSG           0x03
#define	MTY_TERMINAL_INFO       0x04
#define	MTY_INITIALIZATION_DATA 0x05
#define	MTY_INFORMATION_TEXT    0x06
#define	MTY_DEBUG_INFORMATION   0x07
    // Additionaly defined
    // Lock/Unlock command: Reserve/Release access to node to calling client
#define MTY_LOCK                0x30
#define MTY_UNLOCK              0x31
    // Development commands
#define MTY_SET_UINT32          0x40
#define MTY_GET_UINT32          0x41
	//Default Node Address
#define MYT_DEFAULT_NAD         0x00
	//Close command
#define MTY_CLOSE               0x03

#ifndef NDEBUG
#define MTY_QUIT				0x50
#endif
/* Reset command */
#define MTY_T1OI2C_RESET          0x60
/* Access manager reserved commands - start */
// For future use

#define RESERVED_ID2            0x61
#define RESERVED_ID3            0x62
#define RESERVED_ID4            0x63

#define RESERVED_ID5            0x70
#define RESERVED_ID6            0x71
#define RESERVED_ID7            0x72
#define RESERVED_ID8            0x73
/* Access manager reserved commands - end */

// NAD: Node adres
//   For now always 0x00
// LNH: MSB of data payload length
// LNL: LSB of data payload length
// D0 .. Dn: Optional data payload

// Specific Message Formats
// MTY_LOCK
//  CMD: [MTY_LOCK]:[0x00]:[0x00]:[0x00|0x04]:{NULL}|{Timeout_in_ms(4 byte) NOT_IMPLEMENTED}
//  RSP:
//   In case of failure: [MTY_LOCK]:[0x00]:[0x00]:[0x01]:[failure_cause] (NOT_IMPLEMENTED)
//   In case of success: [MTY_LOCK]:[0x00]:[0x00]:[0x00]
//
// MTY_UNLOCK
//  CMD: [MTY_UNLOCK]:[0x00]:[0x00]:[0x00]
//  RSP: [MTY_UNLOCK]:[0x00]:[0x00]:[0x00]
//
// MTY_SET_UINT32
//  CMD: [MTY_SET_UINT32]:[0x00]:[0x00]:[0x05]:[idx]:{Value (4 byte)}
//  RSP:
//   In case of failure: [MTY_SET_UINT32]:[0x00]:[0x00]:[0x00]
//   In case of success: [MTY_SET_UINT32]:[0x00]:[0x00]:[0x05]:[idx]:{Value (4 byte)}
//
// MTY_GET_UINT32
//  CMD: [MTY_GET_UINT32]:[0x00]:[0x00]:[0x01]:[idx]
//  RSP
//   In case of failure: [MTY_SET_UINT32]:[0x00]:[0x00]:[0x00]
//   In case of success: [MTY_SET_UINT32]:[0x00]:[0x00]:[0x05]:[idx]:{Value (4 byte)}
// MTY_QUIT // Only Enabled in Debug build
//  CMD: [MTY_QUIT]:[0x00]:[0x00]:[0x00]
//  RSP: [MTY_QUIT]:[0x00]:[0x00]:[0x00]

#define MTY_IDX 0
#define NAD_IDX 1
#define LNH_IDX 2
#define LNL_IDX 3
#define DATA_START_IDX 4

#define MCS_OK                     0
#define MCS_SOCKET_FAILURE         2
#define MCS_MSG_MISMATCH           3

int handleSetUint32(uint8_t *cmdBuffer, int cmdBufferLen, uint8_t *rspBuffer, int *rspBufferLen);
int handleGetUint32(uint8_t *cmdBuffer, int cmdBufferLen, uint8_t *rspBuffer, int *rspBufferLen);

#define AM_OK       0x0000
#define AM_ARG_FAIL 0x6000

U16 amPackageApduResponse(U8 messageType, U8 nodeAddress, U8 *payload, U16 payloadLen, U8 *targetBuf, U16 *targetBufLen);

#define UNIX_SOCKET_FILE "/var/run/am"
