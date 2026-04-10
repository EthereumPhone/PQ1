/* Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _VENEER_SMCOM_TABLE_H_
#define _VENEER_SMCOM_TABLE_H_

#include "se05x_enums.h"
#include "fsl_sss_api.h"
#include <nxScp03_Apis.h>
#include "se05x_tlv.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

/** Normal world to secure world APDU Frame interface */
typedef struct nseTxFrame
{
    /* Command Apdu Buffer */
    uint8_t *cmdApduBuf;
    /* Transformed header  */
    tlvHeader_t *outhdr;
    /* Transmit  buffer */
    uint8_t *txBuf;
    /* Transmit  buffer length */
    size_t txBufLen;
    /* HAS Le or not? */
    uint8_t hasle;
} nseTxFrame_t;

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*!
 * @brief Entry function for encrypting data in SW
 *
 * This function encrypts data in Secure world
 *
 * @param hdr             pointer to header of APDU
 * @param pSend_nseFrame  pointer to data of APDU
 * @return                smStatus_t of  function
*/
smStatus_t encrypt_plainFrame_NSE(const tlvHeader_t *hdr, const size_t cmdApduBufLen, nseTxFrame_t *txframe);

/*!
 * @brief Entry function for sending data to SW
 *
 * This function sends to SE  in Secure world
 *
 * @param cmdBuf          pointer to Cmd Buffer
 * @param cmdBufLen       size of Cmd Buffer
 * @param rsp             pointer to Rsp Buffer
 * @param rspLen          pointer to size of Rsp Buffer
 * @return                smStatus_t of  function
*/
smStatus_t transmit_scpFrame_NSE(uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *rsp, uint32_t *rspLen);

/*!
 * @brief Entry function for decrypting data in SW
 *
 * This function decrypts in Secure world
 *

 * @param cmdBufLen       size of Cmd Buffer
 * @param rsp             pointer to Rsp Buffer
 * @param rspLen          pointer to size of Rsp Buffer
 * @param hasle           le value
 * @return                uint16_t of  function
 */
uint16_t decrypt_scpFrame_NSE(size_t cmdBufLen, uint8_t *rspBuf, size_t *pRspBufLen, uint8_t hasle);

#endif /* _VENEER_SMCOM_TABLE_H_ */
