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

#ifndef SUS_APDU_H
#define SUS_APDU_H

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if (SSS_HAVE_APPLET_SE051_UWB)
/* OK */
#else
#error "Only with SE051W based build"
#endif //SSS_HAVE_APPLET_SE051_UWB

#include <se05x_tlv.h>

/** \addtogroup se_apdu_apis
 * \{ */

#define SUS_MAX_BUF_SIZE_CMD (64)
#define SUS_MAX_BUF_SIZE_RSP (64)
#define SUS_MAX_WRAPPED_RDS_RSP_SIZE (272)
/**
 * \brief       SUS Client Plain RDS.
 */
/* @{ */
typedef struct
{
    /** Ranging Session Key 16 or 32 bytes*/
    uint8_t *pRangingSessionKey;
    size_t rangingSessionKeyLen;

    /**Responder-specific ranging key */
    uint8_t *pRspndrRangingKey;
    size_t rspndrRangingKeyLen;

    /**  Proximity Distance 2 bytes*/
    uint16_t proxDistance; //Currently not needed

    /** Angle of Arrival 2 bytes */
    int16_t AoA; //Currently not needed

    /** Client specific Data 1 - 128 bytes*/
    uint8_t *pClientData;
    size_t clientDataLen;

    /** Transaction identifier */
    uint8_t *pTransactionId;
    size_t transactionIdLen;

    /** Key identifier 20 bytes */
    uint8_t *pKeyId;
    size_t KeyIdLen;

    /** Aribitrary Data*/
    uint8_t *pArbtData;
    size_t arbtDataLen;

    /** RFU */
    //  uint8_t *pRFU;
    //  size_t len;

    /** Finalization Applet AID */
    uint8_t *pAppletAid;
    size_t appletAidLen;

    /** Session ID */
    uint8_t *pSessionId;
    size_t sessionIdLen;
} se_plainRDS;

/* @}*/

/** \brief SUS_API_GetData
 * Reads SUS applet specific data.
 * Note: This command does not require secure messaging.
 *
 * # Command to Applet
 *
 * @rst
 * +---------+---------------------------+------------------------------------------------+
 * | Field   | Value                     | Description                                    |
 * +=========+===========================+================================================+
 * | CLA     | 0x80 or 0x84              |                                                |
 * +---------+---------------------------+------------------------------------------------+
 * | INS     | 0xCA                      | Get Data                                       |
 * +---------+---------------------------+------------------------------------------------+
 * | P1      | 00                        | Data object tag (MSB)                          |
 * +---------+---------------------------+------------------------------------------------+
 * | P2      | xx                        | Data object tag (LSB)                          |
 * +---------+---------------------------+------------------------------------------------+
 * | Lc      | absent                    |                                                |
 * +---------+---------------------------+------------------------------------------------+
 * | Payload | absent                    |                                              . |
 * +---------+---------------------------+------------------------------------------------+
 * | Le      | 00                        | Expecting return data.                         |
 * +---------+---------------------------+------------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +-----------+----------------------+--------+--------------------------------------------------+
 * | Tag(P1P2) | Name                 | Length | Format                                           |
 * +===========+======================+========+=======================+++++======================+
 * |  '0040'   | Applet version       |   3    | <Major version> || <Minor version> || <Sequence> |
 * |           | identifier           |        |                                                  |
 * +-----------+----------------------+--------+--------------------------------------------------+
 * |  '0042'   | Applet life          |   1    |   '02': Personalized                             |
 * |           | cycle                |        |   '03': Ready                                    |
 * |           |                      |        |   '04': Locked                                   |
 * +-----------+----------------------+--------+--------------------------------------------------+
 * |  '0043'   | Remaining            |    1   | Remaining Factory Reset counter. When equal to 0,|
 * |           | Factory Reset        |        | Factory Reset is unavailable.                    |
 * +-----------+----------------------+--------+--------------------------------------------------+
 * |  '0045'   | Binding history      |variable| Total binding count (2 bytes)                    |
 * |           |                      |        | UWB subsystem count (1 byte)                     |
 * |           |                      |        | UWB subsystem entries (up to 3 entries)          |
 * +-----------+----------------------+--------+--------------------------------------------------+
 * |  '0046'   | Binding State        |   3    | Format description in below table                |
 * +-----------+----------------------+--------+--------------------------------------------------+
 * @endrst
 *
 * Binding State tag 0046 Format
 *
 * @rst
 * +------------+----------------------------------------------+
 * | Value      | Description                                  |
 * +============+==============================================+
 * | 1st byte   | '00' - Not Bound                             |
 * |            | '01' - Bound & Unlocked                      |
 * |            | '02' - Bound & Locked                        |
 * +------------+----------------------------------------------+
 * | 2nd byte   | remaining binding attempts.                  |
 * |            | (remaining factory reset counter, when equal |
 * |            | to 0 Factory Reset is available).            |
 * +------------+----------------------------------------------+
 * | 3rd byte   | remaining binding attempts                   |
 * |            | (bound & unlocked). This value shall be set  |
 * |            | to '00' if byte 1 is equal to '02'           |
 * +------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 * @param[in]  session_ctx        The smcom session context
 * @param[in]  getDataTag      P2 tag for get data
 * @param[out] pOutData    Binding state data
 * @param[out] pOutDataLen Binding state data length
 *
 * @return     The APDU Transive Status.
 */
smStatus_t SUS_API_GetData(pSe05xSession_t session_ctx, uint8_t getDataTag, uint8_t *pOutData, size_t *pOutDataLen);

/** \brief SUS_API_InitiateBinding
 *
 * Signals the beginning of the binding procedure. As a result of processing this command,
 * SUS will derive SCP03 static keys to bind to the UWB subsystem.*
 *
 *
 * # Command to Applet
 *
 *
 * @rst
 * +---------+---------------------------+------------------------------------------------+
 * | Code    | Value                     | Description                                    |
 * +=========+===========================+================================================+
 * | CLA     | 0x80                      | Class byte                                     |
 * +---------+---------------------------+------------------------------------------------+
 * | INS     | 0x20                      | INITIATE BINDING :cpp:type:`SUS_INS_t`         |
 * +---------+---------------------------+------------------------------------------------+
 * | P1      | 00 or 3F                  | HeliosLC byte                                  |
 * +---------+---------------------------+------------------------------------------------+
 * | P2      | 00-FF                     | b1-b7: BRK identifier                          |
 * |         |                           | b8: Alternative DBRK derivation constant flag  |
 * +---------+---------------------------+------------------------------------------------+
 * | Lc      | #(Payload)                | Payload length                                 |
 * +---------+---------------------------+------------------------------------------------+
 * | Payload | (variale) Not TLV         | RAND_HE (8 bytes)                              |
 * |         |                           | Helios ID (16 bytes)                           |
 * +---------+---------------------------+------------------------------------------------+
 * | Le      | 0x00                      |                                                |
 * +---------+---------------------------+------------------------------------------------+
 * @endrst
 *
 *  # R-APDU Body
 *
 * @rst
 * +------------+----------------------------------------------+
 * | LENGTH     | content                                      |
 * +============+==============================================+
 * | 08         | RAND_SE                                      |
 * +------------+----------------------------------------------+
 * | 16         | Secure Element unique ID                     |
 * +------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 * @param[in]  session_ctx        The SMCOM connect context
 * @param[in]  heliosLC
 * @param[in]  brkIdentifier
 * @param[in]  pBindinData
 * @param[in]  bindinDataLen
 * @param[out]  pOutData
 * @param[out]  pOutDataLen
 */
smStatus_t SUS_API_InitiateBinding(pSe05xSession_t session_ctx,
    uint8_t heliosLC,
    uint8_t brkIdentifier,
    uint8_t *pBindinData,
    size_t bindinDataLen,
    uint8_t *pOutData,
    size_t *pOutDataLen);

/** \brief SUS_API_WrapData
 *
 * Transfers input data for Ranging Data Set wrapping to the Secure UWB Service using
 * the FiRa interface and returns the response from the Secure UWB Service back to the
 * user.
 *
 * # Command to Applet
 *
 *
 * @rst
 * +---------+---------------------------+------------------------------------------------+
 * | Code    | Value                     | Description                                    |
 * +=========+===========================+================================================+
 * | CLA     | 0x80                      | Class byte                                     |
 * +---------+---------------------------+------------------------------------------------+
 * | INS     | 0xA0                      | WRAP DATA                                      |
 * +---------+---------------------------+------------------------------------------------+
 * | P1      | xx                        | Any value                                      |
 * +---------+---------------------------+------------------------------------------------+
 * | P2      | xx                        | Any value                                      |
 * +---------+---------------------------+------------------------------------------------+
 * | Lc      | #(Payload)                | Payload length                                 |
 * +---------+---------------------------+------------------------------------------------+
 * | Payload | plain RDS TLV             | data to be wrapped in the Secure UWB Service   |
 * +---------+---------------------------+------------------------------------------------+
 * | Le      | 0x00                      |                                                |
 * +---------+---------------------------+------------------------------------------------+
 * @endrst
 *
 *  # R-APDU Body
 *
 * @rst
 * +-----------------+----------------------------------------------+
 * | Name            | LENGTH                                       |
 * +=================+==============================================+
 * | Wrapped Ranging | depends on C-APDU                            |
 * | Data Set        | Data Field                                   |
 * +-----------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 * @param[in]  session_ctx        The SMCOM connect context
 * @param[in]  pRdsData        Plain RDS
 * @param[out]  pOutData
 * @param[out]  pOutDataLen
 */
smStatus_t SUS_API_WrapData(pSe05xSession_t session_ctx, se_plainRDS *pRdsData, uint8_t *pOutData, size_t *pOutDataLen);

/** \brief SUS_API_Init
 * Opens a logical channel and selects the SUS or SUS client applet.
 *
 * @param[in]  session_ctx       The session context
 * @param[in]  isSusClient       True or False
 *
 */

smStatus_t SUS_API_Init(pSe05xSession_t session_ctx, uint8_t isSusClient, uint8_t logical_channel);

/**
 * @}
 */

#endif //SUS_APDU_H
