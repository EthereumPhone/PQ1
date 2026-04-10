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

#ifndef SE_FIRALITE_APIS_H
#define SE_FIRALITE_APIS_H

#if (SSS_HAVE_APPLET_SE051_UWB)
/* OK */
#else
#error "Only with SE051W based build"
#endif //SSS_HAVE_APPLET_SE051_UWB

#define FIRALITE_MAX_BUF_SIZE_CMD (272)
#define FIRALITE_MAX_BUF_SIZE_RSP (272)

#define FIRALITE_SELECT_BUF_SIZE_CMD (64)
#define FIRALITE_SELECT_BUF_SIZE_RSP (64)

#define FIRALITE_MAX_DEVICE_ID_LEN (13)

/** \addtogroup se_firalite_apdu_apis
 * \{ */

/** FiraLite OID descriptor */
typedef struct
{
    /** Reference to OID data */
    uint8_t *pOIDData;
    /** length of OID data */
    size_t OIDDataLen;
} se_firelite_oid_entry;

/** FiraLite SelectADF response */
typedef struct
{
    /** AID data */
    uint8_t pAid[16];
    /** length of AID */
    size_t aidLen;
    /** indicates whether proprietary info is used */
    bool is_privacy_enabled;
    /** proprietary info */
    uint8_t pPropInfo[32];
    /** Device Identifier which uniquely identifies FiRa device */
    uint8_t deviceId[FIRALITE_MAX_DEVICE_ID_LEN];
} se_firelite_selectadf_reponse_t;

/** FiraLite route target */
typedef enum
{ /** Invalid */
    se_firalite_route_NA = 0,
    /** Route to App in FiraLite Applet */
    se_firalite_route_firaLiteApplet = 0x01,
    /**  Route to App in host */
    se_firalite_route_host = 0x02,
} se_firalite_route_target_t;

/** FiraLite optsA crypto parameter */
typedef enum
{ /** Support symmetric crypto */
    se_firalite_optsa_symm_crypto = 0x00,
} se_firalite_optsa_t;

/**  Firalite secure ranging info */
typedef struct
{
    /**Firalite session key info */
    uint8_t *pUWBSessionKey;
    /**Firalite session key length */
    uint8_t UWBSessionKeyLen;
    /**Firalite sub session key info */
    uint8_t *pUWBSubSessionKey;
    /**Firalite sub session key length */
    uint8_t UWBSubSessionKeyLen;
    /**Firalite session key Id */
    uint32_t subSessionId;
    /**Firalite rds flag */
    uint8_t makeRDSAvailable;
} se_firalite_secure_ranging_info_t;

/**   Firalite command routing info */
typedef struct
{
    /**Firalite command route target */
    se_firalite_route_target_t target;
    /**Firalite command buffer */
    uint8_t *pCmd;
    /**Firalite command buffer length */
    uint8_t CmdLen;
} se_firalite_cmd_routing_info_t;

/** \brief se_FiRaLite_API_Select
* This selects FiRalite applet on channel 1.
*
* # Selects FiRalite Applet
*
* @param[in]  session_ctx        The smcom session context
* @param[in]  logical_channel   The logical channel to be opened.
*
* @return     The select Status.
*/
smStatus_t se_FiRaLite_API_Select(pSe05xSession_t session_ctx, uint8_t logical_channel);

/** \brief se_FiRaLite_API_SelectADF
 * The SELECT ADF command is used to select and route subsequent commands to a specific ADF
 *
 *
 * @param[in]  session_ctx      session context
 * @param[in]  optsA         Crypto Type
 * @param[in]  oid_entries   reference to OID entries
 * @param[in]  oid_entries_count number of OID entries
 * @param[out]  pRspData     Response data
 * @param[out]  pRspDataLen  Response data Length
 *
 * @return     The APDU Transceive Status.
 */
smStatus_t se_FiRaLite_API_SelectADF(pSe05xSession_t session_ctx,
    const se_firalite_optsa_t optsA,
    se_firelite_oid_entry *oid_entries,
    const size_t oid_entries_count,
    uint8_t *pRspData,
    size_t *pRspDataLen);

/** \brief se_FiRaLite_API_InitiateTransaction
 * The INITIATE TRANSACTION command is issued
 * to begin a transaction with the counterpart device
 *
 *
 * @param[in]  session_ctx   session context
 * @param[in]  oid_entries   reference to OID entries
 * @param[in]  oid_entries_count number of OID entries
 * @param[in]  pSessionId    reference to the UWB session id
 * @param[in]  sessionIdLen  length of the UWB session id
 * @param[out]  pRspData     Response data
 * @param[out]  pRspDataLen  Response data Length
 *
 * @return     The APDU Transceive Status.
 */
smStatus_t se_FiRaLite_API_InitiateTransaction(pSe05xSession_t session_ctx,
    se_firelite_oid_entry *oid_entries,
    const size_t oid_entries_count,
    uint8_t *pSessionId,
    const size_t sessionIdLen,
    uint8_t *pRspData,
    size_t *pRspDataLen);

/** \brief se_FiRaLite_API_InitiateTransaction_extended
 * The INITIATE TRANSACTION command is issued
 * to begin a transaction with the counterpart device for transit use case
 *
 *
 * @param[in]  session_ctx   session context
 * @param[in]  oid_entries   reference to OID entries
 * @param[in]  oid_entries_count number of OID entries
 * @param[in]  pSessionId    reference to the UWB session id
 * @param[in]  sessionIdLen  length of the UWB session id
 * @param[out]  pRspData     Response data
 * @param[out]  pRspDataLen  Response data Length
 * @param[in]   P1_value     P1 value
 * @param[in]  pChallenge1   reference to Challenge1
 * @param[in]  challenge1Len  length of Challenge1
 *
 * @return     The APDU Transceive Status.
 */
smStatus_t se_FiRaLite_API_InitiateTransaction_extended(pSe05xSession_t session_ctx,
    se_firelite_oid_entry *oid_entries,
    const size_t oid_entries_count,
    uint8_t *pSessionId,
    const size_t sessionIdLen,
    uint8_t *pRspData,
    size_t *pRspDataLen,
    uint8_t P1_value,
    uint8_t *pChallenge1,
    const size_t challenge1Len);

/** \brief se_FiRaLite_API_Dispatch
 * The DISPATCH command is used to transfer command/responses to the FiRaLite Applet.
 * Any command received over an out-of-band channel, shall be passed on to the FiRaLite
 * applet using the DISPATCH command
 *
 *
 * @param[in]  session_ctx      session context
 * @param[in]  pCmdData    command Buffer
 * @param[in]  cmdDataLen    command Buffer length
 * @param[out]  pRspData     Response data
 * @param[out]  pRspDataLen  Response data Length
 *
 * @return     The APDU Transceive Status.
 */
smStatus_t se_FiRaLite_API_Dispatch(
    pSe05xSession_t session_ctx, uint8_t *pCmdData, const size_t cmdDataLen, uint8_t *pRspData, size_t *pRspDataLen);

/** \brief se_FiRaLite_API_Tunnel
 * The TUNNEL command is used to wrap application specific data
 * that is exchanged over an OoB channel.
 *
 *
 * @param[in]  session_ctx      session context
 * @param[in]  pCmdData      command Buffer
 * @param[in]  cmdDataLen    command Buffer length
 * @param[out]  pRspData     Response data
 * @param[out]  pRspDataLen  Response data Length
 *
 * @return     The APDU Transceive Status.
 */
smStatus_t se_FiRaLite_API_Tunnel(
    pSe05xSession_t session_ctx, uint8_t *pCmdData, const size_t cmdDataLen, uint8_t *pRspData, size_t *pRspDataLen);

/** \brief se_FiRaLite_API_RemoteGetData
 * GET DATA is used to read one or more data elements from the currently selected ADF
 * data structure from remote device.
 *
 *
 * @param[in]  pInBuf              command Buffer
 * @param[in]  inBufLen            command Buffer length
 * @param[out]  pRspData           Response data
 * @param[out]  pRspDataLen        Response data Length
 *
 * @return     The operation status.
 */
smStatus_t se_FiRaLite_API_RemoteGetData(
    const uint8_t *pInBuf, const size_t inBufLen, uint8_t *pRspData, size_t *pRspDataLen);

/** \brief se_FiRaLite_API_RemotePutData
 * The PUT DATA command is used to write one data element into the
 * currently selected ADF data for remote device.
 *
 *
 * @param[in]  pInBuf              command Buffer
 * @param[in]  inBufLen            command Buffer length
 * @param[out]  pRspData           Response data
 * @param[out]  pRspDataLen        Response data Length
 *
 * @return     The operation status.
 */
smStatus_t se_FiRaLite_API_RemotePutData(
    const uint8_t *pInBuf, const size_t inBufLen, uint8_t *pRspData, size_t *pRspDataLen);

/** \brief se_FiRaLite_API_LocalGetData
 * The GET DATA command is used to get data from FiraLite Applet for
 * local device. It cannot be used to read ADF data.
 *
 * @param[in]  session_ctx      session context
 * @param[in]  tagMSB        P1 Value
 * @param[in]  tagLSB        P2 Value
 * @param[out]  pRspData     Response data
 * @param[out]  pRspDataLen  Response data Length
 *
 * @return     The operation status.
 */
smStatus_t se_FiRaLite_API_LocalGetData(
    pSe05xSession_t session_ctx, uint8_t tagMSB, uint8_t tagLSB, uint8_t *pRspData, size_t *pRspDataLen);

/** \brief se_FiRaLite_API_LocalPutData
 * The PUT DATA command is used to put data structure for currently selected ADF
 * for local SE.
 *
 *
 * @param[in]  session_ctx      session context
 * @param[in]  pInBuf              command Buffer
 * @param[in]  inBufLen            command Buffer length
 *
 * @return     The operation status.
 */
smStatus_t se_FiRaLite_API_LocalPutData(pSe05xSession_t session_ctx, const uint8_t *pInBuf, const size_t inBufLen);

/**
 * @}
 */

#endif /* SE_FIRALITE_API_H */
