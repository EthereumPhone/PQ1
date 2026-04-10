/*
 * Copyright 2020-2021,2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef _IOT_AGENT_RTP_CLIENT_H_
#define _IOT_AGENT_RTP_CLIENT_H_
#include <nxp_iot_agent.h>
#include <nxp_iot_agent_config.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! @defgroup edgelock2go_agent_rtp_client Offline remote trust provisioning Client application
*
* @ingroup edgelock2go_agent_rtp_client
*
* @brief Provides functionality of offline remote trust provisioning client.
*
*/
typedef enum
{
    TAG_START = 0x0000U,
    TAG_APDU_CMD = 0x8000U,
    TAG_APDU_RESPONSE = 0x8100U,
    TAG_PROVISIONED_OBJECTS_LIST = 0x8200U,
    TAG_PROVISIONED_OBJECTS_LIST_RESPONSE = 0x8300U,
    TAG_FAILED_PROVISIONED_LIST = 0x8400U,
    TAG_FAILED_PROVISIONED_LIST_RESPONSE = 0x8500U,
    TAG_DONE = 0xFF00U
} REMOTE_PROVISIONING_CMD;

typedef struct remote_provisioning_TLV
{
    uint16_t cmd;
    uint16_t length;
    uint8_t* payload;
} remote_provisioning_TLV_t;

#if defined(USE_RTOS) && (USE_RTOS == 1)
typedef struct rtos_arguments
{
    const char * hostname;
    const char *port;
} rtos_arguments_t;

#endif

/*!
* @addtogroup edgelock2go_agent_rtp_client
* @{
*/

#if defined(USE_RTOS) && (USE_RTOS == 1)

#if defined(LPC_WIFI)
int send(int s, char *buf, int len, int flags);
int recv(int fd, char *buf, int len, int flags);
uint16_t htons(uint16_t const net);
uint32_t htonl(uint32_t const net);
#endif //LPC_WIFI

#endif

/**
 * @brief Start remote_provisioning_client.
 * @param[in] hostname Hostname of RTP server.
 * @param[in] port Port on which RTP server is running.
 * @return Success remote provisioning exits withot error.
 */
iot_agent_status_t remote_provisioning_start(const char* hostname, const char* port);

#ifdef __cplusplus
} // extern "C"
#endif

/*!
*@}
*/ /* end of edgelock2go_agent_rtp_client */

#endif // #ifndef _IOT_AGENT_RTP_CLIENT_H_
