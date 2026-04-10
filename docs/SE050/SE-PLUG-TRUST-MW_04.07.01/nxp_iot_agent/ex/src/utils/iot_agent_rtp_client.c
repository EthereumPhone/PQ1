/*
 * Copyright 2020-2021,2023-2025 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
 // Includes in case of Windows build
#include <ws2tcpip.h>

#elif !(defined(USE_RTOS) && (USE_RTOS == 1))
 // Includes in case of Linux build
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <pthread.h>
#include <dirent.h>
#else
 // Includes in case of FreeRTOS
#ifndef INC_FREERTOS_H /* Header guard of FreeRTOS */
#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#endif /* INC_FREERTOS_H */
#if defined(LPC_ENET)
#include "lwip/opt.h"
#include "lwip/tcpip.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include <lwip/netdb.h>
#include "../include/lwip/sockets.h"
#elif defined(LPC_WIFI)
#include "iot_wifi.h"
#include "wifi_config.h"
#include "serial_mwm.h"
#endif

#endif

#include <nxp_iot_agent_common.h>
#include <nxp_iot_agent_session.h>
#include <nxp_iot_agent_macros.h>
#include <iot_agent_rtp_client.h>

#define RTP_MAX_BUFFER_SIZE 892U
static ex_sss_boot_ctx_t gex_sss_boot_ctx;
size_t successful_provisionings = 0U;
size_t failed_provisionings = 0U;

iot_agent_status_t initialize_client_connection(const char* hostname, const char* server_port, int* pSocket_id);
iot_agent_status_t process_result(remote_provisioning_TLV_t* resultTlv, size_t* num_objects);
iot_agent_status_t sendResponse(remote_provisioning_TLV_t* tlv, int socket_id);
iot_agent_status_t network_reads(remote_provisioning_TLV_t* tlv, int socket_id);
iot_agent_status_t send_apdu(remote_provisioning_TLV_t* apdu, remote_provisioning_TLV_t* response, ex_sss_boot_ctx_t* boot_context);

#if ! defined(_WIN32)
#    if ! defined closesocket
#        define closesocket(a) close(a)
#    endif
#endif

#if defined(LPC_WIFI)
int send(int s, char *buf, int len, int flags) {
	int ret = 0;

    ret = mwm_send(s, (void*)buf, len);

    if (ret < 0)
    {
        return(-1);
    }

    return(ret);
}

int recv(int fd, char *buf, int len, int flags) {
	int ret = 0;

	ret = mwm_recv_timeout(fd, (void*)buf, len, 15000);

    if (ret <= 0)
    {
        return(-1);
    }

    return ret;
}

/*
 * Gracefully close the connection
 */
int closesocket(int s)
{
    if (s == -1)
        return -1;

    return mwm_close(s);
}


uint16_t htons(uint16_t const net) {
    uint8_t data[2] = {};
    memcpy(&data, &net, sizeof(data));

    return ((uint8_t)data[1] << 0)
        | ((uint8_t)data[0] << 8);
}
uint16_t ntohs(uint16_t const netshort ) {
    uint8_t data[2] = {};
    memcpy(&data, &netshort, sizeof(data));

    return ((uint8_t)data[1] << 0)
        | ((uint8_t)data[0] << 8);
}
uint32_t htonl(uint32_t const net) {
    uint8_t data[4] = {};
    memcpy(&data, &net, sizeof(data));

    return ((uint32_t)data[3] << 0)
        | ((uint32_t)data[2] << 8)
        | ((uint32_t)data[1] << 16)
        | ((uint32_t)data[0] << 24);
}
#endif

// This function initialize the server connection
iot_agent_status_t initialize_client_connection(const char* hostname, const char* server_port, int* pSocket_id)
{
    printf("Connecting to Provisioning Server at [%s] on port [%s]\n", hostname, server_port);

    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
#if !defined(LPC_WIFI)
    struct addrinfo hints;
    struct addrinfo *servinfo = NULL;
    int rv;
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Error in WSA startup");
    }
#endif

    /* Do name resolution with both IPv6 and IPv4 */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // only listen on ipv4 addresses
    hints.ai_socktype = SOCK_STREAM;
    rv = getaddrinfo(hostname, server_port, &hints, &servinfo);
    ASSERT_OR_EXIT_MSG(rv == 0, "getaddrinfo Failed");
#if defined(_WIN32) || defined(_WIN64)
    unsigned int socket_id = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
	if (socket_id > INT32_MAX) {
		IOT_AGENT_ERROR("Error in opening socket\n");
		if (closesocket(socket_id) != 0) {
			IOT_AGENT_ERROR("Error while closing socket\n");
		}
		goto exit;
	}
	*pSocket_id = socket_id;
#else
	*pSocket_id = (int)socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
	ASSERT_OR_EXIT_MSG(*pSocket_id >= 0, "Error in opening socket\n");
#endif

	ASSERT_OR_EXIT_MSG(servinfo->ai_addrlen <= INT32_MAX, "Error in casting of address");

    //client establishes a connection with server
    if (connect(*pSocket_id, servinfo->ai_addr, servinfo->ai_addrlen) < 0)
    {
        EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Socket connection failed");
    }
    IOT_AGENT_INFO("Connection to provisioning server established!");

exit:
    freeaddrinfo(servinfo);
    return agent_status;
#else

    int ret = 0;
    mwm_sockaddr_t http_srv_addr = {0};

    strcpy(http_srv_addr.host, hostname);
    http_srv_addr.port = atoi(server_port);

    ret = mwm_wlan_status();

    ASSERT_OR_EXIT_MSG(ret == MWM_CONNECTED, "WiFi not connected\n");

    printf("Connecting to to %s %d\n", hostname, server_port);

    *pSocket_id = mwm_socket(MWM_TCP);

    ASSERT_OR_EXIT_MSG(*pSocket_id >= 0, "Error in opening socket\n");

    ret = mwm_connect(*pSocket_id, &http_srv_addr, sizeof(http_srv_addr));

    ASSERT_OR_EXIT_MSG(ret == 0, "qcom_connect failed");

    IOT_AGENT_INFO("Connection to provisioning server established!");

exit:
    return agent_status;
#endif
}

iot_agent_status_t process_result(remote_provisioning_TLV_t* resultTlv, size_t* num_objects)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    size_t read_id_list_bytes = resultTlv->length;
    *num_objects = read_id_list_bytes / 4U;
    uint32_t * readid = malloc(read_id_list_bytes);
    ASSERT_OR_EXIT_MSG(readid != NULL, "malloc failed");
    memcpy(readid, (resultTlv->payload), read_id_list_bytes);
    for (size_t i = 0U; i < *num_objects; i++)
    {
        printf("[0x%X]\n", htonl(*(readid + i)));
    }
    free(readid);
exit:
    return agent_status;
}

iot_agent_status_t sendResponse(remote_provisioning_TLV_t* tlv, int socket_id)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    uint16_t len = tlv->length;
    tlv->length = htons(len);

    int flags = 0;
	ASSERT_OR_EXIT_MSG(socket_id >= 0, "Error in the socket id");
    if (send(socket_id, (char*)tlv, 4U, flags) != 4)
    {
        EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Failure while sending Tag-Length");
    }
    if (send(socket_id, (char*)tlv->payload, (size_t)len, flags) != len)
    {
        EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Failure while sending payload");
    }
exit:
    return agent_status;
}

iot_agent_status_t network_reads(remote_provisioning_TLV_t* tlv, int socket_id)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    uint16_t cmd;
    uint16_t len;
	ASSERT_OR_EXIT_MSG(socket_id >= 0, "Error in the socket id");

	int recv_length = recv(socket_id, (char*)&cmd, sizeof(tlv->cmd), 0);
	ASSERT_OR_EXIT_MSG((recv_length >= 0) && (recv_length == sizeof(tlv->cmd)), "Failure while receiving Tag");

    tlv->cmd = ntohs(cmd);

	recv_length = recv(socket_id, (char*)&len, sizeof(tlv->length), 0);
	ASSERT_OR_EXIT_MSG((recv_length >= 0) && (recv_length == sizeof(tlv->length)), "Failure while receiving Length");

    tlv->length = ntohs(len);

    if (tlv->length == 0)
    {
        return IOT_AGENT_SUCCESS;
    }
    if (tlv->length > RTP_MAX_BUFFER_SIZE)
    {
        EXIT_STATUS_MSG(IOT_AGENT_ERROR_MEMORY, "Buffer is smaller than data from server");
    }

    if (recv(socket_id, (char*)tlv->payload, (size_t)tlv->length, 0) != tlv->length)
    {
        EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Failure while receiving payload");
    }
exit:
    return agent_status;
}

iot_agent_status_t send_apdu(remote_provisioning_TLV_t* apdu, remote_provisioning_TLV_t* response, ex_sss_boot_ctx_t* boot_context)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&(boot_context->session);
    size_t len = RTP_MAX_BUFFER_SIZE;
    if (SW_OK != DoAPDUTxRx(&(pSession->s_ctx), apdu->payload, (size_t)apdu->length, response->payload, &len))
    {
        IOT_AGENT_ERROR("Error while sending TAG_APDU_CMD");
    }
	if (len >= UINT16_MAX) {
		IOT_AGENT_ERROR("Len is to big to be casted to uint16_t");
		return IOT_AGENT_FAILURE;
	}
    response->length = (uint16_t)len;
    return agent_status;
}

iot_agent_status_t remote_provisioning_start(const char* hostname, const char* port)
{
     iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    // socket file descriptor
    int socket_fd = -1;
    int done = 0;
    remote_provisioning_TLV_t cmd_tlv = { 0, 0, NULL };
    remote_provisioning_TLV_t response_tlv = { 0, 0, NULL };

    const char* ghostname = hostname;
    const char* gport = port;

    agent_status = initialize_client_connection(ghostname, gport, &socket_fd);
    AGENT_SUCCESS_OR_EXIT_MSG("Error in client connection initialization");

    agent_status = iot_agent_session_init(0U, NULL, &gex_sss_boot_ctx);
    AGENT_SUCCESS_OR_EXIT_MSG("Error opening session with SE");

    //allocate memory for command and response payloads
    cmd_tlv.payload = malloc(RTP_MAX_BUFFER_SIZE);
    response_tlv.payload = malloc(RTP_MAX_BUFFER_SIZE);
    ASSERT_OR_EXIT_MSG((cmd_tlv.payload != NULL) && (response_tlv.payload != NULL), "malloc failed");

    while (!done)
    {
        agent_status = network_reads(&cmd_tlv, socket_fd);
        AGENT_SUCCESS_OR_EXIT_MSG("Error while reading from server");
        switch (cmd_tlv.cmd)
        {
        case TAG_START:
            response_tlv.cmd = htons(TAG_START);
            response_tlv.length = htons(0x00U);
            agent_status = sendResponse(&response_tlv, socket_fd);
            AGENT_SUCCESS_OR_EXIT_MSG("Error while sending response");
            break;
        case TAG_APDU_CMD:
            agent_status = send_apdu(&cmd_tlv, &response_tlv, &gex_sss_boot_ctx);
            AGENT_SUCCESS_OR_EXIT_MSG("Error while sending apdu to SE");
            response_tlv.cmd = htons(TAG_APDU_RESPONSE);
            agent_status = sendResponse(&response_tlv, socket_fd);
            AGENT_SUCCESS_OR_EXIT_MSG("Error while sending response");
            break;
        case TAG_PROVISIONED_OBJECTS_LIST:
            agent_status = process_result(&cmd_tlv, &successful_provisionings);
            AGENT_SUCCESS_OR_EXIT_MSG("Error while sending apdu to SE");
            response_tlv.cmd = htons(TAG_PROVISIONED_OBJECTS_LIST_RESPONSE);
            response_tlv.length = 0x00U;
            agent_status = sendResponse(&response_tlv, socket_fd);
            AGENT_SUCCESS_OR_EXIT_MSG("Error while sending response");
            break;
        case TAG_FAILED_PROVISIONED_LIST:
            agent_status = process_result(&cmd_tlv, &failed_provisionings);
#if defined(USE_RTOS) && (USE_RTOS == 1)
            IOT_AGENT_INFO("Received %u failed provisioned objects.", failed_provisionings);
#else
            IOT_AGENT_INFO("Received %zu failed provisioned objects.", failed_provisionings);
#endif
            AGENT_SUCCESS_OR_EXIT_MSG("Error while sending apdu to SE");
            response_tlv.cmd = htons(TAG_FAILED_PROVISIONED_LIST_RESPONSE);
            response_tlv.length = 0x00U;
            agent_status = sendResponse(&response_tlv, socket_fd);
            AGENT_SUCCESS_OR_EXIT_MSG("Error while sending response");
            break;
        case TAG_DONE:
#if defined(USE_RTOS) && (USE_RTOS == 1)
            IOT_AGENT_INFO("Received %u provisioned objects.\nClosing connection", successful_provisionings);
#else
            IOT_AGENT_INFO("Received %zu provisioned objects.\nClosing connection", successful_provisionings);
#endif
            done = 1;
            break;
        default:
            IOT_AGENT_ERROR("Protocol Error: Unknown Tag received from Server");
            break;
        }
    }
exit:
    free(cmd_tlv.payload);
    free(response_tlv.payload);
    iot_agent_session_disconnect(&gex_sss_boot_ctx);
    if (socket_fd >= 0)
    {
        if (closesocket(socket_fd) != 0)
            IOT_AGENT_ERROR("Error while closing socket\n");
    }
#ifdef _WIN32
    if (WSACleanup() != 0) {
        IOT_AGENT_ERROR("WSACleanup failed");
    }
#endif
    return agent_status;
}
