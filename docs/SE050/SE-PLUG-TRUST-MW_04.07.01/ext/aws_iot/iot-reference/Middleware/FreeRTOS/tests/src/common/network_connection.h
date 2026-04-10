/*
 * FreeRTOS FreeRTOS LTS Qualification Tests preview
 * Copyright (C) 2022 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file network_connection.h
 * @brief Network connect/disconnect functions for test appliction.
 */
#ifndef NETWORK_CONNECTION_H
#define NETWORK_CONNECTION_H

/**
 * @brief Struct to hold the host information for connection.
 */
typedef struct TestHostInfo
{
    const char * pHostName; /**< @brief Server host name. The string should be nul terminated. */
    uint16_t port;          /**< @brief Server port in host-order. */
} TestHostInfo_t;

/**
 * @brief Network connect return status.
 */
typedef enum NetworkConnectStatus
{
    NETWORK_CONNECT_SUCCESS = 0,         /**< @brief Function successfully completed. */
    NETWORK_CONNECT_INVALID_PARAMETER,   /**< @brief At least one parameter was invalid. */
    NETWORK_CONNECT_INSUFFICIENT_MEMORY, /**< @brief Insufficient memory required to establish connection. */
    NETWORK_CONNECT_INVALID_CREDENTIALS, /**< @brief Provided credentials were invalid. */
    NETWORK_CONNECT_HANDSHAKE_FAILED,    /**< @brief Performing TLS handshake with server failed. */
    NETWORK_CONNECT_INTERNAL_ERROR,      /**< @brief A call to a system API resulted in an internal error. */
    NETWORK_CONNECT_FAILURE              /**< @brief Initial connection to the server failed. */
} NetworkConnectStatus_t;

/**
 * @brief A function pointer type for function that establish a network connection
 * with a server.
 *
 * @param[in] pNetworkContext Network context to setup the connection.
 * @param[in] pHostInfo Host information for the connection.
 * @param[in] pNetworkCredentials Network credentials for the connection.
 *
 * @return NETWORK_CONNECT_SUCCESS if the network connection is established successfully.
 * Otherwise, return other network connect status to indicate error.
 */
typedef NetworkConnectStatus_t ( * NetworkConnectFunc_t )( void * pNetworkContext,
                                                           TestHostInfo_t * pHostInfo,
                                                           void * pNetworkCredentials );

/**
 * @brief A function pointer type for function that disconnect a previously established
 * network connection with a server.
 *
 * @param[in] pNetworkContext Network context to disconnect the connection.
 */
typedef void ( * NetworkDisconnectFunc_t )( void * pNetworkContext );

#endif /* NETWORK_CONNECTION_H */
