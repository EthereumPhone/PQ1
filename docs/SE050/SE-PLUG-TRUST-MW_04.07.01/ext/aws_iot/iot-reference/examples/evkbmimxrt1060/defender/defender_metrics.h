/*
 * Copyright (C) 2021 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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

#ifndef _DEFENDER_METRICS_H
#define _DEFENDER_METRICS_H

/* Standard includes. */
#include <stdint.h>

/**
 * Struct definitions below represents standard metrics defined by the device
 * defender service specification.
 * https://docs.aws.amazon.com/iot/latest/developerguide/detect-device-side-metrics.html#DetectMetricsMessagesSpec
 *
 */

/**
 * @brief Represents the network statistics for an interface at the physical level.
 */
typedef struct NetworkStats
{
    uint32_t ulBytesReceived;   /**< Number of bytes received. */
    uint32_t ulBytesSent;       /**< Number of bytes sent. */
    uint32_t ulPacketsReceived; /**< Number of packets (ethernet frames) received. */
    uint32_t ulPacketsSent;     /**< Number of packets (ethernet frames) sent. */
} NetworkStats_t;

/**
 * @brief Represents an established TCP connection.
 */
typedef struct TCPConnection
{
    uint32_t ulLocalIPAddr;  /**< Local IPV4 address of a connection in network-byte order. */
    uint32_t ulRemoteIPAddr; /**< Remote IPV4 address of a connection in network-byte order. */
    uint16_t usLocalPort;    /**< Local port for a connection. */
    uint16_t usRemotePort;   /**< Remote port for a connection. */
} TCPConnection_t;


/**
 * @brief Struct represents all the metrics sent to device defender service.
 */
typedef struct DefenderMetrics
{
    TCPConnection_t * pxEstablishedConnectionsList;
    uint32_t ulEstablishedConnectionsListLength;
    uint16_t * pusOpenTCPPortsList;
    uint32_t ulNumOpenTCPPorts;
    uint16_t * pusOpenUDPPortsList;
    uint32_t ulNumOpenUDPPorts;
    NetworkStats_t xNetworkStats;
} DefenderMetrics_t;


#endif /* ifndef _DEFENDER_METRICS_H */
