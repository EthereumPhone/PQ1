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
 * @file transport_interface_test.h
 * @brief Test function for transport interface test.
 */
#ifndef TRANSPORT_INTERFACE_TEST_H
#define TRANSPORT_INTERFACE_TEST_H

/* Standard header includes. */
#include <stdint.h>

/* Include for platform functions */
#include "platform_function.h"

/* Include for network connection. */
#include "network_connection.h"

/* Include for transport interface. */
#include "transport_interface.h"

/**
 * @brief A struct representing transport interface test parameters.
 */
typedef struct TransportTestParam
{
    TransportInterface_t * pTransport;          /**< @brief Transport interface structure to test. */
    NetworkConnectFunc_t pNetworkConnect;       /**< @brief Network connect function pointer. */
    NetworkDisconnectFunc_t pNetworkDisconnect; /**< @brief Network disconnect function pointer. */
    void * pNetworkCredentials;                 /**< @brief Network credentials for network connection. */
    void * pNetworkContext;                     /**< @brief Primary network context. */
    void * pSecondNetworkContext;               /**< @brief Secondary network context. */
} TransportTestParam_t;

/**
 * @brief Customers need to implement this fuction by filling in parameters
 * in the provided TransportTestParam_t.
 *
 * @param[in] pTestParam a pointer to TransportTestParam_t struct to be filled out by
 * caller.
 */
void SetupTransportTestParam( TransportTestParam_t * pTestParam );

/**
 * @brief Run Transport interface tests. This function should be called after calling `setupTransportTestParam()`.
 *
 * @return Negative value if the transport test execution config is not set. Otherwise,
 * number of failure test cases is returned.
 */
int RunTransportInterfaceTest( void );

#endif /* TRANSPORT_INTERFACE_TEST_H */
