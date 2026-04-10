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
 * @file mqtt_test.h
 * @brief Test functions for MQTT test.
 */
#ifndef MQTT_TEST_H
#define MQTT_TEST_H

#include "transport_interface.h"
#include "network_connection.h"
#include "core_mqtt.h"

typedef struct MqttTestParam
{
    TransportInterface_t * pTransport; /**< @brief pNetworkContext, send, receive fields of the TransportInterface_t struct should be filled out. */
    NetworkConnectFunc_t pNetworkConnect;
    NetworkDisconnectFunc_t pNetworkDisconnect;
    void * pNetworkCredentials;
    void * pNetworkContext;
    void * pSecondNetworkContext;
    MQTTGetCurrentTimeFunc_t pGetTimeMs; /**< @brief The getTimeFunction for MQTT_Init API. */
} MqttTestParam_t;

/**
 * @brief Customers need to implement this fuction by filling in parameters
 * in the provided MqttTestParam_t.
 *
 * @param[in] pTestParam a pointer to MqttTestParam_t struct to be filled out by
 * caller.
 *
 */
void SetupMqttTestParam( MqttTestParam_t * pTestParam );

/**
 * @brief Run MQTT test. This function should be called after calling `SetupMqttTest()`.
 *
 * @return Negative value if the transport test execution config is not set. Otherwise,
 * number of failure test cases is returned.
 */
int RunMqttTest( void );

#endif /* MQTT_TEST_H */
