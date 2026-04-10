/******************************************************************************
 * Copyright 2017 Google
 * Copyright 2019 NXP
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *****************************************************************************/

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "MQTTClient.h"
#include "jwt.h"
#include "openssl/conf.h"
#include "openssl/ec.h"
#include "openssl/evp.h"

#include "mqtt_publish.h"

static const int kQos = 1;
static const unsigned long kTimeout = 10000L;

static const unsigned long kInitialConnectIntervalMillis = 500L;
static const unsigned long kMaxConnectIntervalMillis = 6000L;
static const unsigned long kMaxConnectRetryTimeElapsedMillis = 900000L;
static const float kIntervalMultiplier = 1.5f;

volatile MQTTClient_deliveryToken deliveredtoken;
/**
 * Publish a given message, passed in as payload, to Cloud IoT Core using the
 * values passed to the sample, stored in the global opts structure. Returns
 * the result code from the MQTT client
 */
// [START iot_mqtt_publish]

void delivered(void *context, MQTTClient_deliveryToken dt)
{
    (void) (context);
    printf("Message with token value %d delivery confirmed\n", dt);
    deliveredtoken = dt;
}

int msgarrvd(
    void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
    (void) (context);
    (void) (topicLen);
    int i;
    char *payloadptr;

    printf("Message arrived\n");
    printf("     topic: %s\n", topicName);
    printf("   message: ");

    payloadptr = message->payload;
    for (i = 0; i < message->payloadlen; i++) {
        putchar(*payloadptr++);
    }
    putchar('\n');
    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}

void connlost(void *context, char *cause)
{
    (void) (context);
    printf("\nConnection lost\n");
    printf("     cause: %s\n", cause);
}

int Publish(char *payload, int payload_size)
{
    int rc = -1;
    MQTTClient client = {0};
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token = {0};

    if ((MQTTClient_create(&client,
            opts.address,
            opts.clientid,
            MQTTCLIENT_PERSISTENCE_NONE,
            NULL)) != MQTTCLIENT_SUCCESS) {
        printf("MQTTClient_create failed \n");
        exit(EXIT_FAILURE);
    }
    conn_opts.keepAliveInterval = 60;
    conn_opts.cleansession = 1;
    conn_opts.reliable = 0;
    conn_opts.username = opts.username;
    conn_opts.password = NULL;
    MQTTClient_SSLOptions sslopts = MQTTClient_SSLOptions_initializer;

    sslopts.enableServerCertAuth = 0;
    sslopts.trustStore = opts.rootpath;
    sslopts.privateKey = opts.keypath;
    sslopts.keyStore = opts.devcert;
    conn_opts.ssl = &sslopts;

    unsigned long retry_interval_ms = kInitialConnectIntervalMillis;
    unsigned long total_retry_time_ms = 0;
    MQTTClient_setCallbacks(client, NULL, connlost, msgarrvd, delivered);
    while (
        (rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
        if (rc == 3) { // connection refused: server unavailable
            sleep(retry_interval_ms / 1000);
            total_retry_time_ms += retry_interval_ms;
            if (total_retry_time_ms >= kMaxConnectRetryTimeElapsedMillis) {
                printf("Failed to connect, maximum retry time exceeded.");
                exit(EXIT_FAILURE);
            }
            retry_interval_ms *= kIntervalMultiplier;
            if (retry_interval_ms > kMaxConnectIntervalMillis) {
                retry_interval_ms = kMaxConnectIntervalMillis;
            }
        }
        else {
            printf("Failed to connect, return code %d\n", rc);
            exit(EXIT_FAILURE);
        }
    }

    pubmsg.payload = payload;
    pubmsg.payloadlen = payload_size;
    pubmsg.qos = kQos;
    pubmsg.retained = 0;
    rc = MQTTClient_publishMessage(client, opts.topic, &pubmsg, &token);
    printf("MQTTClient_publishMessage done with error %d\n", rc);
    if (rc != MQTTCLIENT_SUCCESS) {
        exit(EXIT_FAILURE);
    }
    printf(
        "Waiting for up to %lu seconds for publication of %s\n"
        "on topic %s for client with ClientID: %s\n",
        (kTimeout / 1000),
        opts.payload,
        opts.topic,
        opts.clientid);
    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);

    return rc;
}
// [END iot_mqtt_publish]