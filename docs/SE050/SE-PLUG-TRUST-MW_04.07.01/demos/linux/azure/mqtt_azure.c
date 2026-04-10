/******************************************************************************
 * Copyright 2017 Google
 * Copyright 2019,2020,2023 NXP
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
#define _XOPEN_SOURCE 500
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "MQTTClient.h"
#include "jwt.h"
#include "jansson.h"
#include "openssl/conf.h"
#include "openssl/ec.h"
#include "openssl/evp.h"

#include "mqtt_azure.h"

static const int kQos = 1;
static const unsigned long kTimeout = 10000L;

static const unsigned long kInitialConnectIntervalMillis = 500L;
static const unsigned long kMaxConnectIntervalMillis = 6000L;
static const unsigned long kMaxConnectRetryTimeElapsedMillis = 900000L;
static const float kIntervalMultiplier = 1.5f;

volatile MQTTClient_deliveryToken deliveredtoken;
register_state state = ASSIGNING;
volatile uint16_t msgnum = 0;

azure_opts opts;

/**
 * 1) Register Azure device:
 *  Required parameters (either in JSON file or via command line):
 *   -Registration ID of the device
 *   -Id_Scope the Azuer IoTHub DPS
 *   -Path to keyref file
 *   -Path to device certificate file
 *   -Path to azure root certificate file
 * 2) Publish a given message, passed in as payload, to Cloud IoT Core using the
 * values passed to the sample, stored in the global opts structure. Returns
 * the result code from the MQTT client
 */
// [START iot_mqtt_register]

bool get_json_tagValue(char *payload, const char * key, char * value)
{
    json_error_t error;
    json_t *root = json_loads( payload, 0, &error );
    json_t *value_json;

    if ( !root )
    {
        printf("Error while loading json data\n");
        return 0;
    }

    value_json = json_object_get(root, key);
    value = json_string_value(value_json);

    json_decref(root);

    if (value == NULL) {
        return false;
    }
    return true;
}

bool write_registration_configuration(char* payload)
{
    char assignedhub[256];
    char deviceId[256];
    char registrationId[256];
    char status[256];
    if (!get_json_tagValue(payload, "registrationId", registrationId) ||
        !get_json_tagValue(payload, "status", status) ||
        !get_json_tagValue(payload, "assignedHub", assignedhub) ||
        !get_json_tagValue(payload, "deviceId", deviceId))
    {
        return false;
    }
    char * filename = malloc(strlen(deviceId) + 4);
    strcpy(filename, deviceId);
    filename = strcat(filename, ".txt");

    FILE* fp = fopen(filename, "wb");
    fprintf(fp, "{\n");
    fprintf(fp, "  \"assignedHub\": \"%s\",\n", assignedhub);
    fprintf(fp, "  \"deviceId\": \"%s\",\n", deviceId);
    fprintf(fp, "  \"registration_id\": \"%s\",\n", registrationId);
    fprintf(fp, "  \"status\": \"%s\",\n", status);
    fprintf(fp, "  \"keypath\": \"%s\",\n", opts.keypath);
    fprintf(fp, "  \"devcert\": \"%s\",\n", opts.devcert);
    fprintf(fp, "  \"rootpath\": \"%s\",\n", opts.rootpath);
    fprintf(fp, "  \"payload\": \"hello message from device %s\"\n", deviceId);
    fprintf(fp, "}");
    fclose(fp);
    return true;
}

void delivered(void *context, MQTTClient_deliveryToken dt)
{
    (void) (context);
    printf("Message with token value %d delivery confirmed\n", dt);
    deliveredtoken = dt;
}

int msgarrvd(
    void *client, char *topicName, int topicLen, MQTTClient_message *message)
{
    (void) (topicLen);
    int i;
    char *payloadptr;
    MQTTClient_deliveryToken token = { 0 };
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    pubmsg.payload = "";
    pubmsg.payloadlen = 0;
    pubmsg.qos = 1;
    pubmsg.retained = 0;

    printf("Message #%d arrived \n", msgnum++);
    printf("     topic: %s\n", topicName);
    printf("   message: ");
    payloadptr = message->payload;
    for (i = 0; i < message->payloadlen; i++) {
        putchar(*payloadptr++);
    }
    putchar('\n');
    switch (state)
    {
    case ASSIGNING:
        pubmsg.qos = 1;
        char *message_ptr = malloc(message->payloadlen + 1);
        memcpy(message_ptr, message->payload, message->payloadlen);
        message_ptr[message->payloadlen] = '\0';
        char opid[256];
        char status[64];
        if (!(get_json_tagValue(message_ptr, "status", status) &&
            get_json_tagValue(message_ptr, "operationId", opid)))
        {
            printf("Registartion failed with message: %s\n", message_ptr);
            exit(EXIT_FAILURE);
        }
        if (!strcmp(status, "assigning"))
        {
            char *topicOperationId = malloc(strlen(MQTT_PUBLISH_MSG_OPID_AZURE) + strlen(opid) + 1); // +1 for the null-terminator
            if (topicOperationId == NULL)
            {
                printf("malloc error\n");
                exit(EXIT_FAILURE);
            }
            strcpy(topicOperationId, MQTT_PUBLISH_MSG_OPID_AZURE);
            strcat(topicOperationId, opid);
            // Prevent Throttling by backend: As per this link, maximum 5 requests per 10 seconds allowed:
            // https://github.com/MicrosoftDocs/azure-docs/blob/master/includes/iot-dps-limits.md
            // A better approach would be to react appropriately in case throttling occurs
            {
                struct timespec req;
                const struct timespec *pReq;

                req.tv_sec = 1;
                req.tv_nsec = 0;
                pReq = &req;
                for (unsigned int i = 0; i < (msgnum % 5); i++)
                {
                    nanosleep(pReq, NULL);
                }
            }
            int rc = MQTTClient_publishMessage((MQTTClient *)client, topicOperationId, &pubmsg, &token);
            if (rc != MQTTCLIENT_SUCCESS) {
                free(topicOperationId);
                exit(EXIT_FAILURE);
            }
            printf("Device State is assigning\n");
            state = ASSIGNING;
            free(topicOperationId);
        }
        else if (!strcmp(status, "assigned"))
        {
            printf("Device State is now ASSIGNED\n");
            if (!write_registration_configuration(message_ptr))
            {
                printf("Error while writing file\n");
                free(message_ptr);
                exit(EXIT_FAILURE);
            }
            state = STOP;
        }
        else
        {
            free(message_ptr);
            printf("Error while assigning\n");
            exit(EXIT_FAILURE);
        }
        free(message_ptr);
        break;
    case STOP:
        break;
    default:
        printf("Error state\n");
        exit(EXIT_FAILURE);
        break;
    }
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

int register_device(bool registerDevice)
{
    int rc = -1;
    MQTTClient client = {0};
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token = {0};

#ifdef DEBUG
    printf("MQTTClient_create opts.address = %s \n", opts.address);
    printf("MQTTClient_create opts.username = %s \n", opts.username);
    printf("MQTTClient_create opts.clientid = %s \n", opts.clientid);
    printf("MQTTClient_create opts.keypath = %s \n", opts.keypath);
    printf("MQTTClient_create opts.devcert = %s \n", opts.devcert);
    printf("MQTTClient_create opts.rootpath = %s \n", opts.rootpath);
#endif
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
    MQTTClient_setCallbacks(client, client, connlost, msgarrvd, delivered);
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
    pubmsg.qos = kQos;
    pubmsg.retained = 0;

    if (registerDevice)
    {
        pubmsg.payload = "";
        pubmsg.payloadlen = 0;
        rc = MQTTClient_publishMessage(client, MQTT_REGISTRATION_MSG_AZURE, &pubmsg, &token);

        if (rc != MQTTCLIENT_SUCCESS) {
            exit(EXIT_FAILURE);
        }

        MQTTClient_subscribe(client, MQTT_SUBSCRIBE_MSG_AZURE, 1);
        struct timespec req;
        const struct timespec *pReq;

        req.tv_sec = 1;
        req.tv_nsec = 0;
        pReq = &req;

        unsigned int registration_time_sec = 0;
        while (state != STOP) {
            nanosleep(pReq, NULL);
            registration_time_sec++;
            if (registration_time_sec > REGISTRATION_TIMEOUT)
            {
                printf("Failed to complete registration, maximum wait time exceeded.\n");
                exit(EXIT_FAILURE);
            }
        }
        MQTTClient_unsubscribe(client, MQTT_SUBSCRIBE_MSG_AZURE);
    }
    else
    {
        pubmsg.payload = opts.payload;
        pubmsg.payloadlen = strlen(opts.payload);
        state = STOP;
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
    }
    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);

    return rc;
}
// [END iot_mqtt_register]
