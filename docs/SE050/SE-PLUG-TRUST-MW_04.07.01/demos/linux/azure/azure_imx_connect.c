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

// [START iot_mqtt_include]
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
#include "openssl/conf.h"
#include "openssl/ec.h"
#include "openssl/evp.h"

#include "mqtt_azure.h"
// [END iot_mqtt_include]

#define TRACE 1 /* Set to 1 to enable tracing */

extern azure_opts opts;

void Usage()
{
    printf("azure_imx_connect \\\n");
    printf("\t--payload \"Message to publish\"\\\n");
    printf("\t--deviceid <your device id>\\\n");
    printf("\t--keypath <e.g. ./ec_private.pem>\\\n");
    printf("\t--rootpath root CA file of Azure in PEM format\n\n");
    printf("\t--devcert device certificate in PEM format\n\n");
    printf("\t--hubname azure IoT hub name\n\n");
    printf("\t--username azure IoT user name\n\n");
}

bool calculate_url(char* hubname, char * deviceid)
{
    size_t n = snprintf(opts.address,
        sizeof(opts.address),
        "ssl://%s:8883",
        hubname);
    size_t m = snprintf(opts.username,
        sizeof(opts.username),
        "%s/%s/?api-version=2018-06-30",
        hubname,
        deviceid);

    if (n > sizeof(opts.address) || m > sizeof(opts.username)) {
        printf(
            "Error, buffer for storing hubname/username was too small.\n");
        return false;
    }
    return true;
}

bool calculate_topic(char * deviceid)
{
    size_t n = snprintf(opts.topic,
        sizeof(opts.topic),
        "devices/%s/messages/events/",
        deviceid);
    if (n > sizeof(opts.topic)) {
        printf("Error, buffer for storing device ID was too small.\n");
        return false;
    }
    return true;
}

bool get_connection_params_file(char * filename)
{
    FILE *fk = fopen(filename, "rb");
    if (fk == NULL)
    {
        printf("Can not open the file [%s]\n", filename);
        return false;
    }
    fseek(fk, 0, SEEK_END);
    long json_file_len = ftell(fk);
    fseek(fk, 0, SEEK_SET);
    char *json_file = malloc(json_file_len +1);
    fread(json_file, 1, json_file_len, fk);
    json_file[json_file_len] = 0;
    fclose(fk);

    printf("file contents %s\n", json_file);

    char assignedHub[256];
    char deviceId[256];
    char payload[256];
    char key[256];
    char cert[256];
    char root[256];

    if (!get_json_tagValue(json_file, "deviceId", deviceId) ||
        !get_json_tagValue(json_file, "assignedHub", assignedHub) ||
        !get_json_tagValue(json_file, "payload", payload) ||
        !get_json_tagValue(json_file, "keypath", key) ||
        !get_json_tagValue(json_file, "devcert", cert) ||
        !get_json_tagValue(json_file, "rootpath", root))
    {
        printf("File missing required parameters!\n");
        free(json_file);
        return false;
    }

    free(json_file);

    strcpy((char *restrict) & opts.payload, payload);
    strcpy((char *restrict) & opts.clientid, deviceId);
    strcpy((char *restrict) & opts.keypath, key);
    strcpy((char *restrict) & opts.devcert, cert);
    strcpy((char *restrict) & opts.rootpath, root);

    if (!calculate_url(assignedHub, deviceId) || !calculate_topic(deviceId))
    {
        return false;
    }
    return true;
}

/**
 * Helper to parse arguments passed to app. Returns false if there are missing
 * or invalid arguments; otherwise, returns true indicating the caller should
 * free the calculated client ID placed on the opts structure.
 *
 * TODO: (class) Consider getopt
 */
// [START iot_mqtt_opts]
bool GetOpts(int argc, char **argv)
{
    int pos = 1;
    if (argc < 2) {
        return false;
    }

    if (strcmp(argv[pos], "--json") == 0) {
        if (++pos < argc) {
            char * filename = argv[pos];
            printf("Reading parameters from json file %s\n", filename);
            if (get_connection_params_file(filename))
            {
                return true;
            }
        }
        exit(EXIT_FAILURE);
    }
    char *deviceid;
    char hubname[257];
    bool hasPayload = false;

    while (pos < argc) {
        if (strcmp(argv[pos], "--payload") == 0) {
            if (++pos < argc) {
                //opts.payload = argv[pos];
                strcpy((char *restrict) & opts.payload, argv[pos]);
                hasPayload = true;
            }
            else {
                return false;
            }
        }
        if (strcmp(argv[pos], "--deviceid") == 0) {
            if (++pos < argc) {
                deviceid = argv[pos];
            }
            else
                return false;
        }
        else if (strcmp(argv[pos], "--keypath") == 0) {
            if (++pos < argc) {
                strcpy((char *restrict) & opts.keypath, argv[pos]);
                //opts.keypath = argv[pos];
            }
            else {
                return false;
            }
        }
        else if (strcmp(argv[pos], "--devcert") == 0) {
            if (++pos < argc) {
                strcpy((char *restrict) & opts.devcert, argv[pos]);
                //opts.devcert = argv[pos];
            }
            else {
                return false;
            }
        }
        else if (strcmp(argv[pos], "--rootpath") == 0) {
            if (++pos < argc) {
                strcpy((char *restrict) & opts.rootpath, argv[pos]);
                //opts.rootpath = argv[pos];
            }
            else {
                return false;
            }
        }
        else if (strcmp(argv[pos], "--topic") == 0) {
            if (++pos < argc) {
                strcpy((char *restrict) & opts.topic, argv[pos]);
            }
            else {
                return false;
            }
        }
        else if (strcmp(argv[pos], "--hubname") == 0) {
            if (++pos < argc) {
                strcpy((char *restrict) & hubname, argv[pos]);
            }
            else {
                return false;
            }
        }
        else if (strcmp(argv[pos], "--username") == 0) {
            if (++pos < argc) {
                strcpy((char *restrict) & opts.username, argv[pos]);
            }
            else {
                return false;
            }
        }

        pos++;
    }

    if (!hasPayload) {
        printf("Payload not passed\n");
        return false;
    }

    if (!calculate_url(hubname, deviceid) || !calculate_topic(deviceid))
    {
        return false;
    }

    strcpy((char *restrict) & opts.clientid, deviceid);
    return true;
}
// [END iot_mqtt_opts]

/**
 * Connects MQTT client and transmits payload.
 */
// [START iot_mqtt_run]
int main(int argc, char *argv[])
{
    if (GetOpts(argc, argv)) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        OPENSSL_config(NULL);
#else
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
#endif
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_digests();
        OpenSSL_add_all_ciphers();
        int rc = -1;

        rc = register_device(false);
        printf("Publish done with error code : %d\n", rc);
    }
    else {
        Usage();
    }

    EVP_cleanup();
}
// [END iot_mqtt_run]
