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

#define OPT_REGISTRATION_ID "registration_id"
#define OPT_JSON_FILE "json"
#define OPT_KEY_FILE "keypath"
#define OPT_ROOT_CERT_FILE "rootpath"
#define OPT_DEVICE_CERT_FILE "devcert"
#define OPT_ID_SCOPE "id_scope"

extern azure_opts opts;

void Usage()
{
    printf("azure_imx_register \n");
    printf("\t--%-25s configuration file containing options\n", OPT_JSON_FILE " <filename>");
    printf("\t--%-25s registration id\n",                       OPT_REGISTRATION_ID " <id>");
    printf("\t--%-25s private key file in PEM format\n",        OPT_KEY_FILE " <filename>");
    printf("\t--%-25s root CA file of Azure in PEM format\n",   OPT_ROOT_CERT_FILE " <filename>");
    printf("\t--%-25s device certificate in PEM format\n",      OPT_DEVICE_CERT_FILE " <filename>");
    printf("\t--%-25s id scope of NXP-DPS in azure IoT\n",      OPT_ID_SCOPE " <id_scope>");
}


bool calculate_username(const char * idscope, const char *deviceid)
{
    size_t n = snprintf(opts.username,
        sizeof(opts.username),
        "%s/registrations/%s/api-version=2018-11-01&ClientVersion=1.4.0",
        idscope,
        deviceid);
    if (n > sizeof(opts.username)) {
        printf(
            "Error, buffer for storing idscope in address was too "
            "small.\n");
        return false;
    }
    return true;
}


bool get_registration_params_file(char * filename)
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

    char idscope[256];
    char registrationId[256];
    char key[256];
    char cert[256];
    char root[256];

    if (!get_json_tagValue(json_file, OPT_REGISTRATION_ID, registrationId) ||
        !get_json_tagValue(json_file, OPT_ID_SCOPE, idscope) ||
        !get_json_tagValue(json_file, OPT_KEY_FILE, key) ||
        !get_json_tagValue(json_file, OPT_DEVICE_CERT_FILE, cert) ||
        !get_json_tagValue(json_file, OPT_ROOT_CERT_FILE, root))
    {
        printf("File missing required parameters!\n");
        free(json_file);
        return false;
    }

    free(json_file);

    strcpy(opts.address, MQTT_REGISTER_URL_AZURE);
    strcpy((char *restrict) & opts.clientid, registrationId);
    strcpy((char *restrict) & opts.keypath, key);
    strcpy((char *restrict) & opts.devcert, cert);
    strcpy((char *restrict) & opts.rootpath, root);

    if (!calculate_username(idscope, opts.clientid))
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
    if (argc < 2) {
        return false;
    }
    int pos = 1;
    if (strcmp(argv[pos], "--" OPT_JSON_FILE) == 0) {
        if (++pos < argc) {
            char * filename = argv[pos];
            printf("Reading parameters from json file %s\n", filename);
            if (get_registration_params_file(filename))
            {
                return true;
            }
        }
        exit(EXIT_FAILURE);
    }

    char *deviceid;
    char idscope[257];
    bool hasIdScope = false;
    bool hasRegisterId = false;
    bool hasKeyPath = false;
    bool hasCertPath = false;
    bool hasRootCertPath = false;

    while (pos < argc) {
        if (strcmp(argv[pos], "--" OPT_REGISTRATION_ID) == 0) {
            if (++pos < argc) {
                deviceid = argv[pos];
                printf("Registration ID: %s \n", deviceid);
                hasRegisterId = true;
            }
            else
                return false;
        }
        else if (strcmp(argv[pos], "--" OPT_KEY_FILE) == 0) {
            if (++pos < argc) {
                strcpy((char *restrict) & opts.keypath, argv[pos]);
                hasKeyPath = true;
            }
            else
                return false;
        }
        else if (strcmp(argv[pos], "--" OPT_DEVICE_CERT_FILE) == 0) {
            if (++pos < argc) {
                strcpy((char *restrict) & opts.devcert, argv[pos]);
                hasCertPath = true;
            }
            else
                return false;
        }
        else if (strcmp(argv[pos], "--" OPT_ROOT_CERT_FILE) == 0) {
            if (++pos < argc) {
                strcpy((char *restrict) & opts.rootpath, argv[pos]);
                hasRootCertPath = true;
            }
            else
                return false;
        }
        else if (strcmp(argv[pos], "--" OPT_ID_SCOPE) == 0) {
            if (++pos < argc) {
                strcpy((char *restrict) & idscope, argv[pos]);
                hasIdScope = true;
            }
            else
                return false;
        }

        pos++;
    }

    if (!hasRegisterId || !hasKeyPath || !hasCertPath || !hasRootCertPath || !hasIdScope)
    {
        printf("See usage\n");
        return false;
    }

    strcpy((char *restrict) & opts.clientid, deviceid);
    strcpy(opts.address, MQTT_REGISTER_URL_AZURE);

    if (!calculate_username(idscope, opts.clientid))
    {
        return false;
    }

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
        printf("keyref: %s\n", opts.keypath);
        printf("rootCA: %s\n", opts.rootpath);
        printf("devCert: %s\n", opts.devcert);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        OPENSSL_config(NULL);
#else
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
#endif
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_digests();
        OpenSSL_add_all_ciphers();
        int rc = -1;

        rc = register_device(true);
        printf("Publish done with error code : %d\n", rc);
    }
    else {
        Usage();
    }

    EVP_cleanup();
}
// [END iot_mqtt_run]
