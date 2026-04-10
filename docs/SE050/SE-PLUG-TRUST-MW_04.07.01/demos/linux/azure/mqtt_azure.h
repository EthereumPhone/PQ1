/******************************************************************************
 * Copyright 2017 Google
 * Copyright 2019,2020 NXP
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

#ifndef _MQTT_PUBLISH
#define _MQTT_PUBLISH

//Azure IoTHub global endpoint URL
#define MQTT_REGISTER_URL_AZURE "ssl://global.azure-devices-provisioning.net:8883"

//string for publishing initial request for registration
#define MQTT_REGISTRATION_MSG_AZURE "$dps/registrations/PUT/iotdps-register/?$rid=1"

//string for publishing with operationID after initail request
#define MQTT_PUBLISH_MSG_OPID_AZURE "$dps/registrations/GET/iotdps-get-operationstatus/?$rid=2&operationId="

//string for subscribing topic to receive registration messages from Azure
#define MQTT_SUBSCRIBE_MSG_AZURE "$dps/registrations/res/#"

//Fixed timeout in seconds for registration
#define REGISTRATION_TIMEOUT 30

//global states for registration process
typedef enum { ASSIGNING, STOP } register_state;

enum
{
    address_maxlen = 256,
    address_size
};
enum
{
    clientid_maxlen = 256,
    clientid_size
};
enum
{
    topic_maxlen = 256,
    topic_size
};
enum
{
    username_maxlen = 256,
    username_size
};

typedef struct
{
    char address[address_size];
    char clientid[clientid_size];
    char keypath[256];
    char rootpath[256];
    char topic[topic_size];
    char payload[256];
    char devcert[256];
    char username[username_size];
} azure_opts;

int register_device(bool registerDevice);
bool get_json_tagValue(char *js, const char * key, char * value);
bool write_registration_configuration(char* payload);


#endif //_MQTT_PUBLISH
