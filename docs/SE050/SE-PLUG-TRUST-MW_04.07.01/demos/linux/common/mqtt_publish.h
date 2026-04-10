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

#ifndef _MQTT_PUBLISH
#define _MQTT_PUBLISH

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

static struct
{
    char address[address_size];
    char clientid[clientid_size];
    char *keypath;
    char *rootpath;
    char topic[topic_size];
    char *payload;
    char *devcert;
    char username[username_size];
} opts;

int Publish(char *payload, int payload_size);

#endif //_MQTT_PUBLISH