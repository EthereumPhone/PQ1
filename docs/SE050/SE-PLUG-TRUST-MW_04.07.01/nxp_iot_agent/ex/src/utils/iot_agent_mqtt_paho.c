/* Copyright 2020-2025 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sm_types.h"

#ifdef _WIN32
#include <direct.h>
#include <dirent_win32.h>
#else /* ! _WIN32 */
 /* AX_EMBEDDED is defined and set by sm_types.h. Use after including sm_types.h */
#if AX_EMBEDDED
// Do not include dirent.h for KSDK
#else /* ! AX_EMBEDDED */
#include <dirent.h>
#endif /* AX_EMBEDDED */
#endif /* _WIN32 */

#include <iot_agent_mqtt_paho.h>
#include <nxp_iot_agent.h>
#include <nxp_iot_agent_macros.h>
#include <nxp_iot_agent_utils.h>
#include <nxLog_App.h>

#if IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE
#include <nxp_iot_agent_session.h>
#include <network_openssl.h>
#include <MQTTClient.h>

#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL
#include <openssl/ossl_typ.h>
#include <openssl/engine.h>
#endif

#ifdef NXP_IOT_AGENT_USE_COREJSON
#include "core_json.h"
#else
#include "jsmn.h"
#endif

#endif

#if defined(__linux__) || defined(__CYGWIN__) || defined(__clang__)
#define DO_MKDIR(DIR_NAME) \
    mkdir((DIR_NAME), S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IXOTH);
#else
#define DO_MKDIR(DIR_NAME) \
    _mkdir((DIR_NAME));
#endif

static const char path_separator =
#ifdef _WIN32
'\\';
#else
'/';
#endif

const char* goutput_directory = "output";
const char* goutput_directory_rtp = "output_rtp";

#define SERVICE_CONFIGURATION_PATTERN "config_%" PRIu64 ".txt"
#define SERVICE_CERTIFICATE_PATTERN "cert_%" PRIu64 ".pem"
#define SERVICE_KEYREF_PATTERN "keyref_%" PRIu64 ".pem"
#define SERVICE_SERVER_CERT_PATTERN "server_cert_%s_%" PRIu64 ".pem"
#define SERVICE_METADATA_PATTERN "metadata_%" PRIu64 ".txt"

#if IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE
typedef struct mqtt_connection_params
{
    char address[256];
    char username[256];
    char topic[256];
    char *clientid;
    char *keypath;
    char *rootpath;
    char *payload;
    char *devcert;
} mqtt_connection_params_t;

typedef enum { NOT_ASSIGNED, ASSIGNING, ASSIGNED } registration_state;

typedef struct mqtt_azure_params
{
    registration_state state;
    char assignedHub[256];
    char operationId[256];
    char deviceId[256];
} mqtt_azure_params_t;

volatile MQTTClient_deliveryToken deliveredtoken;


void delivered(void *context, MQTTClient_deliveryToken dt);
void connlost(void *context, char *cause);
void write_error_logs(const char* message);
void delete_old_service_files(const char* output_directory);
void delete_old_service_files_folders(const char* output_directory);
int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message);
int azure_callback(void *context, char *topicName, int topicLen, MQTTClient_message *message);
int network_openssl_engine_session_connect_mqtt();
int network_openssl_engine_session_disconnect_mqtt();
#ifdef NXP_IOT_AGENT_USE_COREJSON
static iot_agent_status_t get_value_from_tag(char *js, size_t js_size, const char * key, size_t key_size, char * value, size_t max_value_size);
#else
iot_agent_status_t get_value_from_tag(char *js, const char * key, char * value);
#endif
iot_agent_status_t connect_and_publish_message(mqtt_connection_params_t* connection_params);
iot_agent_status_t iot_agent_mqtt_connect_aws(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params);
iot_agent_status_t iot_agent_mqtt_register_azure(mqtt_connection_params_t* connection_params, mqtt_azure_params_t* azure_params);
iot_agent_status_t iot_agent_mqtt_connect_azure(mqtt_connection_params_t* connection_params, mqtt_azure_params_t* azure_params);
iot_agent_status_t iot_agent_mqtt_register_and_connect_azure(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params);
iot_agent_status_t iot_agent_mqtt_connect_custom(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params);
iot_agent_status_t iot_agent_mqtt_test(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params);
iot_agent_status_t write_service_configuration_aws(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename, const char* certificate_filename, const char* keyref_filename, const char* server_cert_filename);
iot_agent_status_t write_service_configuration_azure(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename, const char* certificate_filename, const char* keyref_filename, const char* server_cert_filename);
iot_agent_status_t write_service_configuration_custom(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename, const char* certificate_filename, const char* keyref_filename, const char* server_cert_filename);
iot_agent_status_t write_service_metadata(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename);
iot_agent_status_t write_service_configuration(const nxp_iot_ServiceDescriptor* service_descriptor,
    char *filename, char* certificate_filename, const char* keyref_filename, const char* server_cert_filename);

#ifdef NXP_IOT_AGENT_USE_COREJSON
static iot_agent_status_t get_value_from_tag(char *js, size_t js_size, const char * key, size_t key_size, char * value, size_t max_value_size) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	char* value_ptr;
	size_t value_size = 0U;

	ASSERT_OR_EXIT_MSG(js != NULL, "The input pointer is NULL");
	ASSERT_OR_EXIT_MSG(key != NULL, "The input pointer is NULL");
	ASSERT_OR_EXIT_MSG(value != NULL, "The input pointer is NULL");
	ASSERT_OR_EXIT_MSG(JSON_Search(js, js_size, key, key_size, &value_ptr, &value_size) == JSONSuccess, "Error in JSON string parsing");
	ASSERT_OR_EXIT_MSG(value_size < max_value_size, "To less space allocated for the value buffer");
	strncpy(value, value_ptr, value_size);
exit:
	return agent_status;
}
#else
#define JSMN_TOKENS_SIZE 50U
iot_agent_status_t get_value_from_tag(char *js, const char * key, char * value)
{
    jsmn_parser p;
    jsmntok_t tokens[JSMN_TOKENS_SIZE] = {0}; /* We expect no more than 50 JSON tokens */
    jsmn_init(&p);
    int count = jsmn_parse(&p, js, strlen(js), tokens, JSMN_TOKENS_SIZE);
    for (int i = 1; i < count; i += 2)
    {
        jsmntok_t *t = &tokens[i];
        char *tag = js + t->start;
        if (!memcmp(tag, key, (size_t)(t->end - t->start)))
        {
            t = &tokens[i + 1];
            memcpy(value, js + t->start, (size_t)(t->end - t->start));
            value[t->end - t->start] = '\0';
            return IOT_AGENT_SUCCESS;
        }
    }
    return IOT_AGENT_FAILURE;
}
#endif

void delivered(void *context, MQTTClient_deliveryToken dt)
{
    (void)(context);
    LOG_I("Message with token value %d delivery confirmed\n", dt);
    deliveredtoken = dt;
}

void connlost(void *context, char *cause)
{
    (void)(context);
    LOG_E("\nConnection lost\n");
    LOG_E("     cause: %s\n", cause);
}

int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
    (void)(context);
    (void)(topicLen);

	if ((message->payloadlen < 0) || (message->payloadlen > (INT32_MAX - 1)))
	{
		LOG_E("\nError in the payload length\n");
		return 0;
	}
    char *payload = malloc((size_t)message->payloadlen + 1U);
    if (payload == NULL)
    {
        return 0;
    }
    memcpy(payload, message->payload, (size_t)message->payloadlen);
    payload[message->payloadlen] = '\0';

    LOG_I("Message arrived\n");
    LOG_I("     topic: %s\n", topicName);
    LOG_I("   message: %s", payload);

    free(payload);
    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}

int azure_callback(void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
    (void)(context);
    (void)(topicLen);
    char opid[256 - sizeof(IOT_AGENT_MQTT_OPID_TOPIC_AZURE)] = {0};
    char status[64] = {0};

	if ((message->payloadlen < 0) || (message->payloadlen > (INT32_MAX - 1))) {
		return 0;
	}
	size_t payloadLength = (size_t)message->payloadlen + 1U;

    char *payload = malloc(payloadLength);
    if (payload == NULL)
    {
        return 0;
    }

    memcpy(payload, message->payload, (size_t)message->payloadlen);
    payload[message->payloadlen] = '\0';

    LOG_I("Message arrived\n");
    LOG_I("     topic: %s\n", topicName);
    LOG_I("   message: %s", payload);

#ifdef NXP_IOT_AGENT_USE_COREJSON
	get_value_from_tag(payload, payloadLength, "operationId", strlen("operationId"), opid, sizeof(opid));
	get_value_from_tag(payload, payloadLength, "status", strlen("status"), status, sizeof(status));
#else
    get_value_from_tag(payload, "operationId", opid);
    get_value_from_tag(payload, "status", status);
#endif

    mqtt_azure_params_t* context_cb = (mqtt_azure_params_t*)context;
    LOG_I("reading opid from context: [%s]", context_cb->operationId);

    if (strcmp(status, "assigning") == 0)
    {
        LOG_I("Device State is now ASSIGNING");
        strncpy(context_cb->operationId, IOT_AGENT_MQTT_OPID_TOPIC_AZURE, sizeof(IOT_AGENT_MQTT_OPID_TOPIC_AZURE));
        strncat(context_cb->operationId, opid, sizeof(opid));

        context_cb->state = ASSIGNING;
    }
    else if (strcmp(status, "assigned") == 0)
    {
        LOG_I("Device State is now ASSIGNED");
#ifdef NXP_IOT_AGENT_USE_COREJSON
		char* registrationState = malloc(payloadLength);

		memset(registrationState, '\0', payloadLength);
		get_value_from_tag(payload, payloadLength, "registrationState", strlen("registrationState"), registrationState, payloadLength);
		get_value_from_tag(registrationState, strlen(registrationState), "assignedHub", strlen("assignedHub"), context_cb->assignedHub, sizeof(context_cb->assignedHub));
		get_value_from_tag(registrationState, strlen(registrationState), "deviceId", strlen("deviceId"), context_cb->deviceId, sizeof(context_cb->deviceId));
		free(registrationState);
#else
        get_value_from_tag(payload, "assignedHub", context_cb->assignedHub);
        get_value_from_tag(payload, "deviceId", context_cb->deviceId);
#endif

        context_cb->state = ASSIGNED;
    }

    free(payload);

    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}

iot_agent_status_t connect_and_publish_message(mqtt_connection_params_t* connection_params)
{
    iot_agent_status_t agent_status = IOT_AGENT_FAILURE;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_SSLOptions sslopts = MQTTClient_SSLOptions_initializer;
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token = { 0 };
    MQTTClient client = { 0 };
    int rc;
    size_t retry = 0U;

    rc = MQTTClient_create(&client, connection_params->address,
        connection_params->clientid, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    ASSERT_OR_EXIT_MSG(rc == MQTTCLIENT_SUCCESS, "MQTTClient_create Failed, return code [%d]", rc);

    conn_opts.keepAliveInterval = 60;
    conn_opts.cleansession = 1;
    conn_opts.reliable = 0;
    conn_opts.username = connection_params->username;
    conn_opts.password = NULL;

    sslopts.enableServerCertAuth = 1;
    sslopts.trustStore = connection_params->rootpath;
    sslopts.privateKey = connection_params->keypath;
    sslopts.keyStore = connection_params->devcert;
    conn_opts.ssl = &sslopts;

    MQTTClient_setCallbacks(client, NULL, connlost, msgarrvd, delivered);

    while (
        ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)) {
        if (rc == 3 && retry++ < 3U) { // connection refused: server unavailable
            SLEEP_SEC(1U);
        }
        else {
            IOT_AGENT_ERROR("Failed to connect, return code %d\n", rc);
            goto exit;
        }
    }

    pubmsg.payload = connection_params->payload;
    pubmsg.payloadlen = (int)strlen(connection_params->payload);
    pubmsg.qos = 1;
    pubmsg.retained = 0;
    for (int i = 0; i < 3; i++)
    {
        rc = MQTTClient_publishMessage(client, connection_params->topic, &pubmsg, &token);
        ASSERT_OR_EXIT_MSG(rc == MQTTCLIENT_SUCCESS, "MQTTClient_publishMessage Failed, return code [%d]", rc);
        IOT_AGENT_INFO("Message successfully published");
    }
    agent_status = IOT_AGENT_SUCCESS;
exit:
    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
    return agent_status;
}

iot_agent_status_t iot_agent_mqtt_connect_aws(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params)
{
    iot_agent_status_t agent_status;
    int n = snprintf(connection_params->address,
        sizeof(connection_params->address),
        "ssl://%s:8883",
        service_descriptor->hostname);
    if (n > (int)sizeof(connection_params->address)) {
        LOG_E("Error, buffer for storing URL was too small.\n");
        return IOT_AGENT_FAILURE;
    }

    strncpy(connection_params->username, IOT_AGENT_MQTT_USERNAME_AWS, sizeof(IOT_AGENT_MQTT_USERNAME_AWS));
    strncpy(connection_params->topic, IOT_AGENT_MQTT_TOPIC_AWS, sizeof(IOT_AGENT_MQTT_TOPIC_AWS));
    connection_params->clientid = service_descriptor->client_id;
    connection_params->payload = IOT_AGENT_MQTT_PAYLOAD;

    IOT_AGENT_INFO("\nConnecting to AWS service: %s", service_descriptor->client_id)
    agent_status = connect_and_publish_message(connection_params);
    AGENT_SUCCESS_OR_EXIT();
exit:
    return agent_status;

}

iot_agent_status_t iot_agent_mqtt_register_azure(mqtt_connection_params_t* connection_params, mqtt_azure_params_t* azure_params)
{
    iot_agent_status_t agent_status = IOT_AGENT_FAILURE;
    MQTTClient client = { 0 };
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token = { 0 };
    int rc = -1;
    uint16_t maxWaiting = 0U;
    size_t retry = 3U;

    if ((rc = MQTTClient_create(&client, connection_params->address, connection_params->clientid,
        MQTTCLIENT_PERSISTENCE_NONE, NULL)) != MQTTCLIENT_SUCCESS)
    {
        IOT_AGENT_ERROR("MQTTClient_create Failed, return code %d\n", rc);

    }

    conn_opts.keepAliveInterval = 60;
    conn_opts.cleansession = 1;
    conn_opts.reliable = 0;
    conn_opts.username = connection_params->username;
    conn_opts.password = NULL;
    MQTTClient_SSLOptions sslopts = MQTTClient_SSLOptions_initializer;

    sslopts.enableServerCertAuth = 0;
    sslopts.trustStore = connection_params->rootpath;
    sslopts.privateKey = connection_params->keypath;
    sslopts.keyStore = connection_params->devcert;
    conn_opts.ssl = &sslopts;

    MQTTClient_setCallbacks(client, azure_params, connlost, azure_callback, delivered);

    while (
        ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) && retry--) {
        if (rc == 3) { // connection refused: server unavailable
            SLEEP_SEC(1U);
        }
        else {
			EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Failed to connect, return code %d\n", rc);
        }
    }

    rc = MQTTClient_subscribe(client, IOT_AGENT_MQTT_SUBSCRIBE_TOPIC_AZURE, 1);
    ASSERT_OR_EXIT_MSG(rc == MQTTCLIENT_SUCCESS, "MQTTClient_subscribe Failed, return code [%d]", rc);

    azure_params->state = NOT_ASSIGNED;
    strncpy(azure_params->operationId, "testing", sizeof("testing"));
    pubmsg.qos = 1;

    rc = MQTTClient_publishMessage(client, IOT_AGENT_MQTT_REGISTRATION_TOPIC_AZURE, &pubmsg, &token);
    ASSERT_OR_EXIT_MSG(rc == MQTTCLIENT_SUCCESS, "MQTTClient_publishMessage while registering failed, return code [%d]", rc);

    while (azure_params->state != ASSIGNING && maxWaiting < 10U)
    {
        SLEEP_SEC(1U);
        maxWaiting++;
    }

    maxWaiting = 0U;
    while (azure_params->state != ASSIGNED && maxWaiting < 10U)
    {
        SLEEP_SEC(1U * (maxWaiting + 1U));
        rc = MQTTClient_publishMessage(client, azure_params->operationId, &pubmsg, &token);
        ASSERT_OR_EXIT_MSG(rc == MQTTCLIENT_SUCCESS, "MQTTClient_publishMessage while assigning failed, return code [%d]", rc);
        maxWaiting++;
    }

    if (azure_params->state == ASSIGNED)
    {
        IOT_AGENT_INFO("\nAzure registration is successful for [%s]", azure_params->deviceId)
            agent_status = IOT_AGENT_SUCCESS;
    }

    LOG_I("Disconnect MQTT connection...");

exit:
    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
    return agent_status;
}

iot_agent_status_t iot_agent_mqtt_connect_azure(mqtt_connection_params_t* connection_params, mqtt_azure_params_t* azure_params)
{
    iot_agent_status_t agent_status;
    int m = snprintf(connection_params->address,
        sizeof(connection_params->address),
        "ssl://%s:8883",
        azure_params->assignedHub);
	ASSERT_OR_EXIT_MSG(m >= 0, "Error in the snprint execution");
    int n = snprintf(connection_params->username,
        sizeof(connection_params->username),
        "%s/%s/?api-version=2018-06-30",
        azure_params->assignedHub,
        azure_params->deviceId);
	ASSERT_OR_EXIT_MSG(n >= 0, "Error in the snprint execution");
    int o = snprintf(connection_params->topic,
        sizeof(connection_params->topic),
        "devices/%s/messages/events/",
        azure_params->deviceId);
	ASSERT_OR_EXIT_MSG(o >= 0, "Error in the snprint execution");
    if (m > (int)sizeof(connection_params->address) || n > (int)sizeof(connection_params->username) || o > (int)sizeof(connection_params->topic)) {
        LOG_E("Error, buffer for storing address/username was too small.\n");
        return IOT_AGENT_FAILURE;
    }

    connection_params->clientid = azure_params->deviceId;
    connection_params->payload = IOT_AGENT_MQTT_PAYLOAD;
    IOT_AGENT_INFO("Connecting to Azure service: %s", azure_params->deviceId)
    agent_status = connect_and_publish_message(connection_params);
exit:
    return agent_status;
}

iot_agent_status_t iot_agent_mqtt_register_and_connect_azure(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params)
{
    iot_agent_status_t agent_status;
    mqtt_azure_params_t azure_params = { 0 };
    int m = snprintf(connection_params->address,
        sizeof(connection_params->address),
        "ssl://%s:8883",
        service_descriptor->azure_global_device_endpoint);
	ASSERT_OR_EXIT_MSG(m >= 0, "Error in the snprint execution");

    int n = snprintf(connection_params->username,
        sizeof(connection_params->username),
        "%s/registrations/%s/api-version=2018-11-01&ClientVersion=1.4.0",
        service_descriptor->azure_id_scope,
        service_descriptor->azure_registration_id);
	ASSERT_OR_EXIT_MSG(n >= 0, "Error in the snprint execution");

    if (m > (int)sizeof(connection_params->address) || n > (int)sizeof(connection_params->username)) {
        LOG_E("Error, buffer for storing hubname/username was too small.\n");
        return IOT_AGENT_FAILURE;
    }
    connection_params->clientid = service_descriptor->azure_registration_id;
    connection_params->payload = "HelloMessage";

    agent_status = iot_agent_mqtt_register_azure(connection_params, &azure_params);
    AGENT_SUCCESS_OR_EXIT();
    agent_status = iot_agent_mqtt_connect_azure(connection_params, &azure_params);
    AGENT_SUCCESS_OR_EXIT();
exit:
    return agent_status;
}

iot_agent_status_t iot_agent_mqtt_connect_custom(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params)
{
    iot_agent_status_t agent_status;
    int n = snprintf(connection_params->address,
        sizeof(connection_params->address),
        "ssl://%s:8883",
        service_descriptor->hostname);
    if (n > (int)sizeof(connection_params->address)) {
        LOG_E("Error, buffer for storing URL was too small.\n");
        return IOT_AGENT_FAILURE;
    }
    strncpy(connection_params->username, IOT_AGENT_MQTT_USERNAME_CUSTOM, sizeof(IOT_AGENT_MQTT_USERNAME_CUSTOM));
    strncpy(connection_params->topic, IOT_AGENT_MQTT_TOPIC_CUSTOM, sizeof(IOT_AGENT_MQTT_TOPIC_CUSTOM));
    connection_params->clientid = (service_descriptor->client_id != NULL) ? service_descriptor->client_id : "";
    connection_params->payload = IOT_AGENT_MQTT_PAYLOAD;

    IOT_AGENT_INFO("\nConnecting to custome service: %s", service_descriptor->hostname)
    agent_status = connect_and_publish_message(connection_params);
    AGENT_SUCCESS_OR_EXIT();
exit:
    return agent_status;
}

int network_openssl_engine_session_connect_mqtt() {

    int network_status = NETWORK_STATUS_OK;
#if (OPENSSL_VERSION_NUMBER < 0x30000000) 
    ENGINE *e = ENGINE_by_id(NETWORK_OPENSSL_ENGINE_ID);
    NETWORK_ASSERT_OR_EXIT_MSG(e != NULL, "Error finding OpenSSL Engine by id (id = %s)\n", NETWORK_OPENSSL_ENGINE_ID);

    // NOTE: Open engine connection to SE via Engine control interface
    LOG_I("Open connection to secure element through Engine control interface (Engine=%s).\n", NETWORK_OPENSSL_ENGINE_ID);
    ENGINE_ctrl(e, ENGINE_CMD_BASE + 1, 0, NULL, NULL);

exit:
    ENGINE_free(e);
#endif
    return network_status;
}

int network_openssl_engine_session_disconnect_mqtt() {
    int network_status = NETWORK_STATUS_OK;
#if (OPENSSL_VERSION_NUMBER < 0x30000000) 

    ENGINE *e = ENGINE_by_id(NETWORK_OPENSSL_ENGINE_ID);
    NETWORK_ASSERT_OR_EXIT_MSG(e != NULL, "Error finding OpenSSL Engine by id (id = %s)\n", NETWORK_OPENSSL_ENGINE_ID);

    LOG_I("Close connection to secure element through Engine control interface (Engine=%s).\n", NETWORK_OPENSSL_ENGINE_ID);
    ENGINE_ctrl(e, ENGINE_CMD_BASE + 2, 0, NULL, NULL);

exit:
    ENGINE_free(e);
#endif
    return network_status;
}

static iot_agent_status_t iot_agent_mqtt_open_session_from_sss(iot_agent_keystore_t* keystore, openssl_network_context_t* network_context)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	int network_status = NETWORK_STATUS_OK;

	iot_agent_keystore_close_session(keystore);

	network_status = network_openssl_engine_session_connect(network_context);
	ASSERT_OR_EXIT_MSG(network_status == NETWORK_STATUS_OK, "network_openssl_engine_session_connect failed with 0x%08x.", network_status);
exit:
	return agent_status;
}

static iot_agent_status_t iot_agent_mqtt_open_session_from_keystore(iot_agent_keystore_t* keystore, openssl_network_context_t* network_context)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	int network_status = NETWORK_STATUS_OK;

	network_status = network_openssl_engine_session_disconnect(network_context);
	ASSERT_OR_EXIT_MSG(network_status == NETWORK_STATUS_OK, "network_openssl_engine_session_disconnect failed with 0x%08x.", network_status);

	agent_status = iot_agent_keystore_open_session(keystore);
	AGENT_SUCCESS_OR_EXIT_MSG("Failed to re-connect to Secure Element.")
exit:
	return agent_status;
}

iot_agent_status_t iot_agent_mqtt_test(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    switch (service_descriptor->service_type)
    {
    case nxp_iot_ServiceType_AWSSERVICE:
        agent_status = iot_agent_mqtt_connect_aws(service_descriptor, connection_params);
        break;
    case nxp_iot_ServiceType_AZURESERVICE:
        agent_status = iot_agent_mqtt_register_and_connect_azure(service_descriptor, connection_params);
        break;
    case nxp_iot_ServiceType_CUSTOMSERVICE:
        agent_status = iot_agent_mqtt_connect_custom(service_descriptor, connection_params);
        break;
    default:
        LOG_E("Invalid service type\n");
        break;
    }

    return agent_status;
}
#endif //IOT_AGENT_MQTT_CONNECTION_DEMO_ENABLE

void write_error_logs(const char* message)
{
#if (!AX_EMBEDDED)
    FILE* fp = fopen("output\\errors.log", "a");
    if (fp != NULL) {
		if (fprintf(fp, "Error: %s \n", message) < 0) {
			IOT_AGENT_ERROR("Error in fprintf funxtion");
		}
		if (fclose(fp) != 0) {
			IOT_AGENT_ERROR("Error in fclose funxtion");
		}
	}
#endif
}

void delete_old_service_files(const char* output_directory)
{
    DIR *dir;
    struct dirent *file;
    char filepath[256];
    if ((dir = opendir(output_directory)) != NULL)
    {
        while ((file = readdir(dir)) != NULL)
        {
            if (!strcmp(file->d_name, ".") || !strcmp(file->d_name, ".."))
            {
                continue;
            }

			if (snprintf(filepath, sizeof(filepath), "%s/%s", output_directory, file->d_name) < 0) {
				IOT_AGENT_ERROR("Error in the creation of the output directory");
			}

            if (remove(filepath) != 0)
            {
                closedir(dir);
                return;
            };
        }
        closedir(dir);
        return;
    }
	else if (errno == ENOENT) 
	{
		// do not print anything if directory doesn't exist
		return;
	}
    else
    {
        /* could not open directory */
        perror("");
        return;
    }
}

void delete_old_service_files_folders(const char* output_directory)
{
    DIR *dir;
    struct dirent *file;
    char subdir[256];
    if ((dir = opendir(output_directory)) != NULL)
    {
        while ((file = readdir(dir)) != NULL)
        {
            if (!strcmp(file->d_name, ".") || !strcmp(file->d_name, ".."))
            {
                continue;
            }
			if (snprintf(subdir, sizeof(subdir), "%s/%s", output_directory, file->d_name) < 0) {
				IOT_AGENT_ERROR("Error in building the output string");
			}
            delete_old_service_files(subdir);
        }
        delete_old_service_files(output_directory);
        closedir(dir);
        return;
    }
	else if (errno == ENOENT) 
	{
		// do not print anything if directory doesn't exist
		return;
	}
    else
    {
        /* could not open directory */
        perror("");
        return;
    }
}

iot_agent_status_t write_service_configuration_aws(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename, const char* certificate_filename, const char* keyref_filename, const char* server_cert_filename)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    const char* protocol = NULL;
    FILE* fp = NULL;

    ASSERT_OR_EXIT_MSG(service_descriptor->hostname != NULL, "Missing hostname.");
    ASSERT_OR_EXIT_MSG(service_descriptor->client_id != NULL, "Missing client_id.");
    agent_status = iot_agent_service_get_protocol_of_service_as_string(service_descriptor, &protocol);
    AGENT_SUCCESS_OR_EXIT();
    fp = fopen(filename, "w");
    ASSERT_OR_EXIT_MSG(fp != NULL, "Error opening file");

	ASSERT_OR_EXIT_MSG(fprintf(fp, "{\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"endpoint\": \"%s\",\n", service_descriptor->hostname) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"protocol\": \"%s\",\n", protocol) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"port\": %d,\n", service_descriptor->port) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"mqtt_port\": 8883,\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"https_port\": 443,\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"greengrass_discovery_port\": 8443,\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"root_ca_relative_path\": \"%s\",\n", server_cert_filename) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"device_certificate_relative_path\": \"%s\",\n", certificate_filename) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"device_private_key_relative_path\": \"%s\",\n", keyref_filename) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"tls_handshake_timeout_msecs\": 60000,\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"tls_read_timeout_msecs\": 2000,\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"tls_write_timeout_msecs\": 2000,\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"aws_region\": \"\",\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"aws_access_key_id\": \"\",\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"aws_secret_access_key\": \"\",\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"aws_session_token\": \"\",\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"client_id\": \"%s\",\n", service_descriptor->client_id) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"thing_name\": \"CppSDKTesting\",\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"is_clean_session\": true,\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"mqtt_command_timeout_msecs\": %d,\n", service_descriptor->timeout_ms) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"keepalive_interval_secs\": 600,\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"minimum_reconnect_interval_secs\": 1,\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"maximum_reconnect_interval_secs\": 128,\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"maximum_acks_to_wait_for\": 32,\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"action_processing_rate_hz\": 5,\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"maximum_outgoing_action_queue_length\": 32,\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"discover_action_timeout_msecs\": 300000\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "}") >= 0, "Error in fprintf execution");
exit:
	if (fp != NULL) {
		ASSERT_OR_EXIT_MSG(fclose(fp) == 0, "Error in fclose execution");
	}
    return agent_status;
}

iot_agent_status_t write_service_configuration_azure(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename, const char* certificate_filename, const char* keyref_filename, const char* server_cert_filename)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    FILE* fp = NULL;

    ASSERT_OR_EXIT_MSG(service_descriptor->azure_id_scope != NULL, "Missing azure_id_scope.");
    ASSERT_OR_EXIT_MSG(service_descriptor->azure_global_device_endpoint != NULL, "Missing azure_global_device_endpoint.");
    ASSERT_OR_EXIT_MSG(service_descriptor->azure_registration_id != NULL, "Missing azure_registration_id.");

    fp = fopen(filename, "w");
    ASSERT_OR_EXIT_MSG(fp != NULL, "Error opening file");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "{\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"id_scope\": \"%s\",\n", service_descriptor->azure_id_scope) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"global_device_endpoint\": \"%s\",\n", service_descriptor->azure_global_device_endpoint) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"registration_id\": \"%s\",\n", service_descriptor->azure_registration_id) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"devcert\": \"%s\",\n", certificate_filename) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"keypath\": \"%s\",\n", keyref_filename) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"rootpath\": \"%s\",\n", server_cert_filename) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "}") >= 0, "Error in fprintf execution");
exit:

	if (fp != NULL) {
		ASSERT_OR_EXIT_MSG(fclose(fp) == 0, "Error in fclose execution");
	}
    return agent_status;
}

iot_agent_status_t write_service_configuration_custom(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename, const char* certificate_filename, const char* keyref_filename, const char* server_cert_filename)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    const char* protocol = NULL;
    const char* hostname = "empty";
    FILE* fp = NULL;

    agent_status = iot_agent_service_get_protocol_of_service_as_string(service_descriptor, &protocol);
    AGENT_SUCCESS_OR_EXIT();

    if (service_descriptor->hostname != NULL)
        hostname = service_descriptor->hostname;

    fp = fopen(filename, "w");
    ASSERT_OR_EXIT_MSG(fp != NULL, "Error opening file");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "{\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"hostname\": \"%s\",\n", hostname) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"username\": \"use-token-auth\",\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"protocol\": \"%s\",\n", protocol) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"port\": \"%d\",\n", service_descriptor->port) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"devcert\": \"%s\",\n", certificate_filename) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"keypath\": \"%s\",\n", keyref_filename) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"payload\": \"HelloMessage\",\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"topic\": \"iot-2/evt/status/fmt/string\",\n") >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "  \"rootpath\": \"%s\",\n", server_cert_filename) >= 0, "Error in fprintf execution");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "}") >= 0, "Error in fprintf execution");

exit:
	if (fp != NULL) {
		ASSERT_OR_EXIT_MSG(fclose(fp) == 0, "Error in fclose execution");
	}
    return agent_status;
}

iot_agent_status_t write_service_metadata(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    const char * metadata = "{}";
    FILE* fp = NULL;

    if (service_descriptor->customer_metadata_json != NULL) {
        metadata = service_descriptor->customer_metadata_json;
    }

    fp = fopen(filename, "w");
    ASSERT_OR_EXIT_MSG(fp != NULL, "Error opening file");
	ASSERT_OR_EXIT_MSG(fprintf(fp, "%s\n", metadata) >= 0, "Error in fprintf execution");
exit:
	if (fp != NULL) {
		ASSERT_OR_EXIT_MSG(fclose(fp) == 0, "Error in fclose execution");
	}
    return agent_status;
}

iot_agent_status_t write_service_configuration(const nxp_iot_ServiceDescriptor* service_descriptor,
    char *filename, char* certificate_filename, const char* keyref_filename, const char* server_cert_filename)
{
    iot_agent_status_t agent_status = IOT_AGENT_FAILURE;
    ASSERT_OR_EXIT_MSG(service_descriptor->has_service_type, "Missing service type");

    switch (service_descriptor->service_type)
    {
    case nxp_iot_ServiceType_AWSSERVICE:
        return write_service_configuration_aws(service_descriptor, filename, certificate_filename, keyref_filename, server_cert_filename);
    case nxp_iot_ServiceType_AZURESERVICE:
        return write_service_configuration_azure(service_descriptor, filename, certificate_filename, keyref_filename, server_cert_filename);
        //TODO: Currently config files for Google and IBM services are being written same as custom service
    case nxp_iot_ServiceType_GOOGLESERVICE:
    case nxp_iot_ServiceType_IBMSERVICE:
    case nxp_iot_ServiceType_CUSTOMSERVICE:
        return write_service_configuration_custom(service_descriptor, filename, certificate_filename, keyref_filename, server_cert_filename);
    default:
        IOT_AGENT_ERROR("Unknown service type");
        break;
    }
exit:
    return agent_status;
}


// doc: trigger MQTT connection paho - start
iot_agent_status_t iot_agent_verify_mqtt_connection_for_service(iot_agent_context_t* iot_agent_context, const nxp_iot_ServiceDescriptor* service_descriptor)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
#if (OPENSSL_VERSION_NUMBER < 0x30000000)
	int mkdir_check = 0;

#if IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE
	mqtt_connection_params_t connection_params = { 0 };
	iot_agent_status_t mqtt_status = IOT_AGENT_SUCCESS;
#endif
	//write to files

	char config_filename[256];
	char certificate_filename[256];
	char keyref_filename[256];
	char server_cert_filename[256];
	char metadata_filename[256];

	const char* service_type_str;
	char service_dir[64];

	uint32_t keystore_id = service_descriptor->client_key_sss_ref.endpoint_id;
	iot_agent_keystore_t* keystore = NULL;
	agent_status = iot_agent_get_keystore_by_id(iot_agent_context, keystore_id, &keystore);
	AGENT_SUCCESS_OR_EXIT();

    agent_status = iot_agent_keystore_open_session(keystore);
    AGENT_SUCCESS_OR_EXIT();

	agent_status = iot_agent_service_get_service_type_as_string(service_descriptor, &service_type_str);
	AGENT_SUCCESS_OR_EXIT();

	if (ACCESS(goutput_directory, R_OK) != 0)
	{
		mkdir_check = DO_MKDIR(goutput_directory);
		ASSERT_OR_EXIT(mkdir_check == 0);
	}

	ASSERT_OR_EXIT_MSG(snprintf(service_dir, sizeof(service_dir), "%s%c%s%c", goutput_directory, path_separator, service_type_str, path_separator) >= 0, "Error in creating output folder string");
	if (ACCESS(service_dir, R_OK) != 0)
	{
		mkdir_check = DO_MKDIR(service_dir);
		ASSERT_OR_EXIT(mkdir_check == 0);
	}

	ASSERT_OR_EXIT_MSG(snprintf(config_filename, sizeof(config_filename), "%s" SERVICE_CONFIGURATION_PATTERN, service_dir, service_descriptor->identifier) >= 0, "Error in creating filename string");
	ASSERT_OR_EXIT_MSG(snprintf(metadata_filename, sizeof(metadata_filename), "%s" SERVICE_METADATA_PATTERN, service_dir, service_descriptor->identifier) >= 0, "Error in creating filename string");
	ASSERT_OR_EXIT_MSG(snprintf(keyref_filename, sizeof(keyref_filename), "%s" SERVICE_KEYREF_PATTERN, service_dir, service_descriptor->identifier) >= 0, "Error in creating filename string");
	ASSERT_OR_EXIT_MSG(snprintf(certificate_filename, sizeof(certificate_filename), "%s" SERVICE_CERTIFICATE_PATTERN, service_dir, service_descriptor->identifier) >= 0, "Error in creating filename string");
	ASSERT_OR_EXIT_MSG(snprintf(server_cert_filename, sizeof(server_cert_filename), "%s" SERVICE_SERVER_CERT_PATTERN, service_dir, service_type_str, service_descriptor->identifier) >= 0, "Error in creating filename string");

	//create service files
	char relative_certificate_filename[128];
	char relative_keyref_filename[128];
	char relative_server_cert_filename[128];
	ASSERT_OR_EXIT_MSG(snprintf(relative_certificate_filename, sizeof(relative_certificate_filename), SERVICE_CERTIFICATE_PATTERN, service_descriptor->identifier) >= 0, "Error in creating filename string");
	ASSERT_OR_EXIT_MSG(snprintf(relative_keyref_filename, sizeof(relative_keyref_filename), SERVICE_KEYREF_PATTERN, service_descriptor->identifier) >= 0, "Error in creating filename string");
	ASSERT_OR_EXIT_MSG(snprintf(relative_server_cert_filename, sizeof(relative_server_cert_filename), SERVICE_SERVER_CERT_PATTERN, service_type_str, service_descriptor->identifier) >= 0, "Error in creating filename string");

	if (IOT_AGENT_SUCCESS != write_service_configuration(service_descriptor, config_filename,
		relative_certificate_filename, relative_keyref_filename, relative_server_cert_filename))
	{
		write_error_logs(config_filename);
	}
	else
	{
		LOG_D("Created service configuration file [%s]", config_filename);
	}

	if (IOT_AGENT_SUCCESS != write_service_metadata(service_descriptor, metadata_filename))
	{
		write_error_logs(metadata_filename);
	}
	else
	{
		LOG_D("Created metadata file [%s]", metadata_filename);
	}

	if (service_descriptor->server_certificate != NULL) {
		if (IOT_AGENT_SUCCESS != iot_agent_utils_write_certificate_pem(service_descriptor->server_certificate->bytes,
			(size_t)service_descriptor->server_certificate->size, server_cert_filename))
		{
			write_error_logs(server_cert_filename);
		}
		else
		{
			LOG_D("Created server root certificate file [%s]", server_cert_filename);
		}
	}

	if (service_descriptor->client_certificate != NULL) {
		if (IOT_AGENT_SUCCESS != iot_agent_utils_write_certificate_pem(service_descriptor->client_certificate->bytes,
			(size_t)service_descriptor->client_certificate->size, certificate_filename))
		{
			write_error_logs(certificate_filename);
		}
		else
		{
			LOG_D("Created service client certificate file [%s]", certificate_filename);
		}
	}

	if (IOT_AGENT_SUCCESS != iot_agent_utils_write_key_ref_service_pem(iot_agent_context, keyref_filename))
	{
		write_error_logs(keyref_filename);
	}
	else
	{
		LOG_D("Created service keyref file [%s]", keyref_filename);
	}
	//write to files - end

#if IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE
	iot_agent_keystore_close_session(keystore);

	int network_status = network_openssl_engine_session_connect_mqtt();
	ASSERT_OR_EXIT_MSG(network_status == NETWORK_STATUS_OK, "network_openssl_engine_session_connect failed with 0x%08x.", network_status);

	connection_params.keypath = keyref_filename;
	connection_params.devcert = certificate_filename;
	connection_params.rootpath = server_cert_filename;
	mqtt_status = iot_agent_mqtt_test(service_descriptor, &connection_params);

	network_status = network_openssl_engine_session_disconnect_mqtt();
	ASSERT_OR_EXIT_MSG(network_status == NETWORK_STATUS_OK, "network_openssl_engine_session_connect failed with 0x%08x.", network_status);

	agent_status = iot_agent_keystore_open_session(keystore);
	AGENT_SUCCESS_OR_EXIT();
#endif
exit:
	if (mqtt_status != IOT_AGENT_SUCCESS) {
		return mqtt_status;
	}
#endif //if (OPENSSL_VERSION_NUMBER < 0x30000000)
	return agent_status;
}

iot_agent_status_t iot_agent_verify_mqtt_connection(iot_agent_context_t* iot_agent_context)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    size_t number_of_services = 0U;
	nxp_iot_ServiceDescriptor service_descriptor = nxp_iot_ServiceDescriptor_init_default;

    number_of_services = iot_agent_get_number_of_services(iot_agent_context);
	delete_old_service_files_folders(goutput_directory);
    AGENT_SUCCESS_OR_EXIT();

    for (size_t i = 0U; i < number_of_services; i++)
    {
		agent_status = iot_agent_select_service_by_index(iot_agent_context, i, &service_descriptor);
		AGENT_SUCCESS_OR_EXIT();

		agent_status = iot_agent_verify_mqtt_connection_for_service(iot_agent_context, &service_descriptor);
		AGENT_SUCCESS_OR_EXIT();
	}
exit:
	iot_agent_free_service_descriptor(&service_descriptor);
    return agent_status;
}


// doc: trigger MQTT connection paho - end

iot_agent_status_t iot_agent_cleanup_mqtt_config_files()
{
	delete_old_service_files_folders(goutput_directory);
	return IOT_AGENT_SUCCESS;
}

#if	(NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL)
iot_agent_status_t iot_agent_verify_mqtt_connection_cos_over_rtp(iot_agent_context_t* iot_agent_context, const nxp_iot_ServiceDescriptor* service_descriptor)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	iot_agent_keystore_key_ref_t gen_key_ref = {0};
	int mkdir_check = 0;
	openssl_network_context_t* network_context = NULL;

#if IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE
	mqtt_connection_params_t connection_params = { 0 };
	iot_agent_status_t mqtt_status = IOT_AGENT_SUCCESS;
#endif
	//write to files

	char config_filename[256];
	char certificate_filename[256];
	char keyref_filename[256];
	char server_cert_filename[256];
	char metadata_filename[256];

	const char* service_type_str;
	char service_dir[64];

	uint32_t keystore_id = service_descriptor->client_key_sss_ref.endpoint_id;
	iot_agent_keystore_t* keystore = NULL;
	agent_status = iot_agent_get_keystore_by_id(iot_agent_context, keystore_id, &keystore);
	AGENT_SUCCESS_OR_EXIT();

	agent_status = iot_agent_keystore_open_session(keystore);
	AGENT_SUCCESS_OR_EXIT();

	agent_status = iot_agent_service_get_service_type_as_string(service_descriptor, &service_type_str);
	AGENT_SUCCESS_OR_EXIT();

	if (ACCESS(goutput_directory_rtp, R_OK) != 0)
	{
		mkdir_check = DO_MKDIR(goutput_directory_rtp);
		ASSERT_OR_EXIT(mkdir_check == 0);
	}

	ASSERT_OR_EXIT_MSG(snprintf(service_dir, sizeof(service_dir), "%s%c%s%c", goutput_directory_rtp, path_separator, service_type_str, path_separator) >= 0, "Error in creating output folder string");
	if (ACCESS(service_dir, R_OK) != 0)
	{
		mkdir_check = DO_MKDIR(service_dir);
		ASSERT_OR_EXIT(mkdir_check == 0);
	}

	ASSERT_OR_EXIT_MSG(snprintf(config_filename, sizeof(config_filename), "%s" SERVICE_CONFIGURATION_PATTERN, service_dir, service_descriptor->identifier) >= 0, "Error in creating filename string");
	ASSERT_OR_EXIT_MSG(snprintf(metadata_filename, sizeof(metadata_filename), "%s" SERVICE_METADATA_PATTERN, service_dir, service_descriptor->identifier) >= 0, "Error in creating filename string");
	ASSERT_OR_EXIT_MSG(snprintf(keyref_filename, sizeof(keyref_filename), "%s" SERVICE_KEYREF_PATTERN, service_dir, service_descriptor->identifier) >= 0, "Error in creating filename string");
	ASSERT_OR_EXIT_MSG(snprintf(certificate_filename, sizeof(certificate_filename), "%s" SERVICE_CERTIFICATE_PATTERN, service_dir, service_descriptor->identifier) >= 0, "Error in creating filename string");
	ASSERT_OR_EXIT_MSG(snprintf(server_cert_filename, sizeof(server_cert_filename), "%s" SERVICE_SERVER_CERT_PATTERN, service_dir, service_type_str, service_descriptor->identifier) >= 0, "Error in creating filename string");

	//create service files
	char relative_certificate_filename[128];
	char relative_keyref_filename[128];
	char relative_server_cert_filename[128];
	ASSERT_OR_EXIT_MSG(snprintf(relative_certificate_filename, sizeof(relative_certificate_filename), SERVICE_CERTIFICATE_PATTERN, service_descriptor->identifier) >= 0, "Error in creating filename string");
	ASSERT_OR_EXIT_MSG(snprintf(relative_keyref_filename, sizeof(relative_keyref_filename), SERVICE_KEYREF_PATTERN, service_descriptor->identifier) >= 0, "Error in creating filename string");
	ASSERT_OR_EXIT_MSG(snprintf(relative_server_cert_filename, sizeof(relative_server_cert_filename), SERVICE_SERVER_CERT_PATTERN, service_type_str, service_descriptor->identifier) >= 0, "Error in creating filename string");

	if (IOT_AGENT_SUCCESS != write_service_configuration(service_descriptor, config_filename,
		relative_certificate_filename, relative_keyref_filename, relative_server_cert_filename))
	{
		write_error_logs(config_filename);
	}
	else
	{
		LOG_D("Created service configuration file [%s]", config_filename);
	}

	if (IOT_AGENT_SUCCESS != write_service_metadata(service_descriptor, metadata_filename))
	{
		write_error_logs(metadata_filename);
	}
	else
	{
		LOG_D("Created metadata file [%s]", metadata_filename);
	}

	if (service_descriptor->server_certificate != NULL) {
		if (IOT_AGENT_SUCCESS != iot_agent_utils_write_certificate_pem(service_descriptor->server_certificate->bytes,
			(size_t)service_descriptor->server_certificate->size, server_cert_filename))
		{
			write_error_logs(server_cert_filename);
		}
		else
		{
			LOG_D("Created server root certificate file [%s]", server_cert_filename);
		}
	}

	if (service_descriptor->has_client_certificate_sss_ref == true) {
		if (IOT_AGENT_SUCCESS != iot_agent_utils_write_certificate_pem_cos_over_rtp(iot_agent_context, service_descriptor, certificate_filename))
		{
			write_error_logs(certificate_filename);
		}
		else
		{
			LOG_D("Created service client certificate file [%s]", certificate_filename);
		}
	}
	iot_agent_keystore_close_session(keystore);

	network_context = network_new();
	ASSERT_OR_EXIT_MSG(network_context != NULL, "Network context is NULL");
	int network_status = network_openssl_init(network_context);
	ASSERT_OR_EXIT_MSG(network_status == NETWORK_STATUS_OK, "Network context is NULL");


#if (OPENSSL_VERSION_NUMBER < 0x30000000)
	gen_key_ref.key_ref = EVP_PKEY_new();
#endif
	agent_status = iot_agent_mqtt_open_session_from_keystore(keystore, network_context);
	AGENT_SUCCESS_OR_EXIT_MSG("Failed to connect to Secure Element keystore.")

	agent_status = iot_agent_utils_get_keystore_from_service_descriptor(iot_agent_context, service_descriptor, &keystore);
	AGENT_SUCCESS_OR_EXIT();

	agent_status = iot_agent_utils_gen_key_ref(keystore, service_descriptor->client_key_sss_ref.object_id, &gen_key_ref);
	AGENT_SUCCESS_OR_EXIT();

	// In OpenSSL >= 3.x the EVP PKEY generation required in iot_agent_utils_write_key_ref_pem need
	// an open session between the sssProvider and SE05x: the function iot_agent_mqtt_open_session_from_sss
	// will do the following steps:
	// - close the session between EL2GO agent keystore and SE05x
	// - open session between sssProvider and SE05x is open
#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
	agent_status = iot_agent_mqtt_open_session_from_sss(keystore, network_context);
	AGENT_SUCCESS_OR_EXIT_MSG("Failed to connect to Secure Element keystore.")
#endif

	if (IOT_AGENT_SUCCESS != iot_agent_utils_write_key_ref_pem(&gen_key_ref, keyref_filename))
	{
		write_error_logs(keyref_filename);
	}
	else
	{
		LOG_D("Created service keyref file [%s]", keyref_filename);
	}
	//write to files - end

	// After writing the PEM, restore the session between EL2GO Agent keystore and Se05x
#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
	agent_status = iot_agent_mqtt_open_session_from_keystore(keystore, network_context);
	AGENT_SUCCESS_OR_EXIT_MSG("Failed to connect to Secure Element keystore.")
#endif
#if IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE

	agent_status = iot_agent_mqtt_open_session_from_sss(keystore, network_context);
	AGENT_SUCCESS_OR_EXIT_MSG("Failed to connect to Secure Element keystore.")

	connection_params.keypath = keyref_filename;
	connection_params.devcert = certificate_filename;
	connection_params.rootpath = server_cert_filename;
	mqtt_status = iot_agent_mqtt_test(service_descriptor, &connection_params);

	agent_status = iot_agent_mqtt_open_session_from_keystore(keystore, network_context);
	AGENT_SUCCESS_OR_EXIT_MSG("Failed to connect to Secure Element keystore.")
#endif
exit:
	network_free(network_context);
	if (mqtt_status != IOT_AGENT_SUCCESS) {
		return mqtt_status;
	}
	return agent_status;
}

iot_agent_status_t iot_agent_cleanup_mqtt_config_files_cos_over_rtp()
{
	delete_old_service_files_folders(goutput_directory_rtp);
	return IOT_AGENT_SUCCESS;
}
#endif

