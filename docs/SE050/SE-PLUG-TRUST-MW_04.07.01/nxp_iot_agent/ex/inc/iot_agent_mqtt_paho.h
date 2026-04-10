/*
 * Copyright 2020-2021,2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef _IOT_AGENT_MQTT_PAHO_H_
#define _IOT_AGENT_MQTT_PAHO_H_
#include <nxp_iot_agent.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! @defgroup edgelock2go_agent_mqtt_openssl EdgeLock 2GO agent write service credentials into files for MQTT connection
*
* @ingroup edgelock2go_agent_mqtt_openssl
*
* @brief Provides functionality to write service credentials into files. These files can be used for MQTT connection demo example.
*
*/

/*!
* @addtogroup edgelock2go_agent_mqtt_openssl
* @{
*/
#define IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE 1U

#if IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE
#if defined(_WIN32)
#define SLEEP_SEC(x) Sleep(x*1000L);
#else
#define SLEEP_SEC(x) sleep(x);
#endif

#define IOT_AGENT_MQTT_REGISTRATION_TOPIC_AZURE "$dps/registrations/PUT/iotdps-register/?$rid=1"
#define IOT_AGENT_MQTT_OPID_TOPIC_AZURE "$dps/registrations/GET/iotdps-get-operationstatus/?$rid=2&operationId="
#define IOT_AGENT_MQTT_SUBSCRIBE_TOPIC_AZURE "$dps/registrations/res/#"
#define REGISTRATION_TIMEOUT 30

#define IOT_AGENT_MQTT_USERNAME_AWS "dummy"
#define IOT_AGENT_MQTT_TOPIC_AWS "CppSDKTesting"

#define IOT_AGENT_MQTT_USERNAME_CUSTOM "use-token-auth"
#define IOT_AGENT_MQTT_TOPIC_CUSTOM "iot-2/evt/status/fmt/string"

#define IOT_AGENT_MQTT_PAYLOAD "Hello from EdgeLock2Go-Agent"
#endif

iot_agent_status_t iot_agent_verify_mqtt_connection_for_service(iot_agent_context_t* iot_agent_context, const nxp_iot_ServiceDescriptor* service_descriptor);

iot_agent_status_t iot_agent_verify_mqtt_connection(iot_agent_context_t* iot_agent_context);

iot_agent_status_t iot_agent_cleanup_mqtt_config_files();

#if	(NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL)
iot_agent_status_t iot_agent_verify_mqtt_connection_cos_over_rtp(iot_agent_context_t* iot_agent_context, const nxp_iot_ServiceDescriptor* service_descriptor);

iot_agent_status_t iot_agent_cleanup_mqtt_config_files_cos_over_rtp();
#endif


#ifdef __cplusplus
} // extern "C"
#endif


  /*!
  *@}
  */ /* end of edgelock2go_agent_mqtt_openssl */

#endif // #ifndef _IOT_AGENT_MQTT_PAHO_H_
