# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(el2go_mqtt_demo)

target_compile_definitions(app PRIVATE
    IOT_AGENT_MQTT_ENABLE=1
)

target_sources(app PRIVATE
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/apps/el2go_mqtt_client.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/network/iot_agent_network_zephyr_wifi.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/utils/iot_agent_mqtt_zephyr.c
)

zephyr_include_directories(
    $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/api_ns/interface/include
    ${APPLICATION_SOURCE_DIR}/inc
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/inc
)

if(CONFIG_AP_SSID)
    target_compile_definitions(app PRIVATE AP_SSID="${CONFIG_AP_SSID}")
else()
    if(DEFINED ENV{CONFIG_AP_SSID})
        target_compile_definitions(app PRIVATE AP_SSID="$ENV{CONFIG_AP_SSID}")
    endif()
endif()

if(CONFIG_AP_PASSWORD)
    target_compile_definitions(app PRIVATE AP_PASSWORD="${CONFIG_AP_PASSWORD}")
else()
    if(DEFINED ENV{CONFIG_AP_PASSWORD})
        target_compile_definitions(app PRIVATE AP_PASSWORD="$ENV{CONFIG_AP_PASSWORD}")
    endif()
endif()

# Compare these to default value in Kconfig
# Not possible to leave default value out in Kconfig, leads to build errors
if(NOT CONFIG_AWS_SERVICE_KEY_PAIR_ID EQUAL 0x0)
    target_compile_definitions(app PRIVATE
        AWS_SERVICE_KEY_PAIR_ID=${CONFIG_AWS_SERVICE_KEY_PAIR_ID})
endif()

if(NOT CONFIG_AWS_SERVICE_DEVICE_CERT_ID EQUAL 0x0)
    target_compile_definitions(app PRIVATE
        AWS_SERVICE_DEVICE_CERT_ID=${CONFIG_AWS_SERVICE_DEVICE_CERT_ID})
endif()

if(NOT CONFIG_AZURE_SERVICE_KEY_PAIR_ID EQUAL 0x0)
    target_compile_definitions(app PRIVATE
        AZURE_SERVICE_KEY_PAIR_ID=${CONFIG_AZURE_SERVICE_KEY_PAIR_ID})
endif()

if(NOT CONFIG_AZURE_SERVICE_DEVICE_CERT_ID EQUAL 0x0)
    target_compile_definitions(app PRIVATE
        AZURE_SERVICE_DEVICE_CERT_ID=${CONFIG_AZURE_SERVICE_DEVICE_CERT_ID})
endif()
