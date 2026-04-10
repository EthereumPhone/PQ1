# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(el2go_agent)

target_sources(app PRIVATE
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/iot_agent_demo.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/network/iot_agent_network_zephyr_wifi.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/utils/iot_agent_claimcode_import.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/utils/iot_agent_mqtt_zephyr.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/utils/mbedtls_psa/iot_agent_psa_sign_test.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/osal/zephyr/iot_agent_osal_zephyr.c
)

zephyr_include_directories(
    $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/api_ns/interface/include
    ${APPLICATION_SOURCE_DIR}/inc
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/inc
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/inc/mbedtls_psa
)

if(CONFIG_EDGELOCK2GO_HOSTNAME)
    target_compile_definitions(app PRIVATE EDGELOCK2GO_HOSTNAME="${CONFIG_EDGELOCK2GO_HOSTNAME}")
else()
    if(DEFINED ENV{CONFIG_EDGELOCK2GO_HOSTNAME})
        target_compile_definitions(app PRIVATE EDGELOCK2GO_HOSTNAME="$ENV{CONFIG_EDGELOCK2GO_HOSTNAME}")
    endif()
endif()

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

if(CONFIG_IOT_AGENT_CLAIMCODE_INJECT_ENABLE)
    target_compile_definitions(app PRIVATE IOT_AGENT_CLAIMCODE_INJECT_ENABLE=1)
endif()

if(CONFIG_IOT_AGENT_MQTT_ENABLE)
    target_compile_definitions(app PRIVATE IOT_AGENT_MQTT_ENABLE=1)
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
