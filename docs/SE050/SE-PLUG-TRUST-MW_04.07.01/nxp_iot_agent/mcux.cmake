# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent.lwip_enet)
    mcux_add_source(
        SOURCES ex/src/network/iot_agent_network_lwip.c
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent.lwip_wifi)
    mcux_add_source(
        SOURCES ex/src/network/iot_agent_network_lwip_wifi.c
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent.sss)
    mcux_add_macro(
        CC "NXP_IOT_AGENT_HAVE_SSS=1"
    )
    mcux_add_source(
        SOURCES ex/inc/iot_agent_claimcode_inject.h
                ex/src/utils/iot_agent_claimcode_inject.c
                platform/se05x/*.c
                platform/se05x/*.h
                src/keystore/sss/*.c
                src/keystore/sss/*.h
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
    mcux_add_include(
        INCLUDES ex/inc
                 src/keystore/sss
                 platform/se05x
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent.psa)
    mcux_add_macro(
        CC "NXP_IOT_AGENT_HAVE_PSA=1\
            NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM=1"
    )
    mcux_add_source(
        SOURCES ex/inc/iot_agent_claimcode_import.h
                ex/inc/mbedtls_psa/iot_agent_psa_sign_test.h
                ex/src/utils/iot_agent_claimcode_import.c
                ex/src/utils/mbedtls_psa/iot_agent_psa_sign_test.c
                platform/tfm/*.c
                src/keystore/psa/*.c
                src/keystore/psa/*.h
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
    mcux_add_include(
        INCLUDES ex/inc
                 ex/inc/mbedtls_psa
                 src/keystore/psa
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent)
    mcux_add_macro(
        CC "PB_FIELD_32BIT\
            NXP_IOT_AGENT_HAVE_HOSTCRYPTO_MBEDTLS=1"
    )
    mcux_add_source(
        SOURCES inc/*.h
                src/*.h
                ex/inc/iot_agent_demo_config.h
                ex/inc/iot_agent_mqtt_freertos.h
                ex/inc/iot_agent_network.h
                ex/inc/iot_agent_osal.h
                ex/src/osal/freertos/iot_agent_osal_freertos.c
                ex/src/osal/freertos/iot_agent_osal_freertos.h
                ex/src/utils/iot_agent_mqtt_freertos.c
                net_crypto/network.h
                net_crypto/mbedtls/network_mbedtls.h
                net_crypto/mbedtls/network_mbedtls.c
                net_crypto/mbedtls/net_lwip.c
                src/*.c
                src/common/*.c
                src/protobuf/*.h
                src/protobuf/*.c
                src/datastore/plain/*.c
                src/datastore/plain/*.h
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
    mcux_add_include(
        INCLUDES inc
                 src
                 ex/inc
                 net_crypto
                 net_crypto/mbedtls
                 src/protobuf
                 ex/src/osal/freertos
                 src/datastore/plain
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent.mqtt)
    mcux_add_macro(
        CC "PB_FIELD_32BIT\
            NXP_IOT_AGENT_HAVE_HOSTCRYPTO_MBEDTLS=1\
            NXP_IOT_AGENT_HAVE_PSA=1\
            NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM=1\
            IOT_AGENT_MQTT_ENABLE=1"
    )
    mcux_add_source(
        SOURCES inc/*.h
                ex/inc/iot_agent_demo_config.h
                ex/inc/iot_agent_mqtt_freertos.h
                ex/inc/iot_agent_network.h
                ex/src/utils/iot_agent_mqtt_freertos.c
                src/keystore/psa/nxp_iot_agent_macros_psa.h
                src/protobuf/*.h
                src/protobuf/pb_common.c
                src/protobuf/pb_decode.c
                src/protobuf/ServiceDescriptor.pb.c
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
    mcux_add_include(
        INCLUDES inc
                 ex/inc
                 src/keystore/psa
                 src/protobuf
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()

if(CONFIG_MCUX_COMPONENT_middleware.nxp_iot_agent.claimcode)
    mcux_add_macro(
        CC "NXP_IOT_AGENT_HAVE_HOSTCRYPTO_MBEDTLS=1\
            NXP_IOT_AGENT_HAVE_PSA=1"
    )
    mcux_add_source(
        SOURCES inc/*.h
                ex/inc/iot_agent_claimcode_encrypt.h
                ex/inc/iot_agent_demo_config.h
                ex/src/utils/iot_agent_claimcode_encrypt_els.c
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
    mcux_add_include(
        INCLUDES inc
                 ex/inc
        BASE_PATH ${SdkRootDirPath}/middleware/nxp_iot_agent/
    )
endif()