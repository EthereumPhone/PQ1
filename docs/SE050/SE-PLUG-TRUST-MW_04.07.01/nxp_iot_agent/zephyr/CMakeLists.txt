# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_EL2GO_COMMON)
    target_compile_definitions(app PRIVATE
        AX_EMBEDDED=1
        NXP_IOT_AGENT_HAVE_HOSTCRYPTO_MBEDTLS=1
        NXP_IOT_AGENT_HAVE_PSA=1
        NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM=1
        PB_FIELD_32BIT
        SSS_USE_FTR_FILE
        USE_RTOS=1
    )

    target_include_directories(app PRIVATE
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/inc
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/zephyr/common
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/keystore/psa
    )

    if(CONFIG_EL2GO_AGENT_LIBRARY_SOURCES)
        target_sources(app PRIVATE
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/net_crypto/mbedtls/net_zephyr.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/net_crypto/mbedtls/network_mbedtls.c
        )

        target_sources(app PRIVATE
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/nxp_iot_agent_common.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/nxp_iot_agent_config.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/datastore/plain/nxp_iot_agent_datastore_plain.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/nxp_iot_agent_datastore.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/keystore/psa/nxp_iot_agent_keystore_psa.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/nxp_iot_agent_keystore.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/nxp_iot_agent_service.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/nxp_iot_agent_utils_protobuf_socket.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/nxp_iot_agent_utils.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/nxp_iot_agent.c
        )

        target_sources(app PRIVATE
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/common/nxp_iot_agent_dispatcher.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/common/nxp_iot_agent_utils_protobuf.c
        )

        target_sources(app PRIVATE
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/Agent.pb.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/Apdu.pb.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/Datastore.pb.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/Dispatcher.pb.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/Hostcmd.pb.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/pb_common.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/pb_decode.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/pb_encode.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/Proxy.pb.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/PSA.pb.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/RPC.pb.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/ServiceDescriptor.pb.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/Types.pb.c
        )

        target_include_directories(app PRIVATE
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/net_crypto
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/net_crypto/mbedtls
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/platform/tfm
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/datastore/plain
        )

        target_sources(app PRIVATE
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/platform/tfm/nxp_iot_agent_platform_tfm.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/platform/tfm/nxp_iot_agent_time_tfm.c
        )

    elseif(CONFIG_EL2GO_MQTT_LIBRARY_SOURCES)
        target_sources(app PRIVATE
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/net_crypto/mbedtls/net_zephyr.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/net_crypto/mbedtls/network_mbedtls.c
        )

        target_sources(app PRIVATE
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/pb_common.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/pb_decode.c
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf/ServiceDescriptor.pb.c
        )

        target_include_directories(app PRIVATE
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/net_crypto
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/net_crypto/mbedtls
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/src/protobuf
        )
    endif()
endif()

if(CONFIG_EL2GO_TFM_LEGACY_CRYPTO_ENABLE)
    set_property(TARGET zephyr_property_target
        APPEND PROPERTY TFM_CMAKE_OPTIONS
        -DTFM_MBEDCRYPTO_PLATFORM_EXTRA_CONFIG_PATH=${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/zephyr/common/mbedcrypto_extra_config.h
    )
endif()

if(CONFIG_EL2GO_TFM_DATA_IMPORT_REGION)
    set_property(TARGET zephyr_property_target
        APPEND PROPERTY TFM_CMAKE_OPTIONS
        -DUSE_TFM_EL2GO_DATA_IMPORT_REGION=ON
    )
endif()

# Sign image using SPSDK 'nxpimage' tool
if(CONFIG_EL2GO_SIGN_USING_NXPIMAGE OR(DEFINED ENV{CONFIG_EL2GO_SIGN_USING_NXPIMAGE}
    AND $ENV{CONFIG_EL2GO_SIGN_USING_NXPIMAGE} STREQUAL "y")
    AND("${BOARD}${BOARD_QUALIFIERS}" STREQUAL "rd_rw612_bga/rw612/ns"
    OR "${BOARD}${BOARD_QUALIFIERS}" STREQUAL "frdm_rw612/rw612/ns"))
    include(${CMAKE_CURRENT_LIST_DIR}/sign_s_ns/cmake/sign_s_ns.cmake)
endif()
