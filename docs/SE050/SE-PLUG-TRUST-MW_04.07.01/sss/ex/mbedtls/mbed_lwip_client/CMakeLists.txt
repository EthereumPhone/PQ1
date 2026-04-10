#
# Copyright 2024-2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(mbedtls_ex_se05x_client_lwip)

FILE(
    GLOB
    src_files
    ../ex_sss_ssl2.c
    ssl/ssl_test_lib.c
    ${SIMW_TOP_DIR}/sss/plugin/mbedtls/sss_mbedtls.c
    ${SIMW_TOP_DIR}/sss/plugin/mbedtls/sss_mbedtls_rsa.c
    ${SIMW_TOP_DIR}/ext/mbedtls/tests/src/helpers.c
    ${SIMW_TOP_DIR}/nxp_iot_agent/net_crypto/mbedtls/net_lwip.c
    *.h
)

IF(SSS_HAVE_APPLET_SE05X_IOT)
    FILE(
        GLOB
        ax_files
        ${SIMW_TOP_DIR}/hostlib/hostLib/libCommon/infra/sm_app_boot.c
    )
ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    ADD_EXECUTABLE(
        ${PROJECT_NAME}
        ${KSDK_STARTUP_FILE}
        ${ax_files}
        ${src_files}
    )
ELSE()
    ADD_EXECUTABLE(
        ${PROJECT_NAME}
        ${KSDK_STARTUP_FILE}
        ${ax_files}
        ${src_files}

    )
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE
        .
        ssl
        ../../inc
        ../../../plugin/mbedtls
        ${SIMW_TOP_DIR}/hostlib/useCase/common
        ${SIMW_TOP_DIR}/ext/mbedtls/tests/include
        ${SIMW_TOP_DIR}/ext/mbedtls/programs/ssl/       
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} ex_common
)

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    IF(NXPInternal)
        TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE /wd4127 # conditional expression is constant
        )
    ENDIF()
ENDIF()

CREATE_BINARY(${PROJECT_NAME})
