#
# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(mbedtls_3x_client)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${SIMW_TOP_DIR}/ext/mbedtls3x/programs/ssl/ssl_client2.c
    ${SIMW_TOP_DIR}/ext/mbedtls3x/tests/src/certs.c
    ${SIMW_TOP_DIR}/ext/mbedtls3x/tests/src/helpers.c
    ${SIMW_TOP_DIR}/ext/mbedtls3x/programs/test/query_config.c
    ${SIMW_TOP_DIR}/ext/mbedtls3x/programs/ssl/ssl_test_lib.c
    ${SIMW_TOP_DIR}/ext/mbedtls3x/tests/src/psa_crypto_helpers.c
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${SIMW_TOP_DIR}/ext/mbedtls3x/tests/include
)

IF(SSS_HAVE_KSDK)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} mbedtls)
ELSE() # KSDK
    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        mbedtls
        smCom
        SSS_APIs
        ex_common
    )
ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    IF(NXPInternal)
        TARGET_COMPILE_OPTIONS(${PROJECT_NAME}
        PRIVATE /wd4701 #potentially uninitialized local variable
        )
    ENDIF()
ENDIF()

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${SIMW_TOP_DIR}/tools
    COMMENT "Copy exe to ${SIMW_TOP_DIR}/tools"
)

CREATE_BINARY(${PROJECT_NAME})