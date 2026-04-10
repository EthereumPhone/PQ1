#
# Copyright 2022 NXP
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(sa_qi_auth)

FILE(
    GLOB
    files
    *.c
    port/*.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE .
    PRIVATE ..
    PRIVATE port
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
    sa_qi_transmitter_auth
    mbedtls
)

IF(NXPInternal)
    TARGET_COMPILE_DEFINITIONS(
        ${PROJECT_NAME}
        PRIVATE
        USE_ROOT_WPCCA=0
    )
ENDIF()

CREATE_BINARY(${PROJECT_NAME})
