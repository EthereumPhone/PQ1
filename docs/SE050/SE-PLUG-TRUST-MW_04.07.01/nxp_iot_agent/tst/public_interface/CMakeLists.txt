# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: Apache-2.0
#


PROJECT(nxp_iot_agent_public_interface_test)

FILE(
    GLOB
        ${PROJECT_NAME}_files
        *.c
        *.cpp
        *.h
)

ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE} ${${PROJECT_NAME}_files})

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE .
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    nxp_iot_agent_test_common
)

EXPOSE_SE05X_AUTH_STRATEGY("SSS_HAVE_SE05X_AUTH")

CREATE_BINARY(${PROJECT_NAME})
