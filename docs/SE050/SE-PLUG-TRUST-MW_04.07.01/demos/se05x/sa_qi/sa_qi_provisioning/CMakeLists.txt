#
# Copyright 2022 NXP
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(sa_qi_provisioning)

FILE(
    GLOB
    files
    *.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ..
)

CREATE_BINARY(${PROJECT_NAME})
