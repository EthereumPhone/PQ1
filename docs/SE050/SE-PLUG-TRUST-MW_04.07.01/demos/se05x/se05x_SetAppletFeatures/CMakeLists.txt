#
# Copyright 2021 NXP
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(se05x_SetAppletFeatures)

FILE(
    GLOB
    files
    *.c
    *.h
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
)

CREATE_BINARY(${PROJECT_NAME})

EXPOSE_SE05X_AUTH_STRATEGY()
