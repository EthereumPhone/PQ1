#
# Copyright 2021 NXP
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(sbl_app_s)

FILE(
    GLOB
    files
    *.c
    ../sbl_s/memory.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ../common
    PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
    PRIVATE ../sbl_s
    PRIVATE .
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    board
    SSS_APIs
    lpc55s_veneer
    ex_common
)

CREATE_BINARY(${PROJECT_NAME})
