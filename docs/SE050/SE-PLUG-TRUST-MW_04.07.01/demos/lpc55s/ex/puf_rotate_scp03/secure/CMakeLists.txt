#
# Copyright 2021 NXP
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(puf_rotate_scp03_s)

FILE(
    GLOB
    files
    puf_rotate_scp03_s.c
    veneer_table.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ../common
    PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
    PRIVATE .
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} board
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
    ex_common
    lpc55s_veneer
)

CREATE_BINARY(${PROJECT_NAME})
