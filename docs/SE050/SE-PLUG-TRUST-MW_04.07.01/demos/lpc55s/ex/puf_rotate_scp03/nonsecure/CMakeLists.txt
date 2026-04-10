#
# Copyright 2021 NXP
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(puf_rotate_scp03_ns)

FILE(
    GLOB
    files
    puf_rotate_scp03_ns.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ../common .
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} board
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} ${SIMW_TOP_DIR}/binaries/puf_rotate_scp03_s_CMSE_lib.o
)

CREATE_BINARY(${PROJECT_NAME})
