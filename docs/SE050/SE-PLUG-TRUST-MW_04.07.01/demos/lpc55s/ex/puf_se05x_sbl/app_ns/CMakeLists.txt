#
# Copyright 2021 NXP
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(sbl_app_ns)

FILE(
    GLOB
    files
    *.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ../session
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ${CMAKE_SOURCE_DIR}/binaries/sbl_app_s_CMSE_lib.o
    board
    SSS_APIs
    lpc55s_veneer
)

CREATE_BINARY(${PROJECT_NAME})
