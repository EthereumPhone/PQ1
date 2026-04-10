#
# Copyright 2022 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(sa_qi_transmitter_auth)

FILE(
    GLOB
    files
    *.c
    port/*.c
)

ADD_LIBRARY(
    ${PROJECT_NAME}
    ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC .
    PUBLIC ..
    PUBLIC port
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
)
