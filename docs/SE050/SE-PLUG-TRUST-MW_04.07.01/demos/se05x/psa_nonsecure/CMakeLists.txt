# Copyright 2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(psa_nonsecure)
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
    PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
    PRIVATE ${SIMW_TOP_DIR}/sss/plugin/psa/inc
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ${SIMW_TOP_DIR}/binaries/PSA_ALT_CMSE_lib.o
    ex_common
)

CREATE_BINARY(${PROJECT_NAME})
