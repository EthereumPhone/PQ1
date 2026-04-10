#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(cloud_aws)

FILE(
    GLOB
    files
    aws_cert.c
    ../common/ledHandler.c
    ../../../sss/ex/inc/*.h
    *.h
    ../common/*.h
)

IF(SSS_HAVE_MBEDTLS_ALT_SSS AND (SSS_HAVE_APPLET_A7XX OR SSS_HAVE_APPLET_SE050_EAR))
    LIST(
        APPEND
        files
        ${SIMW_TOP_DIR}/sss/ex/src/ex_sss_a71ch.c
    )
ENDIF()

IF(SSS_HAVE_KSDK)
    FILE(
        GLOB
        lwip_files
        aws_jitr_demo_Main_lwip.c
        aws_jitr_task_lwip.c
    )
ENDIF()
IF(SSS_HAVE_HOST_PCWINDOWS)
    FILE(
        GLOB
        x86_files
        aws_jitr_demo_Main_x86.c
        aws_jitr_task_lwip.c
    )
ENDIF()

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE}
    ${files}
    ${lwip_files}
    ${x86_files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ../common
    PRIVATE ../../../sss/ex/inc ../https_client
    PRIVATE .
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    a7x_utils
    freertos-kernel
    ex_common
)

IF(ENABLE_CLOUD_DEMOS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} freertos-ip)
ENDIF()

CREATE_BINARY(${PROJECT_NAME})
