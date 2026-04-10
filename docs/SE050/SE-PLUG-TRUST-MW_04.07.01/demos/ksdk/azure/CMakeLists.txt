#
# Copyright 2018,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(cloud_azure)

FILE(
    GLOB
    files
    azureDemo.h
    azureDemo_Main_lwip.c
    azurePubSub.c
    azureTask_lwip.c
    azure_client_credential_keys.h
    azure_default_root_certificates.h
    azure_iot_config.h
    ../common/ledHandler.c
    ../common/*.h
)

IF(SSS_HAVE_MBEDTLS_ALT_SSS AND (SSS_HAVE_APPLET_A7XX OR SSS_HAVE_APPLET_SE050_EAR))
    LIST(
        APPEND
        files
        ${SIMW_TOP_DIR}/sss/ex/src/ex_sss_a71ch.c
    )
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS)
    LIST(
        APPEND
        files
        azureDemo_Main_x86.c
        azureTask_lwip.c
    )
ENDIF()

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
    PRIVATE ../common/https_client ../common
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} ex_common
)

IF(ENABLE_CLOUD_DEMOS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} freertos-ip)
ENDIF()

CREATE_BINARY(${PROJECT_NAME})
