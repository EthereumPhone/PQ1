#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

MACRO(DO_PROVISOING_PROJECT PROVISOING_PROJECT_NAME)

    PROJECT(cloud_provisioning_${PROVISOING_PROJECT_NAME})

    FILE(
        GLOB
        headers
        *.h
    )

    ADD_EXECUTABLE(
        ${PROJECT_NAME}
        ${KSDK_STARTUP_FILE}
        ${headers}
        provisioning.c
        provisioning_${PROVISOING_PROJECT_NAME}.c
    )

    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
        PRIVATE ../common
    )

    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PRIVATE ../${PROVISOING_PROJECT_NAME})

    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        ex_common
        a7x_utils
    )

    IF(ENABLE_CLOUD_DEMOS)
        TARGET_LINK_LIBRARIES(${PROJECT_NAME} freertos-ip)
    ENDIF()

    CREATE_BINARY(${PROJECT_NAME})
ENDMACRO()

DO_PROVISOING_PROJECT(aws)
#DO_PROVISOING_PROJECT(gcp)
DO_PROVISOING_PROJECT(azure)
#DO_PROVISOING_PROJECT(ibm_watson)
