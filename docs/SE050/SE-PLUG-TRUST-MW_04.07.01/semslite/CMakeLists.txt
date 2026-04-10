#
# Copyright 2019,2020,2024 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(SEMS_LITE_AGENT_APIs LANGUAGES C)


FILE(
    GLOB
        API_FILES
        lib/inc/*.h
        lib/src/*.c
        lib/src/*.h
)

IF(SSS_HAVE_HOST_ANDROID)
    ADD_LIBRARY(${PROJECT_NAME} SHARED ${API_FILES})
ELSE()
    ADD_LIBRARY(${PROJECT_NAME} ${API_FILES})
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC lib/inc
    PUBLIC ../nxp_iot_agent/src
    PUBLIC ../nxp_iot_agent/inc
    PUBLIC ../nxp_iot_agent/src/keystore/sss
    PUBLIC ../nxp_iot_agent/src/protobuf/
    PUBLIC ../hostlib/hostlib/inc
    PUBLIC ../hostlib/hostlib/libCommon
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
    nxp_iot_agent_common
)

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()

IF(SSS_HAVE_LARGE_PROGRAMS)
    IF(NOT SSS_HAVE_APPLET_AUTH)
        ADD_SUBDIRECTORY(ex)
    ENDIF()
ENDIF()

IF(SSS_HAVE_RTOS_DEFAULT AND NXPInternal)
    ADD_SUBDIRECTORY(tst)
ENDIF()



IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(
        DIRECTORY
            lib/inc/
            port/default/
        DESTINATION ${SIMW_INSTALL_INC_DIR}
        FILES_MATCHING
        PATTERN "*.h"
    )
ENDIF()
