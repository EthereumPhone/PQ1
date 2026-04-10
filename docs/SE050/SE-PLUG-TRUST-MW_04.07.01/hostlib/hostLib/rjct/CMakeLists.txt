#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(jrcpv1_server)

FILE(
    GLOB
    jrcpv1_server_sources
    inc/rjct.h
    src/mainRjct.c
    src/rjct.c
    src/rjct_com.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${jrcpv1_server_sources}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC inc
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} smCom
)

IF(SSS_HAVE_SCP_SCP03_SSS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} SSS_APIs)
ENDIF()

CREATE_BINARY(${PROJECT_NAME})

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
ENDIF()
