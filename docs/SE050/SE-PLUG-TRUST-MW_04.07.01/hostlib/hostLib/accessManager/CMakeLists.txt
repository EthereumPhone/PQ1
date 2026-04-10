#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(accessManager)

FILE(
    GLOB
    accessManager_sources
    src/accessManager.c
    src/accessManager_com.c
    src/accessManager_rjct.c
    src/accessManager_utils.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${accessManager_sources}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC inc
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} smCom
)

IF(SSS_HAVE_HOST_IMXLINUX OR SSS_HAVE_HOST_RASPBIAN)
    #ADD_DEFINITIONS(-DENABLE_SD_NOTIFY)
    #TARGET_LINK_LIBRARIES(${PROJECT_NAME} systemd)
ENDIF()

IF(SSS_HAVE_SCP_SCP03_SSS)
    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        ex_common
        SSS_APIs
    )
ENDIF()

CREATE_BINARY(${PROJECT_NAME})

# IF(SSS_HAVE_HOST_LINUX_LIKE)
#     INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
# ENDIF()

IF(SSS_HAVE_HOST_LINUX_LIKE)
    MESSAGE("accessManager is not copied to default binary directory upon install")
ENDIF()
