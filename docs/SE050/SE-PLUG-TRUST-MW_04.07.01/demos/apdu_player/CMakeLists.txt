#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

# TODO: Get rid of -Wno-format -Wno-format-security

IF(CMAKE_COMPILER_IS_GNUCC)
    ADD_DEFINITIONS("-Wno-unused-function -Wno-format -Wno-format-security")
ENDIF()

PROJECT(apdu_player_demo)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    apdu_player.c
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
    ex_common
    smCom
)

CREATE_BINARY(${PROJECT_NAME})

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
ENDIF()
