#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

INCLUDE_DIRECTORIES(/opt/openssl30/include/)

PROJECT(sssProvider)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    provider/*.c
    provider/*.h
)


ADD_LIBRARY(${PROJECT_NAME} SHARED ${${PROJECT_NAME}_files})

IF(SSS_HAVE_APPLET_SE05X_IOT)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} se05x)
ENDIF()

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
)

IF(
    SSS_HAVE_APPLET_SE05X_IOT
    OR SSS_HAVE_APPLET_SE050_EAR
)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} a7x_utils)
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
    PUBLIC provider/inc
)


ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${SIMW_TOP_DIR}/sss/plugin/openssl_provider/bin
    COMMENT "Copy dll to ${SIMW_TOP_DIR}/sss/plugin/openssl_provider/bin"
)

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()
