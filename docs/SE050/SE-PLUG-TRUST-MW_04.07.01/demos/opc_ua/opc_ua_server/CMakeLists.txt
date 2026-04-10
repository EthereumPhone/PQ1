#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(open62541_ex_server)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    *.c
    info_model/*.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${${PROJECT_NAME}_files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ${SIMW_TOP_DIR}/demos/opc_ua/opc_ua_server/info_model
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    open62541_lib
    mbedtls
    ex_common
)

IF(SSS_HAVE_HOST_PCWINDOWS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} Ws2_32)
ENDIF()

CREATE_BINARY(${PROJECT_NAME})

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${SIMW_TOP_DIR}/tools
    COMMENT "Copy exe to ${SIMW_TOP_DIR}/tools"
)

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE
            /wd4706 # assignment within conditional expression
            /wd4701 # potentially uninitialized local variable
            /wd4703 # potentially uninitialized local pointer variable
    )
ENDIF()
