# Copyright 2023 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(core_json)

FILE(
    GLOB
    json_files
    ${SIMW_TOP_DIR}/ext/freertos/corejson/source/*.c
)

ADD_LIBRARY(
    ${PROJECT_NAME}
    ${json_files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC
    ${SIMW_TOP_DIR}/ext/freertos/corejson/source/include
)

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-error=unused-variable
        PRIVATE -Wno-unused-variable
        PRIVATE -Wno-address-of-packed-member
        PRIVATE -Wno-unused-function
        PRIVATE -Wno-array-bounds
    )
    SIMW_DISABLE_EXTRA_WARNINGS(${PROJECT_NAME})

ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE
            /wd4310 # cast truncates constant value
            /wd4127 # conditional expression is constant
            /wd4189 # local variable is initialized but not referenced
            /wd4005 # macro redefinition
            /wd4456 # hides previous local declaration
            /wd4101 # unreferenced local variable
            /wd4267 # possible loss of data
            /wd4295 # array is too small to include a terminating null character
            /wd4057 # differs in indirection to slightly different base types
            /wd4200 # nonstandard extension used: zero-sized array in struct/union
            /wd4055 # type cast: from data pointer to function pointer
            /wd4701 # potentially uninitialized local variable
    )
ENDIF()
