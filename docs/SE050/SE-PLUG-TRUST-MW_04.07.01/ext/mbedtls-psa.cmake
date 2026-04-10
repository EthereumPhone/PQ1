# Copyright 2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
#
# Manually create project. mbedTLS has it's own CMakeLists.txt
#
PROJECT(mbedtls_psa)

IF(((SSS_HAVE_HOST_PCWINDOWS) OR (SSS_HAVE_HOST_PCLINUX64)) AND (SSS_HAVE_APPLET_NONE) AND (SSS_HAVE_HOSTCRYPTO_MBEDTLS) AND (SSS_HAVE_MBEDTLS_ALT_PSA))

    FILE(
        GLOB
        mbedtls_sources
        mbedtls/library/*.c
        mbedtls/library/*.h
        mbedtls/include/mbedtls/*.h
    )

    GET_FILENAME_COMPONENT(
        full_path_psa_its_file
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/psa_its_file.c
        ABSOLUTE
    )

    LIST(
        REMOVE_ITEM
        mbedtls_sources
        "${full_path_psa_its_file}"
    )

    LIST(
        APPEND
        mbedtls_sources
        ${SIMW_TOP_DIR}/sss/plugin/psa/port/sss_psa_its_file.c
    )

    ADD_LIBRARY(
        ${PROJECT_NAME}
        ${mbed_port_sources}
        ${mbedtls_ksdk_sources}
        ${mbedtls_sources}
        ${mbedtls_alt}
    )

    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC mbedtls/include
        PUBLIC mbedtls/library
    )

    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${SIMW_TOP_DIR}/nxp_iot_agent/port)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${SIMW_TOP_DIR}/sss/plugin/psa/inc)
    TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_USER_CONFIG_FILE=\"el2go_x86_mbedtls_psa_user_config.h\")

    IF(
        CMAKE_CXX_COMPILER
        MATCHES
        ".*clang"
        OR CMAKE_CXX_COMPILER_ID
           STREQUAL
           "AppleClang"
    )
        TARGET_COMPILE_OPTIONS(
            ${PROJECT_NAME}
            PRIVATE -Wno-unused-function
            PRIVATE -Wno-error=pointer-sign
            PRIVATE -Wno-error=format
            PRIVATE -Wno-format
            PRIVATE -Wno-error=unused-const-variable
            PRIVATE -Wno-unused-const-variable
            PRIVATE -Wno-sign-conversion
        )
	ENDIF()


    IF(
        "${CMAKE_CXX_COMPILER_ID}"
        MATCHES
        "MSVC"
    )
        IF(NXPInternal)
            TARGET_COMPILE_OPTIONS(
                ${PROJECT_NAME}
                PRIVATE /wd4245 # '=': conversion from 'int' to 'mbedtls_mpi_uint', signed/unsigned misma
                PRIVATE /wd4310 # cast truncates constant value
                PRIVATE /wd4389 # '==': signed/unsigned mismatch
                PRIVATE /wd4132 # const object should be initialized
                PRIVATE /wd4127 # conditional expression is constant
                PRIVATE /wd4701 # potentially uninitialized local variable
                PRIVATE /wd4477 # 'printf' : format string '%d'
                PRIVATE /wd4200 # nonstandard extension used
                PRIVATE /wd4703 # potentially unintialized local pointer
                PRIVATE /wd4057 # different base types
            )
        ENDIF()
    ENDIF()

    IF(
        "${CMAKE_CXX_COMPILER_ID}"
        STREQUAL
        "GNU"
    )
        TARGET_COMPILE_OPTIONS(
            ${PROJECT_NAME}
            PRIVATE -Wno-unused-function
            PRIVATE -Wno-error=pointer-sign
            PRIVATE -Wno-error=format
            PRIVATE -Wno-format
        )

        SET(GCC_VERSION_WITH_UNUSED_CONST 6.3.0)
        IF(
            GCC_VERSION_WITH_UNUSED_CONST
            VERSION_LESS
            CMAKE_CXX_COMPILER_VERSION
        )
            TARGET_COMPILE_OPTIONS(
                ${PROJECT_NAME}
                PRIVATE -Wno-error=unused-const-variable
                PRIVATE -Wno-unused-const-variable
            )
        ENDIF()
    ENDIF()

ENDIF()
