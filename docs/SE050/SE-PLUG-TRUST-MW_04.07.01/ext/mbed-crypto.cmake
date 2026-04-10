# Copyright 2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
#
# Manually create project. mbedTLS has it's own CMakeLists.txt
#
PROJECT(mbedtls)

FILE(
    GLOB
    mbedtls_sources
    mbedtls/library/*.c
    mbedtls/library/*.h
    mbedtls/include/mbedtls/*.h
)

IF( (NOT SSS_HAVE_HOST_LPCXPRESSO55S_NS) AND SSS_HAVE_APPLET_SE05X_IOT)

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

ELSE()

    GET_FILENAME_COMPONENT(
        full_path_psa_crypto_file
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/psa_crypto.c
        ABSOLUTE
    )

    LIST(
        REMOVE_ITEM
        mbedtls_sources
        "${full_path_psa_crypto_file}"
    )

    GET_FILENAME_COMPONENT(
        full_path_psa_crypto_slot_mgmt_file
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/psa_crypto_slot_management.c
        ABSOLUTE
    )

    LIST(
        REMOVE_ITEM
        mbedtls_sources
        "${full_path_psa_crypto_slot_mgmt_file}"
    )

ENDIF()

IF(SSS_HAVE_KSDK)
    FILE(
        GLOB
        mbed_port_sources
        ${SIMW_TOP_DIR}/demos/tfm_port/mbedcrypto_mcux_casper.c
        ${SIMW_TOP_DIR}/demos/tfm_port/mbedcrypto_mcux_hashcrypt.c
        ${SIMW_TOP_DIR}/demos/tfm_port/*.h
    )

    FILE(
        GLOB
        mbedtls_ksdk_sources
        mbedtls/port/ksdk/ksdk_mbedtls.c
        mbedtls/port/ksdk/ksdk_mbedtls.h
    )
ENDIF()

IF(SSS_HAVE_HOST_ANDROID)
    ADD_LIBRARY(
        ${PROJECT_NAME} SHARED
        ${mbed_port_sources}
        ${mbedtls_ksdk_sources}
        ${mbedtls_sources}
        ${mbedtls_alt}
    )
ELSE()
    ADD_LIBRARY(
        ${PROJECT_NAME}
        ${mbed_port_sources}
        ${mbedtls_ksdk_sources}
        ${mbedtls_sources}
        ${mbedtls_alt}
    )
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC mbedtls/include
    PUBLIC mbedtls/library
)

IF(SSS_HAVE_KSDK)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${SIMW_TOP_DIR}/demos/tfm_port)

    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC mbedtls/port/ksdk)
    TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_CONFIG_FILE=\"ksdk_mbedtls_config.h\")
    TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_USER_CONFIG_FILE=\"sss_ksdk_mbedcrypto_config.h\")

    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        board
        _mmcau
    )
ELSE() # KSDK
    TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_USER_CONFIG_FILE=\"sss_x86_mbedcrypto_config.h\")
ENDIF()

IF(NOT SSS_HAVE_HOST_LPCXPRESSO55S_S)
    IF(SSS_HAVE_APPLET_SE05X_IOT)
        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
            PSA_ALT
            SSS_APIs
        )
    ENDIF()
ENDIF()

TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${SIMW_TOP_DIR}/sss/plugin/psa/inc)

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
