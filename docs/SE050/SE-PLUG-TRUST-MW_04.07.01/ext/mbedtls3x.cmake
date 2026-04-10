# Copyright 2024-2025 NXP
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
    mbedtls3x.cmake
    mbedtls3x/library/*.c
    mbedtls3x/library/*.h
    mbedtls3x/include/mbedtls/*.h
)

IF(SSS_HAVE_MBEDTLS_ALT_SSS)
    LIST(REMOVE_ITEM mbedtls_sources "${SIMW_TOP_DIR}/ext/mbedtls3x/library/ctr_drbg.c")
    LIST(REMOVE_ITEM mbedtls_sources "${SIMW_TOP_DIR}/ext/mbedtls3x/library/pkparse.c")
    LIST(REMOVE_ITEM mbedtls_sources "${SIMW_TOP_DIR}/ext/mbedtls3x/library/ecp.c")

    FILE(
        GLOB
        mbedtls_sss_alt_sources
        ${SIMW_TOP_DIR}/sss/plugin/mbedtls3x/ecdsa_sign_alt.c
        ${SIMW_TOP_DIR}/sss/plugin/mbedtls3x/ecdsa_verify_alt.c
        ${SIMW_TOP_DIR}/sss/plugin/mbedtls3x/rsa_alt.c
        ${SIMW_TOP_DIR}/sss/plugin/mbedtls3x/ecdh_alt.c
        ${SIMW_TOP_DIR}/sss/plugin/mbedtls3x/ctr_drbg_alt.c
        ${SIMW_TOP_DIR}/sss/plugin/mbedtls3x/pkparse_alt.c
        ${SIMW_TOP_DIR}/sss/plugin/mbedtls3x/ecp_alt.c
    )
ENDIF()

ADD_LIBRARY(
    ${PROJECT_NAME}
    ${mbedtls_sources}
    ${mbedtls_sss_alt_sources}
)

IF(SSS_HAVE_KSDK)
    TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_CONFIG_FILE=\"mbedtls_config_ksdk.h\")
    # Note - ALT implementation is not tested on KSDK.
ELSE()
    IF(SSS_HAVE_MBEDTLS_ALT_SSS)
        TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PUBLIC MBEDTLS_CONFIG_FILE=\"mbedtls_sss_alt_config.h\")
    ENDIF()
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC mbedtls3x/include
    PUBLIC mbedtls3x/library
    PUBLIC ${SIMW_TOP_DIR}/sss/plugin/mbedtls3x
    PUBLIC ${SIMW_TOP_DIR}/sss/inc
    PUBLIC ${SIMW_TOP_DIR}/sss/ex/inc
    PUBLIC ${SIMW_TOP_DIR}/hostlib/hostLib/
    PUBLIC ${SIMW_TOP_DIR}/hostlib/hostLib/inc
    PUBLIC ${SIMW_TOP_DIR}/sss/plugin/mbedtls3x/ksdk_config
)

IF((SSS_HAVE_MBEDTLS_ALT) AND (NOT SSS_HAVE_LOG_SEGGERRTT))
    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        mwlog
    )
ENDIF()

IF(SSS_HAVE_MBEDTLS_ALT)
    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        ex_common
    )
ENDIF()

IF(SSS_HAVE_KSDK)
    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        board
        _mmcau
    )
ELSE() # KSDK
ENDIF()

IF(
    "${CMAKE_C_COMPILER}"
    MATCHES
    ".*clang"
    OR "${CMAKE_CXX_COMPILER_ID}"
       STREQUAL
       "AppleClang"
)
    # MESSAGE(STATUS "-- No warning for mbedtls")
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-unused-function
        PRIVATE -Wno-error=pointer-sign
        PRIVATE -Wno-error=format
        PRIVATE -Wno-error=unused-const-variable
        PRIVATE -Wno-unused-const-variable
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
            PUBLIC /wd4127 # conditional expression is constant
            PRIVATE /wd4701 # potentially uninitialized local variable
            PRIVATE /wd4477 # 'printf' : format string '%d'
            PUBLIC /wd4200 # zero-sized array in struct/union
            PRIVATE /wd4057 # mbedtls code warning
            PRIVATE /wd4295 # array is too small to include a terminating null character
            PRIVATE /wd4706 # assignment within conditional expression
        )
    ENDIF()

    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        Bcrypt
    )

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
    )

    SET(GCC_VERSION_WITH_UNUSED_CONST 6.3.0)
    IF(
        GCC_VERSION_WITH_UNUSED_CONST
        VERSION_LESS
        CMAKE_CXX_COMPILER_VERSION
    )
        TARGET_COMPILE_OPTIONS(
            ${PROJECT_NAME}
            PRIVATE -Wno-implicit-function-declaration
            PRIVATE -Wno-error=unused-const-variable
            PRIVATE -Wno-unused-const-variable
        )
    ENDIF()
ENDIF()

IF(WithCodeCoverage)
    IF(CMAKE_COMPILER_IS_GNUCXX)
        INCLUDE(../scripts/CodeCoverage.cmake)
        APPEND_COVERAGE_COMPILER_FLAGS()
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()
