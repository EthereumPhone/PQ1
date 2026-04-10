# Copyright 2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(PSA_ALT)

IF(SSS_HAVE_HOST_LPCXPRESSO55S_S)
    FILE(
        GLOB
        ${PROJECT_NAME}_files
        src/psa_alt.c
        src/psa_alt_utils.c
        src/sss_psa_alt.c
        src/secure/psa_secure.c
        src/secure/psa_alt_deserialize.c
        src/secure/psa_alt_se_driver.c
        src/psa_alt_flash.c
    )

ELSEIF(SSS_HAVE_HOST_LPCXPRESSO55S_NS)
    FILE(
        GLOB
        ${PROJECT_NAME}_files
        src/nonsecure/psa_alt_serialize.c
    )

ELSEIF(SSS_HAVE_HOST_LPCXPRESSO55S)
    FILE(
        GLOB
        ${PROJECT_NAME}_files
        src/psa_alt.c
        src/psa_alt_utils.c
        src/sss_psa_alt.c
        src/psa_alt_flash.c
    )

ELSE()
    FILE(
        GLOB
        ${PROJECT_NAME}_files
        src/psa_alt.c
        src/psa_alt_utils.c
        src/sss_psa_alt.c
    )

ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S_S)
    ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE} ${${PROJECT_NAME}_files})
ELSE()
    ADD_LIBRARY(${PROJECT_NAME} ${${PROJECT_NAME}_files})
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS)
    # FIXME: Only required for testing
    ADD_DEFINITIONS(-DEX_SSS_BOOT_DO_ERASE=1)
ENDIF()

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
)

IF(SSS_HAVE_APPLET_SE05X_IOT)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} se05x)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} a7x_utils)
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
    PRIVATE ${SIMW_TOP_DIR}/ext/mbedtls/include
    PUBLIC inc
)

IF(SSS_HAVE_HOST_LPCXPRESSO55S_S)
    CREATE_BINARY(${PROJECT_NAME})
ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-error=type-limits
    )
ENDIF()


SIMW_DISABLE_EXTRA_WARNINGS(${PROJECT_NAME})

#### PROJECT(psa_interface)
#### ADD_LIBRARY(psa_interface INTERFACE)
####
#### TARGET_INCLUDE_DIRECTORIES(psa_interface INTERFACE inc)
