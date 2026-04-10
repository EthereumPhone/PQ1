# Copyright 2019,2021,2023-2025 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(nxp_iot_agent_common LANGUAGES C VERSION 6.2.0)

FILE(
    GLOB
        NXP_IOT_AGENT_COMMON_FILES
        ../../inc/*.h
        ../../inc/*.h.in
        *.c
        ../../src/protobuf/*.h
        ../../src/protobuf/*.c
)

IF(SSS_HAVE_HOST_PCWINDOWS)
    FILE(
        GLOB
            NXP_IOT_AGENT_WINDOWS_FILES
            ../../src/osal/win/*.h
            ../../src/osal/win/*.h.in
            ../../src/osal/win/*.c
    )

    set(NXP_IOT_AGENT_COMMON_FILES ${NXP_IOT_AGENT_COMMON_FILES} ${NXP_IOT_AGENT_WINDOWS_FILES})
ENDIF()

IF (NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    ADD_LIBRARY(nxp_iot_agent_common SHARED ${NXP_IOT_AGENT_COMMON_FILES})
    set_target_properties(nxp_iot_agent_common PROPERTIES
        C_STANDARD 99
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR})
ELSE()
    ADD_LIBRARY(nxp_iot_agent_common ${NXP_IOT_AGENT_COMMON_FILES})
ENDIF()

TARGET_COMPILE_DEFINITIONS(
    ${PROJECT_NAME}
    PUBLIC PB_FIELD_32BIT
)

TARGET_INCLUDE_DIRECTORIES(
    nxp_iot_agent_common
    PUBLIC ../../inc
    PUBLIC ../../net_crypto
    PUBLIC ../../src/protobuf
    PUBLIC ../../../semslite/lib/inc
)

IF(SSS_HAVE_KSDK)
    TARGET_INCLUDE_DIRECTORIES(
        nxp_iot_agent_common
        PUBLIC port/ksdk
    )
ELSE()
    TARGET_INCLUDE_DIRECTORIES(
        nxp_iot_agent_common
        PUBLIC port/default
    )
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS AND NOT NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    IF(((SSS_HAVE_HOST_PCWINDOWS) OR (SSS_HAVE_HOST_PCLINUX64)) AND (SSS_HAVE_APPLET_NONE) AND (SSS_HAVE_MBEDTLS_ALT_PSA))
        TARGET_LINK_LIBRARIES(
            nxp_iot_agent_common
            mbedtls_psa
        )
    ELSE()
    TARGET_LINK_LIBRARIES(
        nxp_iot_agent_common
        mbedtls
    )
    ENDIF()
ENDIF()

IF(NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME}
    PRIVATE ../../platform/smw
    )

    FIND_PACKAGE(NXP_SMW CONFIG REQUIRED)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME}
        PRIVATE $<TARGET_PROPERTY:NXP_SMW::smw,INTERFACE_INCLUDE_DIRECTORIES>)
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_WIN10IOT)
    TARGET_INCLUDE_DIRECTORIES(
        nxp_iot_agent_common
        PUBLIC ../../src/osal/win
    )
ENDIF()


IF(SSS_HAVE_APPLET_SE05X_IOT)
    TARGET_LINK_LIBRARIES(
        nxp_iot_agent_common
        se05x
    )
ENDIF()


TARGET_COMPILE_DEFINITIONS(nxp_iot_agent_common PRIVATE PB_FIELD_32BIT)

IF(SSS_HAVE_APPLET_SE05X_IOT)
    TARGET_LINK_LIBRARIES(
        nxp_iot_agent_common
        ex_common
    )
    IF (NOT SSS_HAVE_MBEDTLS_ALT_PSA)
        TARGET_LINK_LIBRARIES(
            nxp_iot_agent_common
        smCom
        SSS_APIs
    )
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOST_LINUX_LIKE OR NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    INSTALL(TARGETS nxp_iot_agent_common DESTINATION lib)
ENDIF()
