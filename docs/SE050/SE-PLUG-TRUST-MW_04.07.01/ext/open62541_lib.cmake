# Copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(open62541_lib)

SET(OPEN62541_VER_MAJOR 0)
SET(OPEN62541_VER_MINOR 0)
SET(OPEN62541_VER_PATCH 0)
SET(OPEN62541_VER_LABEL "-")
SET(OPEN62541_VER_COMMIT "-")
SET(UA_LOGLEVEL 300)

SET(UA_ENABLE_METHODCALLS 1)
SET(UA_ENABLE_NODEMANAGEMENT 1)
SET(UA_ENABLE_SUBSCRIPTIONS 1)
SET(UA_ENABLE_DA 1)
SET(UA_ENABLE_ENCRYPTION 1)
SET(UA_MULTITHREADING 0)
SET(UA_ENABLE_STATUSCODE_DESCRIPTIONS 1)
SET(UA_ENABLE_TYPEDESCRIPTION 1)
SET(UA_ENABLE_NODESET_COMPILER_DESCRIPTIONS 1)
SET(UA_ENABLE_DISCOVERY 1)
SET(UA_ENABLE_DISCOVERY_SEMAPHORE 1)
SET(UA_VALGRIND_INTERACTIVE_INTERVAL 1000)
SET(UA_GENERATED_NAMESPACE_ZERO 1)
SET(UA_DEBUG 1)

IF(SSS_HAVE_HOST_PCWINDOWS)
    SET(UA_ARCHITECTURE "win32")
ELSEIF(
    SSS_HAVE_HOST_IMXLINUX
    OR SSS_HAVE_HOST_PCLINUX64
    OR SSS_HAVE_HOST_RASPBIAN
)
    SET(UA_ARCHITECTURE "posix")
ENDIF()

SET(
    UA_ARCHITECTURES_NODEF
    "1  && !defined(UA_ARCHITECTURE_ECOS) && !defined(UA_ARCHITECTURE_FREERTOSLWIP) && !defined(UA_ARCHITECTURE_POSIX) && !defined(UA_ARCHITECTURE_VXWORKS) && !defined(UA_ARCHITECTURE_WEC7) && !defined(UA_ARCHITECTURE_WIN32)"
)

CONFIGURE_FILE(
    ${CMAKE_CURRENT_SOURCE_DIR}/open62541/include/open62541/config.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/open62541/build/src_generated/open62541/config.h
)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    ${CMAKE_CURRENT_SOURCE_DIR}/../sss/plugin/open62541/plugins/securityPolicies/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../sss/plugin/open62541/sss_interface.c
    open62541/arch/network_tcp.c
    open62541/build/src_generated/open62541/*.c
    open62541/deps/base64.c
    open62541/deps/libc_time.c
    open62541/deps/pcg_basic.c
    open62541/plugins/securityPolicies/securitypolicy_mbedtls_common.c
    open62541/plugins/securityPolicies/ua_securitypolicy_none.c
    open62541/plugins/ua_accesscontrol_default.c
    open62541/plugins/ua_config_default.c
    open62541/plugins/ua_log_stdout.c
    open62541/plugins/ua_nodestore_default.c
    open62541/plugins/ua_pki_default.c
    open62541/src/client/*.c
    open62541/src/pubsub/ua_pubsub.c
    open62541/src/pubsub/ua_pubsub_manager.c
    open62541/src/pubsub/ua_pubsub_networkmessage.c
    open62541/src/pubsub/ua_pubsub_ns0.c
    open62541/src/server/*.c
    open62541/src/ua_connection.c
    open62541/src/ua_securechannel.c
    open62541/src/ua_timer.c
    open62541/src/ua_types.c
    open62541/src/ua_types_encoding_binary.c
    open62541/src/ua_util.c
    open62541/src/ua_workqueue.c
)

IF(SSS_HAVE_HOST_PCWINDOWS)
    LIST(
        APPEND
        ${PROJECT_NAME}_files
        open62541/arch/win32/ua_clock.c
        open62541/arch/win32/ua_architecture_functions.c
    )
ELSEIF(
    SSS_HAVE_HOST_IMXLINUX
    OR SSS_HAVE_HOST_PCLINUX64
    OR SSS_HAVE_HOST_RASPBIAN
)
    LIST(
        APPEND
        ${PROJECT_NAME}_files
        open62541/arch/posix/ua_clock.c
        open62541/arch/posix/ua_architecture_functions.c
    )
ENDIF()

ADD_LIBRARY(${PROJECT_NAME} ${${PROJECT_NAME}_files})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ex_common)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC open62541/include
    PUBLIC open62541/plugins/include
    PUBLIC open62541/examples
    PUBLIC open62541/build/src_generated/
    PUBLIC open62541/arch
    PUBLIC open62541/deps
    PUBLIC open62541/src
    PUBLIC open62541/src/server
    PUBLIC open62541/src/client
    PUBLIC mbedtls/include
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../sss/plugin/open62541
)

IF(SSS_HAVE_HOST_PCWINDOWS)
    ADD_DEFINITIONS(-DUA_ARCHITECTURE_WIN32)
    ADD_COMPILE_DEFINITIONS(PCWindows=1)
ELSEIF(
    SSS_HAVE_HOST_IMXLINUX
    OR SSS_HAVE_HOST_PCLINUX64
    OR SSS_HAVE_HOST_RASPBIAN
)
    ADD_DEFINITIONS(-DUA_ARCHITECTURE_POSIX)
ENDIF()

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
    # 1900 matches VS2015
    IF(
        ${MSVC_VERSION}
        LESS_EQUAL
        1900
    )
        TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE /wd4127 # conditional expression is constant
        )
    ENDIF()
ENDIF()
