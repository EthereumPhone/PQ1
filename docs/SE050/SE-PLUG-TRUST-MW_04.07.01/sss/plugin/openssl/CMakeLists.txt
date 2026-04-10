#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(sss_engine)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    engine/src/ax_sssEngine_main.c
    engine/src/ax_sssEngine_rand.c
    engine/src/ax_sssEngine_ecc.c
    engine/src/ax_sssEngine_pkey_meths.c
)

IF(
    SSS_HAVE_APPLET_SE05X_IOT
    OR SSS_HAVE_HOSTCRYPTO_MBEDTLS
)
    LIST(
        APPEND
        ${PROJECT_NAME}_files
        engine/src/ax_sssEngine_rsa.c
    )
ENDIF()

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
    OR SSS_HAVE_APPLET_A7XX
)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} a7x_utils)
ENDIF()

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} ${OPENSSL_LIBRARIES}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
    PUBLIC engine/inc
)

IF(
    "${CMAKE_SYSTEM_NAME}"
    STREQUAL
    "WindowsStore"
)
    SET_PROPERTY(TARGET ${PROJECT_NAME} PROPERTY VS_WINRT_COMPONENT TRUE)
ENDIF()

IF(SSS_HAVE_HOST_WIN10IOT)
    SET_TARGET_PROPERTIES(
        ${PROJECT_NAME}
        PROPERTIES LINK_FLAGS_RELEASE
                   "/defaultlib:vccorlib.lib /defaultlib:msvcrt.lib /wholearchive:smComWin10IoTWrapper.lib"
    )
    SET_TARGET_PROPERTIES(
        ${PROJECT_NAME}
        PROPERTIES LINK_FLAGS_DEBUG
                   "/defaultlib:vccorlibd.lib /defaultlib:msvcrtd.lib /wholearchive:smComWin10IoTWrapper.lib"
    )
ENDIF()

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${SIMW_TOP_DIR}/sss/plugin/openssl/bin
    COMMENT "Copy dll to ${SIMW_TOP_DIR}/sss/plugin/openssl/bin"
)

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()

IF(NXPInternal)
    ADD_SUBDIRECTORY(tst)
ENDIF()
