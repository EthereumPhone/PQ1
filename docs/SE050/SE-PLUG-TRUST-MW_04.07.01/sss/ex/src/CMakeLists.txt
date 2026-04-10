#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(ex_common)

FILE(
    GLOB
    files
    ex_sss_boot_connectstring.c
    ex_sss_boot.c
    *.h
    ../inc/*.h
)

IF(SSS_HAVE_APPLET_A71CL OR SSS_HAVE_APPLET_SE05X_L)
    FILE(
        GLOB
        ax_files
        ../../../hostlib/hostLib/libCommon/infra/sm_app_boot.c
        ex_sss_a71cl.c
    )
ENDIF()

IF(SSS_HAVE_APPLET_SE05X_IOT)
    FILE(
        GLOB
        ax_files
        ../../../hostlib/hostLib/libCommon/infra/sm_app_boot.c
        ex_sss_se05x.c
        ex_sss_se05x_auth.c
        ex_sss_se.c
        ex_sss_se_auth.c
        ex_sss_scp03_auth.c
    )
ENDIF()

IF(SSS_HAVE_APPLET_LOOPBACK)
    FILE(
        GLOB
        ax_files
        ../../../hostlib/hostLib/libCommon/infra/sm_app_boot.c
        ex_sss_se.c
    )
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS OR SSS_HAVE_HOSTCRYPTO_OPENSSL)
    FILE(
        GLOB
        mbedtls_files
        ex_sss_boot_sw.c
    )
ENDIF()
IF(SSS_HAVE_KSDK)
    FILE(
        GLOB
        ksdk_files
        ex_sss_boot_direct.c
        ex_sss_boot_direct_*.c
        ex_sss_boot_freertos.c
    )
ENDIF()

ADD_LIBRARY(
    ${PROJECT_NAME}
    ${files}
    ${ax_files}
    ${mbedtls_files}
    ${ksdk_files}
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} SSS_APIs
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ../inc
)

IF(UWBIOT_HOST_LINUX_LIKE)
    INSTALL(
        FILES
            ../inc/ex_sss.h
            ../inc/ex_sss_boot.h
            ../inc/ex_sss_ports.h
            ../inc/ex_sss_main_inc.h
            ../inc/ex_sss_auth.h
            ../inc/ex_sss_objid.h
            ../inc/ex_sss_ports.h
            ../inc/ex_sss_scp03_keys.h
            ../inc/ex_sss_tp_scp03_keys.h
        DESTINATION
            ${UWBIOT_INSTALL_INC_DIR}
    )
    UWBIOT_INSTALL_LIBRARY(
        ${PROJECT_NAME}
    )
ELSEIF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
    INSTALL(
        FILES
            ../inc/ex_sss.h
            ../inc/ex_sss_boot.h
            ../inc/ex_sss_ports.h
            ../inc/ex_sss_main_inc.h
            ../inc/ex_sss_auth.h
            ../inc/ex_sss_objid.h
            ../inc/ex_sss_ports.h
            ../inc/ex_sss_scp03_keys.h
            ../inc/ex_sss_tp_scp03_keys.h
        DESTINATION ${SIMW_INSTALL_INC_DIR}
    )
ENDIF()

EXPOSE_SE05X_AUTH_STRATEGY()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    IF(NXPInternal)
        TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE /wd4127 # conditional expression is constant
        )
    ENDIF()
ENDIF()
