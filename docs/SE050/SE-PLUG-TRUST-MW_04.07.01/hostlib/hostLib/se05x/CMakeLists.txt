#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(se05x)

SET(Applet_Ver_dir "../se05x_03_xx_xx")

FILE(
    GLOB
    sources
    src/*.c
    src/*.h
    ../inc/Applet_SE050_Ver.h
    ${Applet_Ver_dir}/*.py
    ${Applet_Ver_dir}/*.c
    ${Applet_Ver_dir}/*.h
    ../inc/se05x*.h
)

IF(SSS_HAVE_SCP_SCP03_SSS)
    FILE(
        GLOB
        nxScp_files
        ../libCommon/nxScp/*.c
        ../inc/nxScp03_*.h
    )
ENDIF()

IF(SSS_HAVE_HOST_ANDROID)
    ADD_LIBRARY(${PROJECT_NAME} STATIC ${sources} ${nxScp_files})
ELSE()
    ADD_LIBRARY(${PROJECT_NAME} ${sources} ${nxScp_files})
ENDIF()

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} smCom
)

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} mbedtls)
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ${Applet_Ver_dir}
    PUBLIC ${SIMW_TOP_DIR}/sss/ex/inc
    PUBLIC ${SIMW_TOP_DIR}/sss/inc
    PUBLIC ../libCommon/nxScp
)

IF(SSS_HAVE_KSDK)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${SIMW_TOP_DIR}/sss/port/kinetis)
ELSE()
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${SIMW_TOP_DIR}/sss/port/x86)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    TARGET_COMPILE_DEFINITIONS(
        ${PROJECT_NAME}
        PUBLIC MBEDTLS # FIXME : Purnank : This must eventually not be needed because sss APIs should be enough
    )
ENDIF()

IF(UWBIOT_HOST_LINUX_LIKE)
    UWBIOT_INSTALL_LIBRARY(${PROJECT_NAME})
    INSTALL(
        FILES
            ../inc/se05x_enums.h
            ${Applet_Ver_dir}/../inc/Applet_SE050_Ver.h
            ${Applet_Ver_dir}/se05x_APDU.h
            ${Applet_Ver_dir}/se05x_APDU_apis.h
            ${Applet_Ver_dir}/se05x_04_xx_APDU_apis.h
            ${Applet_Ver_dir}/se05x_04_xx_APDU_impl.h
        DESTINATION ${UWBIOT_INSTALL_INC_DIR}
    )
ELSEIF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
    INSTALL(
        FILES
            ../inc/se05x_enums.h
            ${Applet_Ver_dir}/../inc/Applet_SE050_Ver.h
            ${Applet_Ver_dir}/se05x_APDU.h
            ${Applet_Ver_dir}/se05x_APDU_apis.h
            ${Applet_Ver_dir}/se05x_04_xx_APDU_apis.h
            ${Applet_Ver_dir}/se05x_04_xx_APDU_impl.h
        DESTINATION ${SIMW_INSTALL_INC_DIR}
    )
ENDIF()
