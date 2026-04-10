#
# Copyright 2019,2020,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(sss_pkcs11)

FILE(
    GLOB
    files
    ${PROJECT_NAME}.c
)

FILE(
    GLOB
    pkcs11_files
    *.c
)

ADD_DEFINITIONS(-DPKCS11_LIBRARY)
ADD_DEFINITIONS(-DPKCS11_SESSION_OPEN)

# To generate RSA-CRT keypair
#ADD_DEFINITIONS(-DPKCS11_ENABLE_RSA_KEY_GEN_CRT)

ADD_LIBRARY(${PROJECT_NAME} SHARED ${files} ${pkcs11_files})

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    #PKCS11 Dependencies
    PRIVATE ${SIMW_TOP_DIR}/sss/plugin/pkcs11
    PRIVATE ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/pkcs11
    PRIVATE ${SIMW_TOP_DIR}/ext/freertos/corepkcs11/source/include
)

##PKCS11 Dependencies
TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ${DEMOS_KSDK_DIR}/common
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} ex_common
)

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE
            /wd4310
            /wd4267
    )
ENDIF()

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()

COPY_TO_SOURCEDIR(
    ${PROJECT_NAME}
    binaries/pkcs11
    ${SMCOM}
)

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${SIMW_TOP_DIR}/sss/plugin/pkcs11/bin
    COMMENT "Copy dll to ${SIMW_TOP_DIR}/sss/plugin/pkcs11/bin"
)
