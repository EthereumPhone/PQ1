#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(se05x_GetInfo)

FILE(
    GLOB
    files
    *.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_COMPILE_DEFINITIONS(
    ${PROJECT_NAME}
    PRIVATE SIMW_DEMO_ENABLE__DEMO_SE05X_GETINFO
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
)

CREATE_BINARY(${PROJECT_NAME})

IF(
    CMAKE_BUILD_TYPE
    STREQUAL
    "Release"
)
    IF(NOT SSS_HAVE_KSDK)
        IF(SSS_HAVE_SE05X_VER_03_XX)
            COPY_TO_SOURCEDIR_RENAME(
                ${PROJECT_NAME}
                "se050_GetInfo"
                binaries/${Host}
                ${SMCOM}-${SE05X_Auth}
            )
        ELSE()
            COPY_TO_SOURCEDIR_RENAME(
                ${PROJECT_NAME}
                "se051_GetInfo"
                binaries/${Host}
                ${SMCOM}-${SE05X_Auth}
            )
        ENDIF()
    ELSE()
        IF(SSS_HAVE_SE05X_VER_03_XX)
            COPY_TO_SOURCEDIR_RENAME(
                ${PROJECT_NAME}
                "se050_GetInfo"
                binaries/MCU/${eSEName}
                ${SMCOM}
            )
        ELSE()
            COPY_TO_SOURCEDIR_RENAME(
                ${PROJECT_NAME}
                "se051_GetInfo"
                binaries/MCU/${eSEName}
                ${SMCOM}
            )
        ENDIF()
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
ENDIF()
