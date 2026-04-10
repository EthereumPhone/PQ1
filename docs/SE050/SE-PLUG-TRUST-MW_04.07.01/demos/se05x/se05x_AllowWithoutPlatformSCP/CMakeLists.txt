#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(se05x_AllowWithoutPlatformSCP)

FILE(
    GLOB
    files
    *.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
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
                "se050_AllowWithoutPlatformSCP"
                binaries/${Host}/tst
                ${SMCOM}-${SE05X_Auth}
            )
        ELSE()
            COPY_TO_SOURCEDIR(
                ${PROJECT_NAME}
                binaries/${Host}/tst
                ${SMCOM}-${SE05X_Auth}
            )
        ENDIF()
    ENDIF()
ENDIF()
