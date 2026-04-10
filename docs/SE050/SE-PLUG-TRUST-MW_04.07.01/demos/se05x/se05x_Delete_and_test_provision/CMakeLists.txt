#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(se05x_Delete_and_test_provision)

FILE(
    GLOB
    files
    se05x_Delete_and_test_provision.c
    se05x_Delete_and_test_provision_common.c
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
        COPY_TO_SOURCEDIR(
            ${PROJECT_NAME}
            binaries/${Host}
            ${SMCOM}-${SE05X_Auth}
        )
    ENDIF()
ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    # 1900 matches VS2015
    IF(
        ${MSVC_VERSION}
        LESS_EQUAL
        1900
    )
        TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PUBLIC /wd4127 # conditional expression is constant
        )
    ENDIF()
ENDIF()

###################

IF(NXPInternal)
    PROJECT(se05x_Delete_and_test_provision_internal)

    FILE(
        GLOB
        files
        se05x_Delete_and_test_provision_internal.c
        se05x_Delete_and_test_provision_common.c
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
            COPY_TO_SOURCEDIR(
                ${PROJECT_NAME}
                binaries/${Host}/tst
                ${SMCOM}-${SE05X_Auth}
            )
        ENDIF()
    ENDIF()

    IF(
        "${CMAKE_CXX_COMPILER_ID}"
        MATCHES
        "MSVC"
    )
        # 1900 matches VS2015
        IF(
            ${MSVC_VERSION}
            LESS_EQUAL
            1900
        )
            TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PUBLIC /wd4127 # conditional expression is constant
            )
        ENDIF()
    ENDIF()
ENDIF()