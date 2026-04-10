# Copyright 2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
#
PROJECT(se05x_TransportUnLock)

FILE(
    GLOB
    files
    *.c
    ../se05x_TransportAuth/*.c
    ../se05x_TransportAuth/*.h
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ../se05x_TransportAuth
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
    COPY_TO_SOURCEDIR(
        ${PROJECT_NAME}
        binaries/tst
        ${SMCOM}-${SE05X_Auth}
    )
ENDIF()
