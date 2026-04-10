#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(ex_policy)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${PROJECT_NAME}.c
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
)
EXPOSE_SE05X_AUTH_STRATEGY()
CREATE_BINARY(${PROJECT_NAME})

IF(
    CMAKE_BUILD_TYPE
    STREQUAL
    "Release"
)
    COPY_TO_SOURCEDIR(
        ${PROJECT_NAME}
        binaries/ex
        ${SMCOM}-${SE05X_Auth}
    )
ENDIF()

#PROJECT(generate_certificate_key)
#ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE} ${PROJECT_NAME}.c)
#TARGET_LINK_LIBRARIES(
#    ${PROJECT_NAME}
#    ex_common
#    SSS_APIs
#)
#CREATE_BINARY(${PROJECT_NAME})
