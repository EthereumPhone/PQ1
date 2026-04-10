# Copyright 2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
#
PROJECT(sems_lite_cli_app)

FILE(
    GLOB
        mfa_files
        mfa_*.c
        mfa_*.h
)

IF(NXPInternal)
    FILE(
        GLOB
            nxp_files
            nxp_mfa_*.c
            nxp_mfa_*.h
    )
ENDIF()

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE}
    ${mfa_files}
    ${nxp_files}
)

IF(NXPInternal)
    TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME}
        PRIVATE
        NXP_INTERNAL_IMPL=1
    )
ENDIF(NXPInternal)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SEMS_LITE_AGENT_APIs
)

CREATE_BINARY(${PROJECT_NAME})

IF(
    CMAKE_BUILD_TYPE
    STREQUAL
    "Release"
)
    COPY_TO_SOURCEDIR(
        ${PROJECT_NAME}
        binaries/${Host}
        ${SMCOM}
    )
ENDIF()