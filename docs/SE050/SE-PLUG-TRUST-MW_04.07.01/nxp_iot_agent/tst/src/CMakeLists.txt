# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(nxp_iot_agent_test_common)

FILE(
    GLOB
        ${PROJECT_NAME}_files
        *.h
        ../inc/*.h
)

IF(SSSFTR_SW_TESTCOUNTERPART)
    FILE(
        GLOB
            ${PROJECT_NAME}_cp_files
            ./nxp_iot_agent_tst_fixture.c
            ./nxp_iot_agent_tst_fixture_cp.c
    )
ELSE()
    FILE(
        GLOB
            ${PROJECT_NAME}_cp_files
            ./nxp_iot_agent_tst_fixture.c
    )
ENDIF()

ADD_LIBRARY(${PROJECT_NAME} ${${PROJECT_NAME}_files} ${${PROJECT_NAME}_cp_files} ${${PROJECT_NAME}_ax_files})

IF(SSS_HAVE_APPLET_SE05X_IOT)
TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
)
ENDIF()

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    unity
    nxp_iot_agent
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ../inc
)
