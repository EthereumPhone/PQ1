# Copyright 2019,2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(unity)

IF(NXPInternal)
    SET(csv_to_junit_xml csv_to_junit_xml.py)
ENDIF()

ADD_LIBRARY(
    unity
    ${csv_to_junit_xml}
    unity.c
    unity.h
    unity_fixture.c
    unity_fixture.h
    unity_fixture_addin.c
    unity_fixture_internals.h
    unity_fixture_malloc_overrides.h
    unity_internals.h
)

# add_definitions(-DUNITY_OUTPUT_COLOR)
ADD_DEFINITIONS(-DUNITY_INCLUDE_CONFIG_H)

TARGET_COMPILE_DEFINITIONS(unity PRIVATE UNITY_REPEAT_TEST_NAME)

TARGET_INCLUDE_DIRECTORIES(unity PUBLIC .)

IF(SSS_HAVE_LOG_SEGGERRTT)
    TARGET_LINK_LIBRARIES(unity seggerrtt)
ENDIF()

TARGET_LINK_LIBRARIES(unity smCom)
