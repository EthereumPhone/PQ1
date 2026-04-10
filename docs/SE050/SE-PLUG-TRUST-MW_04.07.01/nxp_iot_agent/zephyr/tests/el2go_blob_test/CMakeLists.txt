# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(el2go_blob_test)

target_sources(app PRIVATE
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tst/el2go_blob_test/src/el2go_blob_test.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tst/el2go_blob_test/src/el2go_blob_test_executor_psa.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tst/el2go_blob_test/src/el2go_blob_test_parser_psa.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tst/el2go_blob_test/src/el2go_blob_test_reader_inline.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tst/el2go_blob_test/src/el2go_blob_test_suite_generic.c
)

zephyr_include_directories(
    $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/api_ns/interface/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tst/el2go_blob_test/inc
)

if(CONFIG_RTP_JSON OR DEFINED ENV{CONFIG_RTP_JSON})
    find_package(Python REQUIRED)

    if(CONFIG_RTP_JSON)
        set(RTP_JSON ${CONFIG_RTP_JSON})
    else()
        set(RTP_JSON $ENV{CONFIG_RTP_JSON})
    endif()

    execute_process(
        COMMAND ${Python_EXECUTABLE}
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tst/el2go_blob_test/scripts/el2go_blob_test_pre.py
        ${RTP_JSON}
        OUTPUT_VARIABLE OUTPUT
        COMMAND_ERROR_IS_FATAL ANY
    )
    message(STATUS ${OUTPUT})
endif()
