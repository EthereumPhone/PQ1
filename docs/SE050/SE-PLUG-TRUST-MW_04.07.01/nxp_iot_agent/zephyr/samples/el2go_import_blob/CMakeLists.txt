# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(el2go_import_blob)

target_sources(app PRIVATE
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/apps/psa_examples/el2go_import_blob/el2go_import_blob.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/apps/psa_examples/el2go_import_blob/el2go_psa_import.c
)

zephyr_include_directories(
    $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/api_ns/interface/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/apps/psa_examples/el2go_import_blob
)

if(CONFIG_VALIDATE_PSA_IMPORT_OPERATION)
    target_compile_definitions(app PRIVATE VALIDATE_PSA_IMPORT_OPERATION=1)
endif()
