# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(el2go_claimcode_encryption)

target_sources(app PRIVATE
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/apps/el2go_claimcode_encryption.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/utils/iot_agent_claimcode_encrypt_els.c
)

zephyr_include_directories(
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/inc
)

# FIXME: Add ROMAPI as component when available or move to Flash API when supported and remove everything below
target_sources(app PRIVATE 
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk/devices/RW612/drivers/romapi/iap/fsl_romapi_iap.c
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk/devices/RW612/drivers/romapi/flexspi/fsl_romapi_flexspi.c
)

zephyr_include_directories(
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk/devices/RW612/drivers/romapi/iap
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk/devices/RW612/drivers/romapi/flexspi
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk/devices/RW612/drivers/romapi/nboot
    ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk/devices/RW612/drivers/romapi/bootloader
)
