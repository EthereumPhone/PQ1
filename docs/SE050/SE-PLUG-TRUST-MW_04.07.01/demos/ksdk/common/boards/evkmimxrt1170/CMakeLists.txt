#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

# evkmimxrt1170

PROJECT(board)

FILE(
    GLOB
    board_files
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/ax_reset.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/i2c_imxrt.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/se05x_reset.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/se_pit_config.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/timer_kinetis.c
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/*.c
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/*.h
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/se_hostlib_examples/cloud_demo/pin_mux.c
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/se_hostlib_examples/cloud_demo/pin_mux.h
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/serial_manager/*.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/uart/fsl_adapter_lpuart.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/lists/fsl_component_generic_list.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/gpio/fsl_adapter_igpio.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/phy/device/phyrtl8211f/fsl_phyrtl8211f.c
#   ${SIMW_TOP_DIR}/ext/mcu-sdk/components/phy/mdio/enet/fsl_enet_mdio.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_anatop_ai.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_clock.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_common.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_common_arm.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_dcdc.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_gpio.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_lpi2c.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_lpuart.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_pmu.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_pit.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_caam.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_cache.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_pit.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_enet.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/system_${KSDK_CPUName}_cm7.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/mmcau/fsl_mmcau.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/debug_console/*.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/str/*.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/fsl_assert.c
)

IF(SSS_HAVE_RTOS_FREERTOS)
    LIST(
        APPEND
        board_files
        ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/timer_kinetis_freertos.c
        ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_lpi2c_freertos.c
        ${SIMW_TOP_DIR}/ext/mcu-sdk/components/osa/fsl_os_abstraction_free_rtos.c
    )
ELSE()
    LIST(
        APPEND
        board_files
        ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/timer_kinetis_bm.c
        ${SIMW_TOP_DIR}/ext/mcu-sdk/components/osa/fsl_os_abstraction_bm.c
    )
ENDIF()

ADD_LIBRARY(board ${board_files})

TARGET_INCLUDE_DIRECTORIES(
    board
    PRIVATE
        ${SIMW_TOP_DIR}/hostlib/hostLib/platform/inc
        ${SIMW_TOP_DIR}/hostlib/hostLib/libCommon/infra
        ${SIMW_TOP_DIR}/hostlib/hostLib/libCommon/smCom
        ${SIMW_TOP_DIR}/hostlib/hostLib/libCommon/log
)

TARGET_INCLUDE_DIRECTORIES(
    board
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/lwip/src/include
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/lwip/port
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/osa
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/lists
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/phy
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/gpio
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/phy/device/phyrtl8211f
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/phy/mdio/enet
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/serial_manager/usb_cdc_adapter
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/debug_console
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/str
)

IF(NOT SSS_HAVE_LOG_SEGGERRTT)
    TARGET_LINK_LIBRARIES(board mwlog)
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    TARGET_LINK_LIBRARIES(board freertos-kernel)
ENDIF()

TARGET_LINK_LIBRARIES(
    board -Wl,--start-group
)
TARGET_LINK_LIBRARIES(
    board
    debug
    m
)
TARGET_LINK_LIBRARIES(
    board
    debug
    c
)
TARGET_LINK_LIBRARIES(
    board
    debug
    gcc
)
TARGET_LINK_LIBRARIES(
    board
    debug
    nosys
)
TARGET_LINK_LIBRARIES(
    board
    optimized
    m
)
TARGET_LINK_LIBRARIES(
    board
    optimized
    c
)
TARGET_LINK_LIBRARIES(
    board
    optimized
    gcc
)
TARGET_LINK_LIBRARIES(
    board
    optimized
    nosys
)
TARGET_LINK_LIBRARIES(
    board _mmcau
)
TARGET_LINK_LIBRARIES(
    board -Wl,--end-group
)
