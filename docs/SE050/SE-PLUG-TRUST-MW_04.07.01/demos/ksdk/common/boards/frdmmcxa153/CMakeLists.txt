#
# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

# frdmmcxa153

PROJECT(board)

FILE(
    GLOB
    board_files
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/ax_reset.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/i2c_mcxa.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/se05x_reset.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/se_pit_config.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/timer_kinetis.c
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/*.c
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/*.h
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/common/pin_mux.c
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/common/pin_mux.h
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/serial_manager/*.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/uart/fsl_adapter_lpuart.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/lists/fsl_component_generic_list.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/misc_utilities/fsl_memcpy.S
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/misc_utilities/fsl_sbrk.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/misc_utilities/fsl_syscall_stub.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/periph/*.h
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_clock.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_common.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_common_arm.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_gpio.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_lpi2c.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_lpuart.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_spc.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_reset.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/system_${KSDK_CPUName}.c
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
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/periph
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/osa
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/misc_utilities
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/lists
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/phy
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/gpio
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
    board -Wl,--end-group
)
