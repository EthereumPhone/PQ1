# Copyright 2019,2020 NXP
#
# NXP Confidential. This software is owned or controlled by NXP and may only
# be used strictly in accordance with the applicable license terms.  By
# expressly accepting such terms or by downloading, installing, activating
# and/or otherwise using the software, you are agreeing that you have read,
# and that you agree to comply with and are bound by, such license terms.  If
# you do not agree to be bound by the applicable license terms, then you may
# not retain, install, activate or otherwise use the software.
#

# frdmk64f

PROJECT(board)

FILE(
    GLOB
    board_files
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/ax_reset.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/se05x_reset.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/se_pit_config.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/timer_kinetis.c
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/*.c
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/*.h
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/se_hostlib_examples/cloud_demo/pin_mux.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/serial_manager/*.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/uart/fsl_adapter_uart.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/lists/fsl_component_generic_list.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/phy/device/phyksz8081/fsl_phyksz8081.c
#   ${SIMW_TOP_DIR}/ext/mcu-sdk/components/phy/mdio/enet/fsl_enet_mdio.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_clock.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_ftm.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_gpio.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_dspi.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_i2c.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_pit.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_rnga.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_uart.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_enet.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/system_${KSDK_CPUName}.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/mmcau/fsl_mmcau.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/debug_console/*.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/str/*.c
)

IF((SSS_HAVE_APPLET) AND (NOT(SSS_HAVE_SMCOM_PN7150)))
    LIST(
        APPEND
        board_files
        ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/i2c_frdm.c
    )
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    LIST(
        APPEND
        board_files
        ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/timer_kinetis_freertos.c
        ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_i2c_freertos.c
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
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/lwip/src/include
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/lwip/port
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/osa
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/lists
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/phy
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/phy/device/phyksz8081
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/phy/mdio/enet
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/gpio
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
