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

# lpcxpresso55s

PROJECT(board)

FILE(
    GLOB
    board_files
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/ax_reset.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/i2c_lpc55sxx.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/se05x_reset.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/se_pit_config.c
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/timer_kinetis.c
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/*.c
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/*.h
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/se_hostlib_examples/cloud_demo/pin_mux.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/serial_manager/*.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/uart/fsl_adapter_usart.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/lists/generic_list.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/gpio/fsl_adapter_lpc_gpio.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/gpio/fsl_adapter_gint.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_casper.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_clock.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_common.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_common_arm.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_ctimer.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_dma.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_flexcomm.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_gpio.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_i2c.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_inputmux.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_pint.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_reset.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_spi.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_spi_dma.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_usart.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_rng.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_puf.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_iap.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_hashcrypt.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/system_${KSDK_CPUName}*.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/mmcau/fsl_mmcau.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/debug_console/*.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/str/*.c
)

IF(SSS_HAVE_HOST_LPCXPRESSO55S_S)
    FILE(
        GLOB
        lpc55s_tzm_s
        ${SIMW_TOP_DIR}/demos/lpc55s/tzm/tzm_config.c
    )
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    LIST(
        APPEND
        board_files
        ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_usart_freertos.c
        ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_i2c_freertos.c
        ${SIMW_TOP_DIR}/ext/mcu-sdk/components/osa/fsl_os_abstraction_free_rtos.c
        ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/timer_kinetis_freertos.c
    )
ELSE()
    LIST(
        APPEND
        board_files
        ${SIMW_TOP_DIR}/hostlib/hostLib/platform/ksdk/timer_kinetis_bm.c
        ${SIMW_TOP_DIR}/ext/mcu-sdk/components/osa/fsl_os_abstraction_bm.c
    )
ENDIF()

IF(NOT SSS_HAVE_HOST_LPCXPRESSO55S_NS)
    LIST(
        APPEND
        board_files
        ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_iap.c
    )
ENDIF()

ADD_LIBRARY(board ${board_files} ${lpc55s_tzm_s})

TARGET_INCLUDE_DIRECTORIES(
    board
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/serial_mwm
    PRIVATE ${SIMW_TOP_DIR}/hostlib/hostLib/platform/inc
    PRIVATE ${SIMW_TOP_DIR}/hostlib/hostLib/libCommon/infra
    PRIVATE ${SIMW_TOP_DIR}/hostlib/hostLib/libCommon/smCom
    PRIVATE ${SIMW_TOP_DIR}/hostlib/hostLib/libCommon/log
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/osa
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/lists
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/gpio
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/serial_manager/usb_cdc_adapter
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/debug_console
    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/str
)

IF(SSS_HAVE_HOST_LPCXPRESSO55S_S)
    TARGET_INCLUDE_DIRECTORIES(board PUBLIC ${SIMW_TOP_DIR}/demos/lpc55s/tzm)
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S_S OR SSS_HAVE_HOST_LPCXPRESSO55S_NS)
    TARGET_INCLUDE_DIRECTORIES(board PUBLIC ${SIMW_TOP_DIR}/demos/lpc55s/common)
ENDIF()

#TARGET_INCLUDE_DIRECTORIES(board
#    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/lwip/src/include
#    PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/lwip/port
#)

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
    board power_hardabi
)
TARGET_LINK_LIBRARIES(
    board -Wl,--end-group
)

IF(SSS_HAVE_RTOS_FREERTOS)
    PROJECT(wifi_serial_mwm)
    FILE(
        GLOB
        wifi_files
        ${SIMW_TOP_DIR}/ext/mcu-sdk/components/serial_mwm/serial_mwm.c
        ${SIMW_TOP_DIR}/ext/mcu-sdk/components/serial_mwm/serial_mwm_usart.c
    )

    ADD_LIBRARY(${PROJECT_NAME} ${wifi_files})

    TARGET_LINK_LIBRARIES(${PROJECT_NAME} board)

    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${SIMW_TOP_DIR}/ext/mcu-sdk/components/serial_mwm)
ENDIF()

SIMW_DISABLE_EXTRA_WARNINGS(${PROJECT_NAME})
