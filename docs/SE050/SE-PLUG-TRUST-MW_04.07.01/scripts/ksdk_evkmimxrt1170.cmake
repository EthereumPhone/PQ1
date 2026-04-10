#
# Copyright 2019,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
# ksdk_evkmimxrt1060.cmake

FILE(
    GLOB
    KSDK_STARTUP_FILE
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/gcc/startup_MIMXRT1176_cm7.S
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/xip/*_flexspi_nor_config.c
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/xip/dcd.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/xip/fsl_flexspi_nor_boot.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/misc_utilities/fsl_syscall_stub.c
)

ADD_DEFINITIONS(
    -DIMX_RT
    -DCPU_MIMXRT1176DVMAA
    -DCPU_MIMXRT1176DVMAA_cm7
    -DUSE_SDRAM
    -DXIP_EXTERNAL_FLASH=1
    -DXIP_BOOT_HEADER_ENABLE=1
    -DPRINTF_FLOAT_ENABLE=0
    -DSCANF_FLOAT_ENABLE=0
    -DFSL_SDK_DRIVER_QUICK_ACCESS_ENABLE=1
    -DCR_INTEGER_PRINTF
    -DCRYPTO_USE_DRIVER_CAAM
    -DCACHE_MODE_WRITE_THROUGH=1
    -DNXP_IOT_AGENT_USE_COREJSON
)

IF(SSS_HAVE_RTOS_DEFAULT)
    # ADD_DEFINITIONS(-DFSL_RTOS_BM -DSDK_OS_BAREMETAL)
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    ADD_DEFINITIONS(-DFSL_RTOS_FREE_RTOS)
ENDIF()

INCLUDE_DIRECTORIES(demos/ksdk/common/boards/evkmimxrt1170/se_hostlib_examples/cloud_demo)

SET(_FLAGS_CPU " -mcpu=cortex-m7 -mfpu=fpv5-d16 -mfloat-abi=hard ")
SET(_FLAGS_L_SPECS "--specs=nano.specs --specs=nosys.specs ")

SET(
    _FLAGS_L_LD
    " \
-T${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/gcc/MIMXRT1176xxxxx_cm7_flexspi_nor.ld \
-static "
)
