#
# Copyright 2019,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
# ksdk_evkmimxrt1060.cmake

FILE(
    GLOB
    KSDK_STARTUP_FILE
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/gcc/*.S
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/xip/*_flexspi_nor_config.c
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/xip/*_sdram_ini_dcd.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/xip/fsl_flexspi_nor_boot.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/misc_utilities/fsl_syscall_stub.c
)

ADD_DEFINITIONS(
    -DCPU_MIMXRT1062DVL6A
    -DCPU_MIMXRT1062DVL6A_cm7
    -DXIP_EXTERNAL_FLASH=1
    -DXIP_BOOT_HEADER_ENABLE=1
    # -DXIP_BOOT_HEADER_DCD_ENABLE=1
    -DMIMXRT1060_EVK
    -DFSL_FEATURE_PHYKSZ8081_USE_RMII50M_MODE
    -DIMX_RT
    -DEXAMPLE_USE_100M_ENET_PORT
    -DNXP_IOT_AGENT_USE_COREJSON
)

IF(SSS_HAVE_RTOS_DEFAULT)
    ADD_DEFINITIONS(-DFSL_RTOS_BM -DSDK_OS_BAREMETAL)
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    ADD_DEFINITIONS(-DFSL_RTOS_FREE_RTOS)
ENDIF()

INCLUDE_DIRECTORIES(demos/ksdk/common/boards/evkmimxrt1060/se_hostlib_examples/mainA71CH)

SET(_FLAGS_CPU " -mcpu=cortex-m7 -mfpu=fpv5-sp-d16 -mfloat-abi=hard ")
SET(_FLAGS_L_SPECS "--specs=nano.specs --specs=nosys.specs ")
IF(SSS_HAVE_RTOS_FREERTOS)
    SET(
        _FLAGS_L_MEM
        " \
    -Xlinker --defsym=__ram_vector_table__=1 \
    -Xlinker --defsym=__stack_size__=0x2000 \
    -Xlinker --defsym=__heap_size__=0x8000 "
    )
ENDIF()
IF(SSS_HAVE_RTOS_DEFAULT)
    SET(
        _FLAGS_L_MEM
        " \
    -Xlinker --defsym=__ram_vector_table__=1 \
    -Xlinker --defsym=__stack_size__=0x1000 \
    -Xlinker --defsym=__heap_size__=0x1000 "
    )
ENDIF()
SET(
    _FLAGS_L_LD
    " \
-T${SIMW_TOP_DIR}/ext/mcu-sdk/devices/MIMXRT1062/gcc/RTOS_${RTOS}/MIMXRT1062xxxxx_flexspi_nor.ld \
-static "
)
