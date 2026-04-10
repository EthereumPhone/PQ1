#
# Copyright 2024-2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
# ksdk_frdmmcxn947.cmake

FILE(
    GLOB
    KSDK_STARTUP_FILE
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/gcc/startup_MCXN947_cm33_core0.S
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/misc_utilities/fsl_syscall_stub.c
)

ADD_DEFINITIONS(
    -DCPU_MCXN947VDF_cm33_core0
    -DMCXN
    -DPRINTF_ADVANCED_ENABLE=1
    -DPRINTF_FLOAT_ENABLE=0
    -DSCANF_FLOAT_ENABLE=0
    -DFSL_SDK_DRIVER_QUICK_ACCESS_ENABLE=1
    -DCR_INTEGER_PRINTF
    -DLPC_ENET
    -DEXAMPLE_USE_MCXN_ENET_PORT
)

IF(SSS_HAVE_RTOS_FREERTOS)
    ADD_DEFINITIONS(-DFSL_RTOS_FREE_RTOS)
ENDIF()

INCLUDE_DIRECTORIES(demos/ksdk/common/boards/frdmmcxn947/common)

SET(_FLAGS_CPU " -mcpu=cortex-m33 -mthumb -mfloat-abi=hard ")
SET(_FLAGS_L_SPECS "--specs=nano.specs --specs=nosys.specs ")

IF(SSS_HAVE_RTOS_FREERTOS)
    SET(
        _FLAGS_L_MEM
        " \
    -Xlinker --defsym=__stack_size__=0x2000 \
    -Xlinker --defsym=__heap_size__=0x8000 "
    )
ENDIF()
IF(SSS_HAVE_RTOS_DEFAULT)
    SET(
        _FLAGS_L_MEM
        " \
    -Xlinker --defsym=__stack_size__=0x3000 \
    -Xlinker --defsym=__heap_size__=0x4000 "
    )
ENDIF()

SET(
    _FLAGS_L_LD
    " \
-T${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/gcc/MCXN947_cm33_core0_flash.ld \
-static "
)
