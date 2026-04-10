#
# Copyright 2024-2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
# ksdk_frdmmcxa153.cmake

FILE(
    GLOB
    KSDK_STARTUP_FILE
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/gcc/startup_MCXA153.S
)

ADD_DEFINITIONS(
    -DCPU_MCXA153VLH
    -DMCXA 
    -DPRINTF_ADVANCED_ENABLE=1
    -DPRINTF_FLOAT_ENABLE=0
    -DSCANF_FLOAT_ENABLE=0
    -DFSL_SDK_DRIVER_QUICK_ACCESS_ENABLE=1
    -DCR_INTEGER_PRINTF
)

IF(SSS_HAVE_RTOS_FREERTOS)
    ADD_DEFINITIONS(-DFSL_RTOS_FREE_RTOS)
ENDIF()

INCLUDE_DIRECTORIES(demos/ksdk/common/boards/frdmmcxa153/common)

SET(_FLAGS_CPU " -mcpu=cortex-m33+nodsp -mthumb -mfloat-abi=soft ")
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
    -Xlinker --defsym=__stack_size__=0x2000 \
    -Xlinker --defsym=__heap_size__=0x2000 "
    )
ENDIF()

SET(
    _FLAGS_L_LD
    " \
-T${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/gcc/MCXA153_flash.ld \
-static "
)
