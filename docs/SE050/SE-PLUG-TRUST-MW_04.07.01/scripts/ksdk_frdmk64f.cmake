#
# Copyright 2019,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
# ksdk_frdmk64f.cmake

FILE(
    GLOB
    KSDK_STARTUP_FILE
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/gcc/*.S
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/misc_utilities/fsl_syscall_stub.c
)

# -fstack-usage

ADD_DEFINITIONS(
    -DCPU_MK64FN1M0VLL12
    -DCPU_MK64FN1M0VLL12_cm4
    -DFRDM_K64F
    -DFREEDOM
    -DEXAMPLE_USE_100M_ENET_PORT
    -DNXP_IOT_AGENT_USE_COREJSON
)

INCLUDE_DIRECTORIES(demos/ksdk/common/boards/frdmk64f/se_hostlib_examples/cloud_demo hostlib/hostlib/platform/ksdk)

SET(_FLAGS_CPU " -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16 ")
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
    -Xlinker --defsym=__stack_size__=0x200 \
    -Xlinker --defsym=__heap_size__=0x200 "
    )
ENDIF()
SET(
    _FLAGS_L_LD
    " \
    -T${SIMW_TOP_DIR}/demos/ksdk/common/boards/frdmk64f/se_hostlib_examples/cloud_demo/linker/MK64FN1M0xxx12_flash_heap.ld \
    -static "
)
