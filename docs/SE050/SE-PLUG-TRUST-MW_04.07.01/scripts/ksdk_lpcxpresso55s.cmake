# Copyright 2019,2025 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
# ksdk_lpcxpresso55s69.cmake

IF(SSS_HAVE_HOST_LPCXPRESSO55S_S)
    FILE(
        GLOB
        KSDK_VENEER_FILES
        ${SIMW_TOP_DIR}/demos/lpc55s/tzm/tzm_DummyTZEntry.c
        ${SIMW_TOP_DIR}/demos/lpc55s/tzm/tzm_SystemInitHook.c
    )
ENDIF()

FILE(
    GLOB
    KSDK_STARTUP_FILE
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/gcc/startup_LPC55S69_cm33_core0.S
    ${KSDK_VENEER_FILES}
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/misc_utilities/fsl_syscall_stub.c
)

ADD_DEFINITIONS(
    -DLPC_55x
    -DA_LITTLE_ENDIAN
    -DCPU_LPC55S69JBD100_cm33_core0
    -DCPU_LPC55S69JBD100
    -DCPU_LPC55S69JBD100_cm33
    -DARM_MATH_CM33
    -D__MULTICORE_MASTER
    -DNXP_IOT_AGENT_USE_COREJSON
)

IF(SSS_HAVE_HOST_LPCXPRESSO55S_S)
    ADD_DEFINITIONS(-mcmse)
    ADD_DEFINITIONS(-DSECURE_WORLD)
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S_NS)
    ADD_DEFINITIONS(-D__SEMIHOST_HARDFAULT_DISABLE)
    ADD_DEFINITIONS(-DNONSECURE_WORLD)
ENDIF()

INCLUDE_DIRECTORIES(
    demos/ksdk/common/boards/lpcxpresso55s69/se_hostlib_examples/cloud_demo hostlib/hostlib/platform/ksdk
)

SET(_FLAGS_CPU " -mcpu=cortex-m33 -mfpu=fpv5-sp-d16 -mfloat-abi=hard ")
SET(_FLAGS_L_SPECS " --specs=nano.specs --specs=nosys.specs ")

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
    -Xlinker --defsym=__stack_size__=0x6F00 \
    -Xlinker --defsym=__heap_size__=0x4000 "
    )
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    SET(_LD_FILE_ForWorld "LPC55S69_cm33_core0_flash.ld")
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S_NS)
    SET(_LD_FILE_ForWorld "LPC55S69_cm33_core0_flash_ns.ld")
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S_S)
    IF(SSS_HAVE_SBL_SBL_LPC55S)
        SET(_LD_FILE_ForWorld "LPC55S69_cm33_core0_flash_s_sbl_app.ld")
    ELSE()
        SET(_LD_FILE_ForWorld "LPC55S69_cm33_core0_flash_s.ld")
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S_S)
    SET(
        _FLAGS_L_CMSE
        " \
 -Xlinker \
 --cmse-implib \
"
    )
ENDIF()

SET(
    _FLAGS_L_LD
    " -lpower_hardabi \
    ${_FLAGS_L_CMSE} \
    -T${SIMW_TOP_DIR}/ext/mcu-sdk/devices/LPC55S69/gcc/${_LD_FILE_ForWorld} \
    -static "
)

LINK_DIRECTORIES(${SIMW_TOP_DIR}/ext/mcu-sdk/devices/LPC55S69/gcc)
