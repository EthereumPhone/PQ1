# Copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
PROJECT(nxpnfcrdlib)

FILE(
    GLOB
    nxpnfcrdlib_sources
    ${NXPNFCRdLib_DIRNAME}/comps/phalMfdfEv2/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phalMfdfEv2/src/Sw/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phpalI14443p4/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phpalI14443p4/src/Sw/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phalMfpEv1/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phalMfpEv1/src/Sw/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phTools/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phTools/src/Sw/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phLog/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phLog/src/Sw/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phKeyStore/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phKeyStore/src/Sw/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phCryptoSym/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phCryptoSym/src/Sw/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phTMIUtils/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phTMIUtils/src/Sw/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phalVca/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phalVca/src/Sw/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phCryptoRng/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phCryptoRng/src/Sw/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phpalI14443p3a/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phpalI14443p3a/src/Sw/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phpalI14443p4a/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phpalI14443p4a/src/Sw/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phpalMifare/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phhalHw/src/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phhalHw/src/Rc663/*.c
    ${NXPNFCRdLib_DIRNAME}/comps/phpalMifare/src/Sw/*.c
    nxpnfcrdlib.cmake
)

IF(NFC_663_VCOM)
    FILE(
        GLOB
        nxpnfcrdlib_sources_pc
        nxpnfcrdlib_dal/pc/comps/phOsal/src/Winos/phOsal_Winos.c
        nxpnfcrdlib_dal/pc/comps/phbalReg/src/phbalReg.c
        nxpnfcrdlib_dal/pc/comps/phbalReg/src/SerialWin/phbalReg_SerialWin.c
        nxpnfcrdlib_dal/pc/comps/phbalReg/src/Delegate/phbalReg_Delegate.c
        nxpnfcrdlib_dal/pc/comps/phbalReg/src/phPlatform_Delegate.c
        nxpnfcrdlib_dal/pc/RC663/RC663_NNC_IRQTYPE.c
        ${SIMW_TOP_DIR}/demos/nxpnfcrdlib/common/pc/*.c
        ${SIMW_TOP_DIR}/demos/nxpnfcrdlib/common/pc/*.h
    )
ENDIF()

IF(NFC_663_SPI)
    FILE(
        GLOB
        nxpnfcrdlib_sources_embedded
        ${SIMW_TOP_DIR}/ext/nxpnfcrdlib_rtos/phOsal/src/NullOs/phOsal_NullOs.c
        ${SIMW_TOP_DIR}/ext/nxpnfcrdlib_rtos/phOsal/src/NullOs/portable/phOsal_Port_CM3.c
        ${SIMW_TOP_DIR}/ext/nxpnfcrdlib_dal/src/KinetisSDK/${KSDK_BoardName}/*.c
    )
ENDIF()

ADD_LIBRARY(
    ${PROJECT_NAME}
    ${nxpnfcrdlib_sources}
    ${nxpnfcrdlib_sources_pc}
    ${nxpnfcrdlib_sources_embedded}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ${NXPNFCRdLib_DIRNAME}/intfs
    PUBLIC ${NXPNFCRdLib_DIRNAME}/types
    PUBLIC nxpnfcrdlib_rtos/phOsal
    PUBLIC
        nxpnfcrdlib_dal/phUcBal/inc
        # PUBLIC nxpnfcrdlib_dal/inc
        # PUBLIC nxpnfcrdlib_dal/cfg
        # PUBLIC nxpnfcrdlib_dal/boards
)

IF(NFC_663_VCOM)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ${SIMW_TOP_DIR}/demos/nxpnfcrdlib/common/pc
        PUBLIC nxpnfcrdlib_dal/pc/comps/phOsal/
        PUBLIC nxpnfcrdlib_dal/pc/intfs
        PUBLIC nxpnfcrdlib_dal/pc/comps/phbalReg/inc
        PUBLIC nxpnfcrdlib_dal/pc/comps/phbalReg/src/SerialWin/
        PUBLIC nxpnfcrdlib_dal/phUcBal/src/port/x86/
        PUBLIC ${SIMW_TOP_DIR}/demos/nxpnfcrdlib/common/intfs
    )
ENDIF()

IF(NFC_663_SPI)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC nxpnfcrdlib_dal/inc/
        PUBLIC ${SIMW_TOP_DIR}/demos/nxpnfcrdlib/common/ksdk
        PUBLIC ${SIMW_TOP_DIR}/ext/nxpnfcrdlib_rtos/phOsal/inc
        PUBLIC ${SIMW_TOP_DIR}/ext/nxpnfcrdlib_dal/cfg
        PUBLIC ${SIMW_TOP_DIR}/ext/nxpnfcrdlib_dal/boards
        PUBLIC ${SIMW_TOP_DIR}/demos/nxpnfcrdlib/common/intfs
    )

    IF(SSS_HAVE_HOST_FRDMK64F)
        TARGET_COMPILE_DEFINITIONS(
            ${PROJECT_NAME}
            PUBLIC PHDRIVER_FRDM_K64FRC663_BOARD
            PUBLIC PH_OSAL_NULLOS
        )
    ENDIF()

    IF(SSS_HAVE_HOST_EVKMIMXRT1060)
        TARGET_COMPILE_DEFINITIONS(
            ${PROJECT_NAME}
            PUBLIC PHDRIVER_IMXRT1060RC663_BOARD
            PUBLIC PH_OSAL_NULLOS
        )
    ENDIF()

    IF(SSS_HAVE_HOST_LPCXPRESSO55S)
        TARGET_COMPILE_DEFINITIONS(
            ${PROJECT_NAME}
            PUBLIC PHDRIVER_LPC55S69RC663_BOARD
            PUBLIC PH_OSAL_NULLOS
        )
    ENDIF()

ENDIF()

TARGET_COMPILE_DEFINITIONS(
    ${PROJECT_NAME} PUBLIC NXPBUILD_CUSTOMER_HEADER_INCLUDED
                           # PUBLIC PH_OSAL_LINUX
)

IF(
    "${CMAKE_C_COMPILER_ID}"
    STREQUAL
    ".*Clang"
)
    # using Clang
    ADD_DEFINITIONS("-Wno-parentheses-equality")
ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    IF(NXPInternal)
        TARGET_COMPILE_OPTIONS(
            ${PROJECT_NAME}
            PRIVATE /wd4018 # signed/unsigned mismatch
            PRIVATE /wd4090 # 'function': different 'volatile' qualifiers
            PRIVATE /wd4310 # cast truncates constant value
            PRIVATE /wd4305 # '=': truncation from 'double' to 'float32_t'
            PRIVATE /wd4127 # conditional expression is constant
            PRIVATE /wd4047 # '==': 'int' differs in levels of indirection from 'void *'
            PRIVATE /wd4189 #  'zzzzz': local variable is initialized but not referenced
        )
    ENDIF()
ENDIF()

SIMW_DISABLE_EXTRA_WARNINGS(${PROJECT_NAME})
