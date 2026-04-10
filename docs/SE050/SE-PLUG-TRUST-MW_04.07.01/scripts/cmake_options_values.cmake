# Copyright 2018-2022,2024-2025 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
# #############################################################
# This file is generated using a script
# #############################################################
#

SET(
    PTMW_Applet
    "SE050_E"
    CACHE
        STRING
        "The Secure Element Applet"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_Applet
        PROPERTY
            STRINGS
            "None;SE05X_A;SE05X_B;SE05X_C;SE051_UWB;SE051_H;AUTH;SE050_E;LoopBack;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_Applet
        PROPERTY
            STRINGS
            "None;SE05X_A;SE05X_B;SE05X_C;SE051_H;AUTH;SE050_E;"
    )
ENDIF()

SET(
    PTMW_SE05X_Ver
    "07_02"
    CACHE
        STRING
        "Configures supported applet version."
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_SE05X_Ver
        PROPERTY
            STRINGS
            "03_XX;07_02;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_SE05X_Ver
        PROPERTY
            STRINGS
            "03_XX;07_02;"
    )
ENDIF()

SET(
    PTMW_Host
    "PCWindows"
    CACHE
        STRING
        "Host where the software stack is running"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_Host
        PROPERTY
            STRINGS
            "Darwin;PCLinux32;PCLinux64;PCWindows;Cygwin;frdmk64f;evkmimxrt1060;evkmimxrt1170;frdmmcxn947;frdmmcxa153;lpcxpresso55s;lpcxpresso55s_ns;lpcxpresso55s_s;iMXLinux;Raspbian;Android;Win10IoT;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_Host
        PROPERTY
            STRINGS
            "Darwin;PCLinux32;PCLinux64;PCWindows;Cygwin;frdmk64f;evkmimxrt1060;evkmimxrt1170;frdmmcxn947;frdmmcxa153;lpcxpresso55s;lpcxpresso55s_ns;lpcxpresso55s_s;iMXLinux;Raspbian;Android;"
    )
ENDIF()

SET(
    PTMW_SMCOM
    "VCOM"
    CACHE
        STRING
        "Communication Interface"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_SMCOM
        PROPERTY
            STRINGS
            "None;JRCP_V2;JRCP_V1;JRCP_V1_AM;VCOM;T1oI2C;T1oI2C_GP1_0;RC663_VCOM;PN7150;Thread;PCSC;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_SMCOM
        PROPERTY
            STRINGS
            "None;JRCP_V2;JRCP_V1;JRCP_V1_AM;VCOM;T1oI2C;T1oI2C_GP1_0;PCSC;"
    )
ENDIF()

SET(
    PTMW_HostCrypto
    "MBEDTLS"
    CACHE
        STRING
        "Counterpart Crypto on Host"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_HostCrypto
        PROPERTY
            STRINGS
            "MBEDTLS;OPENSSL;User;None;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_HostCrypto
        PROPERTY
            STRINGS
            "MBEDTLS;OPENSSL;User;None;"
    )
ENDIF()

SET(
    PTMW_RTOS
    "Default"
    CACHE
        STRING
        "Choice of Operating system"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_RTOS
        PROPERTY
            STRINGS
            "Default;FreeRTOS;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_RTOS
        PROPERTY
            STRINGS
            "Default;FreeRTOS;"
    )
ENDIF()

SET(
    PTMW_mbedTLS_ALT
    "None"
    CACHE
        STRING
        "ALT Engine implementation for mbedTLS"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_mbedTLS_ALT
        PROPERTY
            STRINGS
            "SSS;PSA;None;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_mbedTLS_ALT
        PROPERTY
            STRINGS
            "SSS;PSA;None;"
    )
ENDIF()

SET(
    PTMW_SCP
    "None"
    CACHE
        STRING
        "Secure Channel Protocol"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_SCP
        PROPERTY
            STRINGS
            "None;SCP03_SSS;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_SCP
        PROPERTY
            STRINGS
            "None;SCP03_SSS;"
    )
ENDIF()

SET(
    PTMW_FIPS
    "None"
    CACHE
        STRING
        "Enable or disable FIPS"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_FIPS
        PROPERTY
            STRINGS
            "None;SE050;140_2;140_3;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_FIPS
        PROPERTY
            STRINGS
            "None;SE050;"
    )
ENDIF()

SET(
    PTMW_SBL
    "None"
    CACHE
        STRING
        "Enable/Disable SBL Bootable support"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_SBL
        PROPERTY
            STRINGS
            "None;SBL_LPC55S;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_SBL
        PROPERTY
            STRINGS
            "None;SBL_LPC55S;"
    )
ENDIF()

SET(
    PTMW_SE05X_Auth
    "None"
    CACHE
        STRING
        "SE050 Authentication"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_SE05X_Auth
        PROPERTY
            STRINGS
            "None;UserID;PlatfSCP03;AESKey;ECKey;UserID_PlatfSCP03;AESKey_PlatfSCP03;ECKey_PlatfSCP03;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_SE05X_Auth
        PROPERTY
            STRINGS
            "None;UserID;PlatfSCP03;AESKey;ECKey;UserID_PlatfSCP03;AESKey_PlatfSCP03;ECKey_PlatfSCP03;"
    )
ENDIF()

SET(
    PTMW_Log
    "Default"
    CACHE
        STRING
        "Logging"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_Log
        PROPERTY
            STRINGS
            "Default;Verbose;Silent;SeggerRTT;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_Log
        PROPERTY
            STRINGS
            "Default;Verbose;Silent;"
    )
ENDIF()

SET(
    CMAKE_BUILD_TYPE
    "Debug"
    CACHE
        STRING
        "See https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE CMAKE_BUILD_TYPE
        PROPERTY
            STRINGS
            "Debug;Release;RelWithDebInfo;;"
    )
ELSE()
    SET_PROPERTY(
        CACHE CMAKE_BUILD_TYPE
        PROPERTY
            STRINGS
            "Debug;Release;RelWithDebInfo;;"
    )
ENDIF()

SET(
    PTMW_OpenSSL
    "3_0"
    CACHE
        STRING
        "For PC, which OpenSSL to pick up"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_OpenSSL
        PROPERTY
            STRINGS
            "1_1_1;3_0;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_OpenSSL
        PROPERTY
            STRINGS
            "1_1_1;3_0;"
    )
ENDIF()

SET(
    PTMW_MBedTLS
    "2_X"
    CACHE
        STRING
        "Which MBedTLS version to choose"
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_MBedTLS
        PROPERTY
            STRINGS
            "2_X;3_X;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_MBedTLS
        PROPERTY
            STRINGS
            "2_X;3_X;"
    )
ENDIF()

SET(
    PTMW_SE_RESET_LOGIC
    "1"
    CACHE
        STRING
        "Reset logic of Secure Element. The value of this will be used for 'SE_RESET_LOGIC' define in 'se05x_ic_reset' function. Select 1 (Active High) for SE050 and 51. Select 0 (Active low) for SE052."
)

IF(NXPInternal)
    SET_PROPERTY(
        CACHE PTMW_SE_RESET_LOGIC
        PROPERTY
            STRINGS
            "1;0;"
    )
ELSE()
    SET_PROPERTY(
        CACHE PTMW_SE_RESET_LOGIC
        PROPERTY
            STRINGS
            "1;0;"
    )
ENDIF()
IF("${PTMW_Applet}" STREQUAL "None")
    # SET(WithPTMW_Applet_None ON)
    SET(SSS_HAVE_APPLET_NONE "1")
ELSE()
    # SET(WithPTMW_Applet_None OFF)
    SET(SSS_HAVE_APPLET_NONE "0")
ENDIF()

IF("${PTMW_Applet}" STREQUAL "SE05X_A")
    # SET(WithPTMW_Applet_SE05X_A ON)
    SET(SSS_HAVE_APPLET_SE05X_A "1")
ELSE()
    # SET(WithPTMW_Applet_SE05X_A OFF)
    SET(SSS_HAVE_APPLET_SE05X_A "0")
ENDIF()

IF("${PTMW_Applet}" STREQUAL "SE05X_B")
    # SET(WithPTMW_Applet_SE05X_B ON)
    SET(SSS_HAVE_APPLET_SE05X_B "1")
ELSE()
    # SET(WithPTMW_Applet_SE05X_B OFF)
    SET(SSS_HAVE_APPLET_SE05X_B "0")
ENDIF()

IF("${PTMW_Applet}" STREQUAL "SE05X_C")
    # SET(WithPTMW_Applet_SE05X_C ON)
    SET(SSS_HAVE_APPLET_SE05X_C "1")
ELSE()
    # SET(WithPTMW_Applet_SE05X_C OFF)
    SET(SSS_HAVE_APPLET_SE05X_C "0")
ENDIF()

IF("${PTMW_Applet}" STREQUAL "SE051_UWB")
    # SET(WithPTMW_Applet_SE051_UWB ON)
    SET(SSS_HAVE_APPLET_SE051_UWB "1")
ELSE()
    # SET(WithPTMW_Applet_SE051_UWB OFF)
    SET(SSS_HAVE_APPLET_SE051_UWB "0")
ENDIF()

IF("${PTMW_Applet}" STREQUAL "SE051_H")
    # SET(WithPTMW_Applet_SE051_H ON)
    SET(SSS_HAVE_APPLET_SE051_H "1")
ELSE()
    # SET(WithPTMW_Applet_SE051_H OFF)
    SET(SSS_HAVE_APPLET_SE051_H "0")
ENDIF()

IF("${PTMW_Applet}" STREQUAL "AUTH")
    # SET(WithPTMW_Applet_AUTH ON)
    SET(SSS_HAVE_APPLET_AUTH "1")
ELSE()
    # SET(WithPTMW_Applet_AUTH OFF)
    SET(SSS_HAVE_APPLET_AUTH "0")
ENDIF()

IF("${PTMW_Applet}" STREQUAL "SE050_E")
    # SET(WithPTMW_Applet_SE050_E ON)
    SET(SSS_HAVE_APPLET_SE050_E "1")
ELSE()
    # SET(WithPTMW_Applet_SE050_E OFF)
    SET(SSS_HAVE_APPLET_SE050_E "0")
ENDIF()

IF("${PTMW_Applet}" STREQUAL "LoopBack")
    # SET(WithPTMW_Applet_LoopBack ON)
    SET(SSS_HAVE_APPLET_LOOPBACK "1")
ELSE()
    # SET(WithPTMW_Applet_LoopBack OFF)
    SET(SSS_HAVE_APPLET_LOOPBACK "0")
ENDIF()

IF("${PTMW_Applet}" STREQUAL "None")
    # OK
ELSEIF("${PTMW_Applet}" STREQUAL "SE05X_A")
    # OK
ELSEIF("${PTMW_Applet}" STREQUAL "SE05X_B")
    # OK
ELSEIF("${PTMW_Applet}" STREQUAL "SE05X_C")
    # OK
ELSEIF("${PTMW_Applet}" STREQUAL "SE051_UWB")
    # OK
ELSEIF("${PTMW_Applet}" STREQUAL "SE051_H")
    # OK
ELSEIF("${PTMW_Applet}" STREQUAL "AUTH")
    # OK
ELSEIF("${PTMW_Applet}" STREQUAL "SE050_E")
    # OK
ELSEIF("${PTMW_Applet}" STREQUAL "LoopBack")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_Applet' '${PTMW_Applet}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'None, SE05X_A, SE05X_B, SE05X_C, SE051_UWB, SE051_H, AUTH, SE050_E, LoopBack'")
ENDIF()

IF("${PTMW_SE05X_Ver}" STREQUAL "03_XX")
    # SET(WithPTMW_SE05X_Ver_03_XX ON)
    SET(SSS_HAVE_SE05X_VER_03_XX "1")
ELSE()
    # SET(WithPTMW_SE05X_Ver_03_XX OFF)
    SET(SSS_HAVE_SE05X_VER_03_XX "0")
ENDIF()

IF("${PTMW_SE05X_Ver}" STREQUAL "07_02")
    # SET(WithPTMW_SE05X_Ver_07_02 ON)
    SET(SSS_HAVE_SE05X_VER_07_02 "1")
ELSE()
    # SET(WithPTMW_SE05X_Ver_07_02 OFF)
    SET(SSS_HAVE_SE05X_VER_07_02 "0")
ENDIF()

IF("${PTMW_SE05X_Ver}" STREQUAL "03_XX")
    # OK
ELSEIF("${PTMW_SE05X_Ver}" STREQUAL "07_02")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_SE05X_Ver' '${PTMW_SE05X_Ver}' is invalid.")
    MESSAGE(STATUS "Only supported values are '03_XX, 07_02'")
ENDIF()

IF("${PTMW_Host}" STREQUAL "Darwin")
    # SET(WithPTMW_Host_Darwin ON)
    SET(SSS_HAVE_HOST_DARWIN "1")
ELSE()
    # SET(WithPTMW_Host_Darwin OFF)
    SET(SSS_HAVE_HOST_DARWIN "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "PCLinux32")
    # SET(WithPTMW_Host_PCLinux32 ON)
    SET(SSS_HAVE_HOST_PCLINUX32 "1")
ELSE()
    # SET(WithPTMW_Host_PCLinux32 OFF)
    SET(SSS_HAVE_HOST_PCLINUX32 "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "PCLinux64")
    # SET(WithPTMW_Host_PCLinux64 ON)
    SET(SSS_HAVE_HOST_PCLINUX64 "1")
ELSE()
    # SET(WithPTMW_Host_PCLinux64 OFF)
    SET(SSS_HAVE_HOST_PCLINUX64 "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "PCWindows")
    # SET(WithPTMW_Host_PCWindows ON)
    SET(SSS_HAVE_HOST_PCWINDOWS "1")
ELSE()
    # SET(WithPTMW_Host_PCWindows OFF)
    SET(SSS_HAVE_HOST_PCWINDOWS "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "Cygwin")
    # SET(WithPTMW_Host_Cygwin ON)
    SET(SSS_HAVE_HOST_CYGWIN "1")
ELSE()
    # SET(WithPTMW_Host_Cygwin OFF)
    SET(SSS_HAVE_HOST_CYGWIN "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "frdmk64f")
    # SET(WithPTMW_Host_frdmk64f ON)
    SET(SSS_HAVE_HOST_FRDMK64F "1")
ELSE()
    # SET(WithPTMW_Host_frdmk64f OFF)
    SET(SSS_HAVE_HOST_FRDMK64F "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "evkmimxrt1060")
    # SET(WithPTMW_Host_evkmimxrt1060 ON)
    SET(SSS_HAVE_HOST_EVKMIMXRT1060 "1")
ELSE()
    # SET(WithPTMW_Host_evkmimxrt1060 OFF)
    SET(SSS_HAVE_HOST_EVKMIMXRT1060 "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "evkmimxrt1170")
    # SET(WithPTMW_Host_evkmimxrt1170 ON)
    SET(SSS_HAVE_HOST_EVKMIMXRT1170 "1")
ELSE()
    # SET(WithPTMW_Host_evkmimxrt1170 OFF)
    SET(SSS_HAVE_HOST_EVKMIMXRT1170 "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "frdmmcxn947")
    # SET(WithPTMW_Host_frdmmcxn947 ON)
    SET(SSS_HAVE_HOST_FRDMMCXN947 "1")
ELSE()
    # SET(WithPTMW_Host_frdmmcxn947 OFF)
    SET(SSS_HAVE_HOST_FRDMMCXN947 "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "frdmmcxa153")
    # SET(WithPTMW_Host_frdmmcxa153 ON)
    SET(SSS_HAVE_HOST_FRDMMCXA153 "1")
ELSE()
    # SET(WithPTMW_Host_frdmmcxa153 OFF)
    SET(SSS_HAVE_HOST_FRDMMCXA153 "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "lpcxpresso55s")
    # SET(WithPTMW_Host_lpcxpresso55s ON)
    SET(SSS_HAVE_HOST_LPCXPRESSO55S "1")
ELSE()
    # SET(WithPTMW_Host_lpcxpresso55s OFF)
    SET(SSS_HAVE_HOST_LPCXPRESSO55S "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "lpcxpresso55s_ns")
    # SET(WithPTMW_Host_lpcxpresso55s_ns ON)
    SET(SSS_HAVE_HOST_LPCXPRESSO55S_NS "1")
ELSE()
    # SET(WithPTMW_Host_lpcxpresso55s_ns OFF)
    SET(SSS_HAVE_HOST_LPCXPRESSO55S_NS "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "lpcxpresso55s_s")
    # SET(WithPTMW_Host_lpcxpresso55s_s ON)
    SET(SSS_HAVE_HOST_LPCXPRESSO55S_S "1")
ELSE()
    # SET(WithPTMW_Host_lpcxpresso55s_s OFF)
    SET(SSS_HAVE_HOST_LPCXPRESSO55S_S "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "iMXLinux")
    # SET(WithPTMW_Host_iMXLinux ON)
    SET(SSS_HAVE_HOST_IMXLINUX "1")
ELSE()
    # SET(WithPTMW_Host_iMXLinux OFF)
    SET(SSS_HAVE_HOST_IMXLINUX "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "Raspbian")
    # SET(WithPTMW_Host_Raspbian ON)
    SET(SSS_HAVE_HOST_RASPBIAN "1")
ELSE()
    # SET(WithPTMW_Host_Raspbian OFF)
    SET(SSS_HAVE_HOST_RASPBIAN "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "Android")
    # SET(WithPTMW_Host_Android ON)
    SET(SSS_HAVE_HOST_ANDROID "1")
ELSE()
    # SET(WithPTMW_Host_Android OFF)
    SET(SSS_HAVE_HOST_ANDROID "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "Win10IoT")
    # SET(WithPTMW_Host_Win10IoT ON)
    SET(SSS_HAVE_HOST_WIN10IOT "1")
ELSE()
    # SET(WithPTMW_Host_Win10IoT OFF)
    SET(SSS_HAVE_HOST_WIN10IOT "0")
ENDIF()

IF("${PTMW_Host}" STREQUAL "Darwin")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "PCLinux32")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "PCLinux64")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "PCWindows")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "Cygwin")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "frdmk64f")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "evkmimxrt1060")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "evkmimxrt1170")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "frdmmcxn947")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "frdmmcxa153")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "lpcxpresso55s")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "lpcxpresso55s_ns")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "lpcxpresso55s_s")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "iMXLinux")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "Raspbian")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "Android")
    # OK
ELSEIF("${PTMW_Host}" STREQUAL "Win10IoT")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_Host' '${PTMW_Host}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'Darwin, PCLinux32, PCLinux64, PCWindows, Cygwin, frdmk64f, evkmimxrt1060, evkmimxrt1170, frdmmcxn947, frdmmcxa153, lpcxpresso55s, lpcxpresso55s_ns, lpcxpresso55s_s, iMXLinux, Raspbian, Android, Win10IoT'")
ENDIF()

IF("${PTMW_SMCOM}" STREQUAL "None")
    # SET(WithPTMW_SMCOM_None ON)
    SET(SSS_HAVE_SMCOM_NONE "1")
ELSE()
    # SET(WithPTMW_SMCOM_None OFF)
    SET(SSS_HAVE_SMCOM_NONE "0")
ENDIF()

IF("${PTMW_SMCOM}" STREQUAL "JRCP_V2")
    # SET(WithPTMW_SMCOM_JRCP_V2 ON)
    SET(SSS_HAVE_SMCOM_JRCP_V2 "1")
ELSE()
    # SET(WithPTMW_SMCOM_JRCP_V2 OFF)
    SET(SSS_HAVE_SMCOM_JRCP_V2 "0")
ENDIF()

IF("${PTMW_SMCOM}" STREQUAL "JRCP_V1")
    # SET(WithPTMW_SMCOM_JRCP_V1 ON)
    SET(SSS_HAVE_SMCOM_JRCP_V1 "1")
ELSE()
    # SET(WithPTMW_SMCOM_JRCP_V1 OFF)
    SET(SSS_HAVE_SMCOM_JRCP_V1 "0")
ENDIF()

IF("${PTMW_SMCOM}" STREQUAL "JRCP_V1_AM")
    # SET(WithPTMW_SMCOM_JRCP_V1_AM ON)
    SET(SSS_HAVE_SMCOM_JRCP_V1_AM "1")
ELSE()
    # SET(WithPTMW_SMCOM_JRCP_V1_AM OFF)
    SET(SSS_HAVE_SMCOM_JRCP_V1_AM "0")
ENDIF()

IF("${PTMW_SMCOM}" STREQUAL "VCOM")
    # SET(WithPTMW_SMCOM_VCOM ON)
    SET(SSS_HAVE_SMCOM_VCOM "1")
ELSE()
    # SET(WithPTMW_SMCOM_VCOM OFF)
    SET(SSS_HAVE_SMCOM_VCOM "0")
ENDIF()

IF("${PTMW_SMCOM}" STREQUAL "T1oI2C")
    # SET(WithPTMW_SMCOM_T1oI2C ON)
    SET(SSS_HAVE_SMCOM_T1OI2C "1")
ELSE()
    # SET(WithPTMW_SMCOM_T1oI2C OFF)
    SET(SSS_HAVE_SMCOM_T1OI2C "0")
ENDIF()

IF("${PTMW_SMCOM}" STREQUAL "T1oI2C_GP1_0")
    # SET(WithPTMW_SMCOM_T1oI2C_GP1_0 ON)
    SET(SSS_HAVE_SMCOM_T1OI2C_GP1_0 "1")
ELSE()
    # SET(WithPTMW_SMCOM_T1oI2C_GP1_0 OFF)
    SET(SSS_HAVE_SMCOM_T1OI2C_GP1_0 "0")
ENDIF()

IF("${PTMW_SMCOM}" STREQUAL "RC663_VCOM")
    # SET(WithPTMW_SMCOM_RC663_VCOM ON)
    SET(SSS_HAVE_SMCOM_RC663_VCOM "1")
ELSE()
    # SET(WithPTMW_SMCOM_RC663_VCOM OFF)
    SET(SSS_HAVE_SMCOM_RC663_VCOM "0")
ENDIF()

IF("${PTMW_SMCOM}" STREQUAL "PN7150")
    # SET(WithPTMW_SMCOM_PN7150 ON)
    SET(SSS_HAVE_SMCOM_PN7150 "1")
ELSE()
    # SET(WithPTMW_SMCOM_PN7150 OFF)
    SET(SSS_HAVE_SMCOM_PN7150 "0")
ENDIF()

IF("${PTMW_SMCOM}" STREQUAL "Thread")
    # SET(WithPTMW_SMCOM_Thread ON)
    SET(SSS_HAVE_SMCOM_THREAD "1")
ELSE()
    # SET(WithPTMW_SMCOM_Thread OFF)
    SET(SSS_HAVE_SMCOM_THREAD "0")
ENDIF()

IF("${PTMW_SMCOM}" STREQUAL "PCSC")
    # SET(WithPTMW_SMCOM_PCSC ON)
    SET(SSS_HAVE_SMCOM_PCSC "1")
ELSE()
    # SET(WithPTMW_SMCOM_PCSC OFF)
    SET(SSS_HAVE_SMCOM_PCSC "0")
ENDIF()

IF("${PTMW_SMCOM}" STREQUAL "None")
    # OK
ELSEIF("${PTMW_SMCOM}" STREQUAL "JRCP_V2")
    # OK
ELSEIF("${PTMW_SMCOM}" STREQUAL "JRCP_V1")
    # OK
ELSEIF("${PTMW_SMCOM}" STREQUAL "JRCP_V1_AM")
    # OK
ELSEIF("${PTMW_SMCOM}" STREQUAL "VCOM")
    # OK
ELSEIF("${PTMW_SMCOM}" STREQUAL "T1oI2C")
    # OK
ELSEIF("${PTMW_SMCOM}" STREQUAL "T1oI2C_GP1_0")
    # OK
ELSEIF("${PTMW_SMCOM}" STREQUAL "RC663_VCOM")
    # OK
ELSEIF("${PTMW_SMCOM}" STREQUAL "PN7150")
    # OK
ELSEIF("${PTMW_SMCOM}" STREQUAL "Thread")
    # OK
ELSEIF("${PTMW_SMCOM}" STREQUAL "PCSC")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_SMCOM' '${PTMW_SMCOM}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'None, JRCP_V2, JRCP_V1, JRCP_V1_AM, VCOM, T1oI2C, T1oI2C_GP1_0, RC663_VCOM, PN7150, Thread, PCSC'")
ENDIF()

IF("${PTMW_HostCrypto}" STREQUAL "MBEDTLS")
    # SET(WithPTMW_HostCrypto_MBEDTLS ON)
    SET(SSS_HAVE_HOSTCRYPTO_MBEDTLS "1")
ELSE()
    # SET(WithPTMW_HostCrypto_MBEDTLS OFF)
    SET(SSS_HAVE_HOSTCRYPTO_MBEDTLS "0")
ENDIF()

IF("${PTMW_HostCrypto}" STREQUAL "OPENSSL")
    # SET(WithPTMW_HostCrypto_OPENSSL ON)
    SET(SSS_HAVE_HOSTCRYPTO_OPENSSL "1")
ELSE()
    # SET(WithPTMW_HostCrypto_OPENSSL OFF)
    SET(SSS_HAVE_HOSTCRYPTO_OPENSSL "0")
ENDIF()

IF("${PTMW_HostCrypto}" STREQUAL "User")
    # SET(WithPTMW_HostCrypto_User ON)
    SET(SSS_HAVE_HOSTCRYPTO_USER "1")
ELSE()
    # SET(WithPTMW_HostCrypto_User OFF)
    SET(SSS_HAVE_HOSTCRYPTO_USER "0")
ENDIF()

IF("${PTMW_HostCrypto}" STREQUAL "None")
    # SET(WithPTMW_HostCrypto_None ON)
    SET(SSS_HAVE_HOSTCRYPTO_NONE "1")
ELSE()
    # SET(WithPTMW_HostCrypto_None OFF)
    SET(SSS_HAVE_HOSTCRYPTO_NONE "0")
ENDIF()

IF("${PTMW_HostCrypto}" STREQUAL "MBEDTLS")
    # OK
ELSEIF("${PTMW_HostCrypto}" STREQUAL "OPENSSL")
    # OK
ELSEIF("${PTMW_HostCrypto}" STREQUAL "User")
    # OK
ELSEIF("${PTMW_HostCrypto}" STREQUAL "None")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_HostCrypto' '${PTMW_HostCrypto}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'MBEDTLS, OPENSSL, User, None'")
ENDIF()

IF("${PTMW_RTOS}" STREQUAL "Default")
    # SET(WithPTMW_RTOS_Default ON)
    SET(SSS_HAVE_RTOS_DEFAULT "1")
ELSE()
    # SET(WithPTMW_RTOS_Default OFF)
    SET(SSS_HAVE_RTOS_DEFAULT "0")
ENDIF()

IF("${PTMW_RTOS}" STREQUAL "FreeRTOS")
    # SET(WithPTMW_RTOS_FreeRTOS ON)
    SET(SSS_HAVE_RTOS_FREERTOS "1")
ELSE()
    # SET(WithPTMW_RTOS_FreeRTOS OFF)
    SET(SSS_HAVE_RTOS_FREERTOS "0")
ENDIF()

IF("${PTMW_RTOS}" STREQUAL "Default")
    # OK
ELSEIF("${PTMW_RTOS}" STREQUAL "FreeRTOS")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_RTOS' '${PTMW_RTOS}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'Default, FreeRTOS'")
ENDIF()

IF("${PTMW_mbedTLS_ALT}" STREQUAL "SSS")
    # SET(WithPTMW_mbedTLS_ALT_SSS ON)
    SET(SSS_HAVE_MBEDTLS_ALT_SSS "1")
ELSE()
    # SET(WithPTMW_mbedTLS_ALT_SSS OFF)
    SET(SSS_HAVE_MBEDTLS_ALT_SSS "0")
ENDIF()

IF("${PTMW_mbedTLS_ALT}" STREQUAL "PSA")
    # SET(WithPTMW_mbedTLS_ALT_PSA ON)
    SET(SSS_HAVE_MBEDTLS_ALT_PSA "1")
ELSE()
    # SET(WithPTMW_mbedTLS_ALT_PSA OFF)
    SET(SSS_HAVE_MBEDTLS_ALT_PSA "0")
ENDIF()

IF("${PTMW_mbedTLS_ALT}" STREQUAL "None")
    # SET(WithPTMW_mbedTLS_ALT_None ON)
    SET(SSS_HAVE_MBEDTLS_ALT_NONE "1")
ELSE()
    # SET(WithPTMW_mbedTLS_ALT_None OFF)
    SET(SSS_HAVE_MBEDTLS_ALT_NONE "0")
ENDIF()

IF("${PTMW_mbedTLS_ALT}" STREQUAL "SSS")
    # OK
ELSEIF("${PTMW_mbedTLS_ALT}" STREQUAL "PSA")
    # OK
ELSEIF("${PTMW_mbedTLS_ALT}" STREQUAL "None")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_mbedTLS_ALT' '${PTMW_mbedTLS_ALT}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'SSS, PSA, None'")
ENDIF()

IF("${PTMW_SCP}" STREQUAL "None")
    # SET(WithPTMW_SCP_None ON)
    SET(SSS_HAVE_SCP_NONE "1")
ELSE()
    # SET(WithPTMW_SCP_None OFF)
    SET(SSS_HAVE_SCP_NONE "0")
ENDIF()

IF("${PTMW_SCP}" STREQUAL "SCP03_SSS")
    # SET(WithPTMW_SCP_SCP03_SSS ON)
    SET(SSS_HAVE_SCP_SCP03_SSS "1")
ELSE()
    # SET(WithPTMW_SCP_SCP03_SSS OFF)
    SET(SSS_HAVE_SCP_SCP03_SSS "0")
ENDIF()

IF("${PTMW_SCP}" STREQUAL "None")
    # OK
ELSEIF("${PTMW_SCP}" STREQUAL "SCP03_SSS")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_SCP' '${PTMW_SCP}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'None, SCP03_SSS'")
ENDIF()

IF("${PTMW_FIPS}" STREQUAL "None")
    # SET(WithPTMW_FIPS_None ON)
    SET(SSS_HAVE_FIPS_NONE "1")
ELSE()
    # SET(WithPTMW_FIPS_None OFF)
    SET(SSS_HAVE_FIPS_NONE "0")
ENDIF()

IF("${PTMW_FIPS}" STREQUAL "SE050")
    # SET(WithPTMW_FIPS_SE050 ON)
    SET(SSS_HAVE_FIPS_SE050 "1")
ELSE()
    # SET(WithPTMW_FIPS_SE050 OFF)
    SET(SSS_HAVE_FIPS_SE050 "0")
ENDIF()

IF("${PTMW_FIPS}" STREQUAL "140_2")
    # SET(WithPTMW_FIPS_140_2 ON)
    SET(SSS_HAVE_FIPS_140_2 "1")
ELSE()
    # SET(WithPTMW_FIPS_140_2 OFF)
    SET(SSS_HAVE_FIPS_140_2 "0")
ENDIF()

IF("${PTMW_FIPS}" STREQUAL "140_3")
    # SET(WithPTMW_FIPS_140_3 ON)
    SET(SSS_HAVE_FIPS_140_3 "1")
ELSE()
    # SET(WithPTMW_FIPS_140_3 OFF)
    SET(SSS_HAVE_FIPS_140_3 "0")
ENDIF()

IF("${PTMW_FIPS}" STREQUAL "None")
    # OK
ELSEIF("${PTMW_FIPS}" STREQUAL "SE050")
    # OK
ELSEIF("${PTMW_FIPS}" STREQUAL "140_2")
    # OK
ELSEIF("${PTMW_FIPS}" STREQUAL "140_3")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_FIPS' '${PTMW_FIPS}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'None, SE050, 140_2, 140_3'")
ENDIF()

IF("${PTMW_SBL}" STREQUAL "None")
    # SET(WithPTMW_SBL_None ON)
    SET(SSS_HAVE_SBL_NONE "1")
ELSE()
    # SET(WithPTMW_SBL_None OFF)
    SET(SSS_HAVE_SBL_NONE "0")
ENDIF()

IF("${PTMW_SBL}" STREQUAL "SBL_LPC55S")
    # SET(WithPTMW_SBL_SBL_LPC55S ON)
    SET(SSS_HAVE_SBL_SBL_LPC55S "1")
ELSE()
    # SET(WithPTMW_SBL_SBL_LPC55S OFF)
    SET(SSS_HAVE_SBL_SBL_LPC55S "0")
ENDIF()

IF("${PTMW_SBL}" STREQUAL "None")
    # OK
ELSEIF("${PTMW_SBL}" STREQUAL "SBL_LPC55S")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_SBL' '${PTMW_SBL}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'None, SBL_LPC55S'")
ENDIF()

IF("${PTMW_SE05X_Auth}" STREQUAL "None")
    # SET(WithPTMW_SE05X_Auth_None ON)
    SET(SSS_HAVE_SE05X_AUTH_NONE "1")
ELSE()
    # SET(WithPTMW_SE05X_Auth_None OFF)
    SET(SSS_HAVE_SE05X_AUTH_NONE "0")
ENDIF()

IF("${PTMW_SE05X_Auth}" STREQUAL "UserID")
    # SET(WithPTMW_SE05X_Auth_UserID ON)
    SET(SSS_HAVE_SE05X_AUTH_USERID "1")
ELSE()
    # SET(WithPTMW_SE05X_Auth_UserID OFF)
    SET(SSS_HAVE_SE05X_AUTH_USERID "0")
ENDIF()

IF("${PTMW_SE05X_Auth}" STREQUAL "PlatfSCP03")
    # SET(WithPTMW_SE05X_Auth_PlatfSCP03 ON)
    SET(SSS_HAVE_SE05X_AUTH_PLATFSCP03 "1")
ELSE()
    # SET(WithPTMW_SE05X_Auth_PlatfSCP03 OFF)
    SET(SSS_HAVE_SE05X_AUTH_PLATFSCP03 "0")
ENDIF()

IF("${PTMW_SE05X_Auth}" STREQUAL "AESKey")
    # SET(WithPTMW_SE05X_Auth_AESKey ON)
    SET(SSS_HAVE_SE05X_AUTH_AESKEY "1")
ELSE()
    # SET(WithPTMW_SE05X_Auth_AESKey OFF)
    SET(SSS_HAVE_SE05X_AUTH_AESKEY "0")
ENDIF()

IF("${PTMW_SE05X_Auth}" STREQUAL "ECKey")
    # SET(WithPTMW_SE05X_Auth_ECKey ON)
    SET(SSS_HAVE_SE05X_AUTH_ECKEY "1")
ELSE()
    # SET(WithPTMW_SE05X_Auth_ECKey OFF)
    SET(SSS_HAVE_SE05X_AUTH_ECKEY "0")
ENDIF()

IF("${PTMW_SE05X_Auth}" STREQUAL "UserID_PlatfSCP03")
    # SET(WithPTMW_SE05X_Auth_UserID_PlatfSCP03 ON)
    SET(SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03 "1")
ELSE()
    # SET(WithPTMW_SE05X_Auth_UserID_PlatfSCP03 OFF)
    SET(SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03 "0")
ENDIF()

IF("${PTMW_SE05X_Auth}" STREQUAL "AESKey_PlatfSCP03")
    # SET(WithPTMW_SE05X_Auth_AESKey_PlatfSCP03 ON)
    SET(SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03 "1")
ELSE()
    # SET(WithPTMW_SE05X_Auth_AESKey_PlatfSCP03 OFF)
    SET(SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03 "0")
ENDIF()

IF("${PTMW_SE05X_Auth}" STREQUAL "ECKey_PlatfSCP03")
    # SET(WithPTMW_SE05X_Auth_ECKey_PlatfSCP03 ON)
    SET(SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03 "1")
ELSE()
    # SET(WithPTMW_SE05X_Auth_ECKey_PlatfSCP03 OFF)
    SET(SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03 "0")
ENDIF()

IF("${PTMW_SE05X_Auth}" STREQUAL "None")
    # OK
ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "UserID")
    # OK
ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "PlatfSCP03")
    # OK
ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "AESKey")
    # OK
ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "ECKey")
    # OK
ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "UserID_PlatfSCP03")
    # OK
ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "AESKey_PlatfSCP03")
    # OK
ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "ECKey_PlatfSCP03")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_SE05X_Auth' '${PTMW_SE05X_Auth}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'None, UserID, PlatfSCP03, AESKey, ECKey, UserID_PlatfSCP03, AESKey_PlatfSCP03, ECKey_PlatfSCP03'")
ENDIF()

IF("${PTMW_Log}" STREQUAL "Default")
    # SET(WithPTMW_Log_Default ON)
    SET(SSS_HAVE_LOG_DEFAULT "1")
ELSE()
    # SET(WithPTMW_Log_Default OFF)
    SET(SSS_HAVE_LOG_DEFAULT "0")
ENDIF()

IF("${PTMW_Log}" STREQUAL "Verbose")
    # SET(WithPTMW_Log_Verbose ON)
    SET(SSS_HAVE_LOG_VERBOSE "1")
ELSE()
    # SET(WithPTMW_Log_Verbose OFF)
    SET(SSS_HAVE_LOG_VERBOSE "0")
ENDIF()

IF("${PTMW_Log}" STREQUAL "Silent")
    # SET(WithPTMW_Log_Silent ON)
    SET(SSS_HAVE_LOG_SILENT "1")
ELSE()
    # SET(WithPTMW_Log_Silent OFF)
    SET(SSS_HAVE_LOG_SILENT "0")
ENDIF()

IF("${PTMW_Log}" STREQUAL "SeggerRTT")
    # SET(WithPTMW_Log_SeggerRTT ON)
    SET(SSS_HAVE_LOG_SEGGERRTT "1")
ELSE()
    # SET(WithPTMW_Log_SeggerRTT OFF)
    SET(SSS_HAVE_LOG_SEGGERRTT "0")
ENDIF()

IF("${PTMW_Log}" STREQUAL "Default")
    # OK
ELSEIF("${PTMW_Log}" STREQUAL "Verbose")
    # OK
ELSEIF("${PTMW_Log}" STREQUAL "Silent")
    # OK
ELSEIF("${PTMW_Log}" STREQUAL "SeggerRTT")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_Log' '${PTMW_Log}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'Default, Verbose, Silent, SeggerRTT'")
ENDIF()

IF("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    # SET(WithCMAKE_BUILD_TYPE_Debug ON)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_DEBUG "1")
ELSE()
    # SET(WithCMAKE_BUILD_TYPE_Debug OFF)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_DEBUG "0")
ENDIF()

IF("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    # SET(WithCMAKE_BUILD_TYPE_Release ON)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_RELEASE "1")
ELSE()
    # SET(WithCMAKE_BUILD_TYPE_Release OFF)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_RELEASE "0")
ENDIF()

IF("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    # SET(WithCMAKE_BUILD_TYPE_RelWithDebInfo ON)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_RELWITHDEBINFO "1")
ELSE()
    # SET(WithCMAKE_BUILD_TYPE_RelWithDebInfo OFF)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_RELWITHDEBINFO "0")
ENDIF()

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
    # SET(WithCMAKE_BUILD_TYPE_ ON)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_ "1")
ELSE()
    # SET(WithCMAKE_BUILD_TYPE_ OFF)
    SET(SSS_HAVE_CMAKE_BUILD_TYPE_ "0")
ENDIF()

IF("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    # OK
ELSEIF("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    # OK
ELSEIF("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    # OK
ELSEIF("${CMAKE_BUILD_TYPE}" STREQUAL "")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'CMAKE_BUILD_TYPE' '${CMAKE_BUILD_TYPE}' is invalid.")
    MESSAGE(STATUS "Only supported values are 'Debug, Release, RelWithDebInfo, '")
ENDIF()

IF("${PTMW_OpenSSL}" STREQUAL "1_1_1")
    # SET(WithPTMW_OpenSSL_1_1_1 ON)
    SET(SSS_HAVE_OPENSSL_1_1_1 "1")
ELSE()
    # SET(WithPTMW_OpenSSL_1_1_1 OFF)
    SET(SSS_HAVE_OPENSSL_1_1_1 "0")
ENDIF()

IF("${PTMW_OpenSSL}" STREQUAL "3_0")
    # SET(WithPTMW_OpenSSL_3_0 ON)
    SET(SSS_HAVE_OPENSSL_3_0 "1")
ELSE()
    # SET(WithPTMW_OpenSSL_3_0 OFF)
    SET(SSS_HAVE_OPENSSL_3_0 "0")
ENDIF()

IF("${PTMW_OpenSSL}" STREQUAL "1_1_1")
    # OK
ELSEIF("${PTMW_OpenSSL}" STREQUAL "3_0")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_OpenSSL' '${PTMW_OpenSSL}' is invalid.")
    MESSAGE(STATUS "Only supported values are '1_1_1, 3_0'")
ENDIF()

IF("${PTMW_MBedTLS}" STREQUAL "2_X")
    # SET(WithPTMW_MBedTLS_2_X ON)
    SET(SSS_HAVE_MBEDTLS_2_X "1")
ELSE()
    # SET(WithPTMW_MBedTLS_2_X OFF)
    SET(SSS_HAVE_MBEDTLS_2_X "0")
ENDIF()

IF("${PTMW_MBedTLS}" STREQUAL "3_X")
    # SET(WithPTMW_MBedTLS_3_X ON)
    SET(SSS_HAVE_MBEDTLS_3_X "1")
ELSE()
    # SET(WithPTMW_MBedTLS_3_X OFF)
    SET(SSS_HAVE_MBEDTLS_3_X "0")
ENDIF()

IF("${PTMW_MBedTLS}" STREQUAL "2_X")
    # OK
ELSEIF("${PTMW_MBedTLS}" STREQUAL "3_X")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_MBedTLS' '${PTMW_MBedTLS}' is invalid.")
    MESSAGE(STATUS "Only supported values are '2_X, 3_X'")
ENDIF()

IF("${PTMW_SE_RESET_LOGIC}" STREQUAL "1")
    # SET(WithPTMW_SE_RESET_LOGIC_1 ON)
    SET(SSS_HAVE_SE_RESET_LOGIC_1 "1")
ELSE()
    # SET(WithPTMW_SE_RESET_LOGIC_1 OFF)
    SET(SSS_HAVE_SE_RESET_LOGIC_1 "0")
ENDIF()

IF("${PTMW_SE_RESET_LOGIC}" STREQUAL "0")
    # SET(WithPTMW_SE_RESET_LOGIC_0 ON)
    SET(SSS_HAVE_SE_RESET_LOGIC_0 "1")
ELSE()
    # SET(WithPTMW_SE_RESET_LOGIC_0 OFF)
    SET(SSS_HAVE_SE_RESET_LOGIC_0 "0")
ENDIF()

IF("${PTMW_SE_RESET_LOGIC}" STREQUAL "1")
    # OK
ELSEIF("${PTMW_SE_RESET_LOGIC}" STREQUAL "0")
    # OK
ELSE()
    MESSAGE(SEND_ERROR "For 'PTMW_SE_RESET_LOGIC' '${PTMW_SE_RESET_LOGIC}' is invalid.")
    MESSAGE(STATUS "Only supported values are '1, 0'")
ENDIF()


# Add Options
# SE05X
SET(SSSFTR_SE05X_AES ON
    CACHE BOOL
    "SE05X Secure Element : Symmetric AES")
SET(SSSFTR_SE05X_ECC ON
    CACHE BOOL
    "SE05X Secure Element : Elliptic Curve Cryptography")
SET(SSSFTR_SE05X_RSA ON
    CACHE BOOL
    "SE05X Secure Element : RSA")
SET(SSSFTR_SE05X_KEY_SET ON
    CACHE BOOL
    "SE05X Secure Element : KEY operations : SET Key")
SET(SSSFTR_SE05X_KEY_GET ON
    CACHE BOOL
    "SE05X Secure Element : KEY operations : GET Key")
SET(SSSFTR_SE05X_AuthECKey ON
    CACHE BOOL
    "SE05X Secure Element : Authenticate via ECKey")
SET(SSSFTR_SE05X_AuthSession ON
    CACHE BOOL
    "SE05X Secure Element : Allow creation of user/authenticated session.")
SET(SSSFTR_SE05X_CREATE_DELETE_CRYPTOOBJ ON
    CACHE BOOL
    "SE05X Secure Element : Allow creation/deletion of Crypto Objects")
# SW
SET(SSSFTR_SW_AES ON
    CACHE BOOL
    "Software : Symmetric AES")
SET(SSSFTR_SW_ECC ON
    CACHE BOOL
    "Software : Elliptic Curve Cryptography")
SET(SSSFTR_SW_RSA ON
    CACHE BOOL
    "Software : RSA")
SET(SSSFTR_SW_KEY_SET ON
    CACHE BOOL
    "Software : KEY operations : SET Key")
SET(SSSFTR_SW_KEY_GET ON
    CACHE BOOL
    "Software : KEY operations : GET Key")
SET(SSSFTR_SW_TESTCOUNTERPART ON
    CACHE BOOL
    "Software : Used as a test counterpart")

# Add Values
# Symmetric AES
IF(SSSFTR_SE05X_AES OR SSSFTR_SW_AES)
    SET(SSSFTR_AES ON)
ELSE()
    SET(SSSFTR_AES OFF)
ENDIF()
# Elliptic Curve Cryptography
IF(SSSFTR_SE05X_ECC OR SSSFTR_SW_ECC)
    SET(SSSFTR_ECC ON)
ELSE()
    SET(SSSFTR_ECC OFF)
ENDIF()
# RSA
IF(SSSFTR_SE05X_RSA OR SSSFTR_SW_RSA)
    SET(SSSFTR_RSA ON)
ELSE()
    SET(SSSFTR_RSA OFF)
ENDIF()
# KEY operations : SET Key
IF(SSSFTR_SE05X_KEY_SET OR SSSFTR_SW_KEY_SET)
    SET(SSSFTR_KEY_SET ON)
ELSE()
    SET(SSSFTR_KEY_SET OFF)
ENDIF()
# KEY operations : GET Key
IF(SSSFTR_SE05X_KEY_GET OR SSSFTR_SW_KEY_GET)
    SET(SSSFTR_KEY_GET ON)
ELSE()
    SET(SSSFTR_KEY_GET OFF)
ENDIF()
# KEY operations
IF(SSSFTR_KEY_SET OR SSSFTR_KEY_GET)
    SET(SSSFTR_KEY ON)
ELSE()
    SET(SSSFTR_KEY OFF)
ENDIF()
# KEY operations
IF(SSSFTR_SE05X_KEY_SET OR SSSFTR_SE05X_KEY_GET)
    SET(SSSFTR_SE05X_KEY ON)
ELSE()
    SET(SSSFTR_SE05X_KEY OFF)
ENDIF()
# KEY operations
IF(SSSFTR_SW_KEY_SET OR SSSFTR_SW_KEY_GET)
    SET(SSSFTR_SW_KEY ON)
ELSE()
    SET(SSSFTR_SW_KEY OFF)
ENDIF()
