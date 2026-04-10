# .. Copyright 2018,2020,2024-2025 NXP
# ..
# .. SPDX-License-Identifier: Apache-2.0
# ..

# .. _se05x-cmake-options:

# ============================================
#  CMake Options
# ============================================

# .. include:: cmake_options_values.rst.txt


#> Use NXP NFC RdLib. This is used mainly for RC663 + SAM Use Cases. Package available under NDA is needed to use this feature
OPTION(WithNXPNFCRdLib "Compile in NXP NFC RdLib support" OFF)

#> Compile with OPC UA.  By default it is disabled from compilation.
OPTION(WithOPCUA_open62541 "Compile With open62541 Support" OFF)

#> Create shared libraries.  Applicable for Engine DLL and other use cases.
OPTION(WithSharedLIB "Create and use shared libraries" OFF)

#> Compile Access Manager with unix socket support.
OPTION(WithAccessMgr_UnixSocket "Compile Access Manager with UNIX socket support (Default is STREAM sockets)." OFF)

# NXP Internal Options
# ============================================
#
# These options are not supported outside NXP.
#
#> .. note:: For deliveries outside NXP, this option is disabled.
OPTION(NXPInternal "NXP Internal" OFF)

#> .. For internal testing.
OPTION(WithCodeCoverage "Compile with Code Coverage" OFF)


#.. Automatic generated options
INCLUDE(scripts/cmake_options_values.cmake)
INCLUDE(scripts/cmake_options_legacy.cmake)

# Other Variables
# ============================================


#> Include code from external tpm2 folder. This way, TPM code can be included in build from outside the simw-top repository.
OPTION(WithExtCustomerTPMCode "Include code from ../customer/tpm2" OFF)

# .. option:: SIMW_INSTALL_INC_DIR
#
#     - Location where library header files are installed for linux based targets. (Used for iMX Linux)
#     - Default location is ``</usr/local/>include/se05x``
#
SET(SIMW_INSTALL_INC_DIR "include/se05x")

# .. option:: SIMW_INSTALL_SHARE_DIR
#
#     - Location where miscellaneous scripts
#       get copiled for linux based targets. (Used for iMX Linux)
#     - e.g. ``cmake_options.mak`` which has current cmake build settings.
#     - Default location is ``</usr/local/>share/se05x``
#
SET(SIMW_INSTALL_SHARE_DIR "share/se05x")

# .. # End of documented part .....

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
    SET(CMAKE_BUILD_TYPE "Debug")
ENDIF()

# .. # SSS_HAVE_LARGE_PROGRAMS: Large enough programs that may
# .. # not fit in smaller size, e.g. small boot loaders.
IF(SSS_HAVE_HOST_LPCXPRESSO55S_S)
    SET(SSS_HAVE_LARGE_PROGRAMS OFF)
ELSE()
    SET(SSS_HAVE_LARGE_PROGRAMS ON)
ENDIF()

# .. To build shared libraries
IF(WithSharedLIB)
    SET(BUILD_SHARED_LIBS ON)
ELSE()
    SET(BUILD_SHARED_LIBS OFF)
ENDIF()

# .. If using NDA Version of WithNXPNFCRdLib
SET(WithNXPNFCRdLib_NDA ON) # .. else set it to off

IF(WithNXPNFCRdLib_NDA)
    SET(NXPNFCRdLib_DIRNAME nxpnfcrdlib_nda)
ELSE()
    SET(NXPNFCRdLib_DIRNAME nxpnfcrdlib_full)
ENDIF()

MESSAGE(STATUS "BUILD_TYPE: " ${CMAKE_BUILD_TYPE})

IF(SSS_HAVE_HOST_PCLINUX32 OR SSS_HAVE_HOST_PCLINUX64)
    SET(SSS_HAVE_HOST_PCLINUX ON)
ELSE()
    SET(SSS_HAVE_HOST_PCLINUX OFF)
ENDIF()

IF(SSS_HAVE_HOST_PCLINUX
   OR SSS_HAVE_HOST_RASPBIAN
   OR SSS_HAVE_HOST_IMXLINUX
   OR SSS_HAVE_HOST_CYGWIN
)
    SET(SSS_HAVE_HOST_LINUX_LIKE ON)
ELSE()
    SET(SSS_HAVE_HOST_LINUX_LIKE OFF)
ENDIF()

IF(
    SSS_HAVE_HOST_LINUX_LIKE
    OR SSS_HAVE_HOST_PCWINDOWS
    OR SSS_HAVE_HOST_DARWIN
)
    SET(SSS_HAVE_HOST_WITH_FILE_SYSTEM ON)
ELSE()
    SET(SSS_HAVE_HOST_WITH_FILE_SYSTEM OFF)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_NONE)
    IF(SSS_HAVE_SCP_SCP03_SSS
     OR SSSFTR_SW_AES
     OR SSSFTR_SW_ECC
     OR SSSFTR_SW_KEY_GET
     OR SSSFTR_SW_KEY_SET
     OR SSSFTR_SW_RSA
     OR SSSFTR_SW_TESTCOUNTERPART)
        MESSAGE(STATUS "Without Host Crypto Can not use any host/sw crypto")
    ENDIF()
ENDIF()

IF((SSS_HAVE_HOST_LINUX_LIKE OR SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_DARWIN OR SSS_HAVE_HOST_WIN10IOT))
    IF(SSS_HAVE_HOST_PCLINUX32)
        IF(EXISTS "/usr/lib/i386-linux-gnu/")
            MESSAGE(STATUS "OpenSSL: Enforcing 32bit linux from /usr/lib/i386-linux-gnu")
            LINK_DIRECTORIES("/usr/lib/i386-linux-gnu")
            SET(OPENSSL_LIBRARIES ssl crypto)
        ELSE()
            MESSAGE(STATUS "OpenSSL libraries not found")
        ENDIF()
    ENDIF()

    IF(SSS_HAVE_HOST_PCLINUX64
       OR SSS_HAVE_HOST_IMXLINUX
       OR SSS_HAVE_HOST_RASPBIAN
       OR SSS_HAVE_HOST_CYGWIN
    )
        IF(OPENSSL_INSTALL_PREFIX)
            MESSAGE(STATUS "OpenSSL: Using: ${OPENSSL_INSTALL_PREFIX}")
            INCLUDE_DIRECTORIES("${OPENSSL_INSTALL_PREFIX}/include")
            SET(OPENSSL_LIBRARIES ${OPENSSL_INSTALL_PREFIX}/lib/libssl.so ${OPENSSL_INSTALL_PREFIX}/lib/libcrypto.so)
        ELSE()
            FIND_PACKAGE(OpenSSL) # Find the OpenSSL Package
            IF(OPENSSL_FOUND)
                MESSAGE(STATUS "Found: " ${OPENSSL_LIBRARIES})
                INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
            ELSE()
                MESSAGE(WARNING "Building with OpenSSL Engine expected to fail")
            ENDIF()
        ENDIF()
    ELSEIF(SSS_HAVE_HOST_PCWINDOWS)
        # Currently SSS_HAVE_HOST_PCWINDOWS implies SSS_HAVE_HOSTCRYPTO_MBEDTLS
        IF(SSS_HAVE_OPENSSL_1_1_1)
            INCLUDE_DIRECTORIES(${SIMW_TOP_DIR}/ext/openssl/include)
            IF(
                "${CMAKE_CXX_COMPILER_ID}"
                MATCHES
                "MSVC"
            )
                SET(OPENSSL_LIBRARIES
                    libssl
                    libcrypto
                    Crypt32
                    Ws2_32
                )
            ELSE()
                # MINGW
                SET(OPENSSL_LIBRARIES
                    ssl
                    crypto
                    Crypt32
                    Ws2_32
                )
            ENDIF()
        ENDIF()
        IF(SSS_HAVE_OpenSSL_1_0_2)
            INCLUDE_DIRECTORIES(${SIMW_TOP_DIR}/ext/openssl-102/include)
            SET(OPENSSL_LIBRARIES libeay32 ssleay32)
        ENDIF()
        IF(SSS_HAVE_OPENSSL_3_0)
            INCLUDE_DIRECTORIES(${SIMW_TOP_DIR}/ext/openssl-30/include)
            IF(
                "${CMAKE_CXX_COMPILER_ID}"
                MATCHES
                "MSVC"
            )
                SET(OPENSSL_LIBRARIES
                    libssl
                    libcrypto
                    Crypt32
                    Ws2_32
                )
            ELSE()
                # MINGW
                MESSAGE(FATAL_ERROR "Openssl 3.0 binaries for mingw not available")
            ENDIF()
        ENDIF()
    ELSEIF(SSS_HAVE_HOST_DARWIN)
        IF(OPENSSL_INSTALL_PREFIX)
            # /usr/local/Cellar/openssl/1.0.2s/
            MESSAGE(STATUS "OpenSSL: Using: ${OPENSSL_INSTALL_PREFIX}")
            INCLUDE_DIRECTORIES("${OPENSSL_INSTALL_PREFIX}/include")
            INCLUDE_DIRECTORIES("${OPENSSL_INSTALL_PREFIX}/lib")
            SET(OPENSSL_LIBRARIES ${OPENSSL_INSTALL_PREFIX}/lib/libssl.a ${OPENSSL_INSTALL_PREFIX}/lib/libcrypto.a)
        ELSE()
            FIND_PACKAGE(OpenSSL) # Find the OpenSSL Package
            IF(OPENSSL_FOUND)
                MESSAGE(STATUS "Found: " ${OPENSSL_LIBRARIES})
                INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
            ELSE()
                MESSAGE(WARNING "Building with OpenSSL Engine expected to fail")
                MESSAGE(WARNING "You can set OPENSSL_INSTALL_PREFIX")
            ENDIF()
        ENDIF()
    ELSEIF(SSS_HAVE_HOST_WIN10IOT)
        IF(SSS_HAVE_OpenSSL_1_0_2)
            INCLUDE_DIRECTORIES(${SIMW_TOP_DIR}/ext/openssl-102/Win10IoT/include)
            SET(OPENSSL_LIBRARIES libeay32 ssleay32)
        ELSE()
            MESSAGE(FATAL "SSS_HAVE_HOST_WIN10IOT needs SSS_HAVE_OpenSSL_1_0_2")
        ENDIF()
    ENDIF()
ENDIF()

IF(SSS_HAVE_MBEDTLS_ALT_A71CH OR SSS_HAVE_MBEDTLS_ALT_SSS OR SSS_HAVE_MBEDTLS_ALT_PSA)
    SET(SSS_HAVE_MBEDTLS_ALT ON)
ELSE()
    SET(SSS_HAVE_MBEDTLS_ALT OFF)
ENDIF()

IF(SSS_HAVE_APPLET_A71CH_SIM OR SSS_HAVE_APPLET_SE05X_L)
    SET(SSS_HAVE_APPLET_SE050_EAR ON)
ELSE()
    SET(SSS_HAVE_APPLET_SE050_EAR OFF)
ENDIF()

IF(SSS_HAVE_APPLET_SE05X_A
   OR SSS_HAVE_APPLET_SE05X_B
   OR SSS_HAVE_APPLET_SE05X_C
   OR SSS_HAVE_APPLET_SE051_UWB
   OR SSS_HAVE_APPLET_AUTH
)
    SET(SSS_HAVE_APPLET_SE05X_IOT ON)
ELSE()
    SET(SSS_HAVE_APPLET_SE05X_IOT OFF)
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    ADD_DEFINITIONS(-DHLSE_MAX_OBJECTS_IN_TABLE=9)
ENDIF()

IF(SSS_HAVE_SCP_SCP03_HOSTCRYPTO)
    ADD_DEFINITIONS("-DUSE_HOSTCRYPTO_FOR_SCP03")
ENDIF()

IF(WithSCP02_HostCrypto)
    ADD_DEFINITIONS("-DUSE_SCP02")
ENDIF()

IF(SSS_HAVE_APPLET_A71CH OR SSS_HAVE_APPLET_A71CL)
    SET(SSS_HAVE_APPLET_A7XX ON)
ELSE()
    SET(SSS_HAVE_APPLET_A7XX OFF)
ENDIF()

IF(SSS_HAVE_APPLET_A71CH OR SSS_HAVE_APPLET_A71CH_SIM)
    ADD_DEFINITIONS("-DTGT_A71CH")
ENDIF()

IF(SSS_HAVE_SMCOM_SCI2C)
    ADD_DEFINITIONS(-DSCI2C)
ENDIF()

IF(SSS_HAVE_SMCOM_T1OI2C OR SSS_HAVE_SMCOM_T1OI2C_GP1_0)
    ADD_DEFINITIONS(-DT1oI2C )
ENDIF()

IF(SSS_HAVE_LOG_SEGGERRTT)
    ADD_DEFINITIONS(-DUSE_SERGER_RTT)
ENDIF()

IF(SSS_HAVE_HOST_FRDMK64F)
    SET(SSS_HAVE_KSDK ON)
    SET(KSDK_BoardName "frdmk64f")
    SET(KSDK_CPUName "MK64F12")
    ADD_DEFINITIONS(-DLPC_ENET) # .. Purnank : FIXME To be removed
ELSEIF(SSS_HAVE_HOST_EVKMIMXRT1060)
    SET(SSS_HAVE_KSDK ON)
    SET(KSDK_BoardName "evkmimxrt1060")
    SET(KSDK_CPUName "MIMXRT1062")
    ADD_DEFINITIONS(-DLPC_ENET) # .. Purnank : FIXME To be removed
ELSEIF(SSS_HAVE_HOST_EVKMIMXRT1170)
    SET(SSS_HAVE_KSDK ON)
    SET(KSDK_BoardName "evkmimxrt1170")
    SET(KSDK_CPUName "MIMXRT1176")
    ADD_DEFINITIONS(-DLPC_ENET) # .. Purnank : FIXME To be removed
ELSEIF(SSS_HAVE_HOST_LPCXPRESSO55S)
    SET(SSS_HAVE_KSDK ON)
    SET(KSDK_BoardName "lpcxpresso55s69")
    SET(KSDK_CPUName "LPC55S69")
    ADD_DEFINITIONS(-DLPC_WIFI)
    # ADD_DEFINITIONS(-DWIFISHIELD_IS=WIFISHIELD_IS_SILEX2401)
ELSEIF(SSS_HAVE_HOST_LPCXPRESSO55S_NS)
    SET(SSS_HAVE_KSDK ON)
    SET(KSDK_BoardName "lpcxpresso55s69")
    SET(KSDK_CPUName "LPC55S69")
    ADD_DEFINITIONS(-DLPC_WIFI)
    # ADD_DEFINITIONS(-DWIFISHIELD_IS=WIFISHIELD_IS_SILEX2401)
ELSEIF(SSS_HAVE_HOST_LPCXPRESSO55S_S)
    SET(SSS_HAVE_KSDK ON)
    SET(KSDK_BoardName "lpcxpresso55s69")
    SET(KSDK_CPUName "LPC55S69")
    ADD_DEFINITIONS(-DLPC_WIFI)
    # ADD_DEFINITIONS(-DWIFISHIELD_IS=WIFISHIELD_IS_SILEX2401)
ELSEIF(SSS_HAVE_HOST_FRDMMCXN947)
    SET(SSS_HAVE_KSDK ON)
    SET(KSDK_BoardName "frdmmcxn947")
    SET(KSDK_CPUName "MCXN947")
ELSEIF(SSS_HAVE_HOST_FRDMMCXA153)
    SET(SSS_HAVE_KSDK ON)
    SET(KSDK_BoardName "frdmmcxa153")
    SET(KSDK_CPUName "MCXA153")
ELSE()
    SET(SSS_HAVE_KSDK OFF)
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    IF (SSS_HAVE_HOST_FRDMMCXA153)
        SET(ENABLE_CLOUD_DEMOS OFF)
        ADD_DEFINITIONS(-DUSE_RTOS -DSDK_OS_FREE_RTOS -DFSL_RTOS_FREE_RTOS)
    ELSE()
        SET(ENABLE_CLOUD_DEMOS ON)
        ADD_DEFINITIONS(-DUSE_RTOS -DSDK_OS_FREE_RTOS -DFSL_RTOS_FREE_RTOS -DENABLE_CLOUD_DEMOS)
    ENDIF()
ENDIF()

IF(SSS_HAVE_SMCOM_JRCP_V2 AND SSS_HAVE_SMCOM_JRCP_V1)
    MESSAGE(FATAL_ERROR "Can not select both SSS_HAVE_SMCOM_JRCP_V2 AND SSS_HAVE_SMCOM_JRCP_V1")
ENDIF()

IF(SSS_HAVE_SMCOM_JRCP_V1_AM AND (SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03 OR SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03 OR SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03 OR SSS_HAVE_SE05X_AUTH_PLATFSCP03))
    MESSAGE(FATAL_ERROR "Can not select JRCP_V1_AM with AUTH PLATFSCP03, use either of UserID, AESKey or ECKey")
ENDIF()

IF(SSS_HAVE_KSDK)
    INCLUDE(scripts/ksdk.cmake)
ELSEIF(
    SSS_HAVE_HOST_LINUX_LIKE
    OR SSS_HAVE_HOST_PCWINDOWS
    OR SSS_HAVE_HOST_WIN10IOT
)
    INCLUDE(scripts/native.cmake)
ELSEIF(SSS_HAVE_HOST_DARWIN)
    INCLUDE(scripts/native.cmake)
ELSEIF(SSS_HAVE_HOST_ANDROID)
    INCLUDE(scripts/android.cmake)
ELSEIF("${CMAKE_SYSTEM_NAME}" STREQUAL "CYGWIN")
    INCLUDE(scripts/native.cmake)
ELSE()
    # .. Falling back on Native
    INCLUDE(scripts/native.cmake)
ENDIF()

MESSAGE(STATUS "CMAKE_CXX_COMPILER_ID = ${CMAKE_CXX_COMPILER_ID}")
MESSAGE(STATUS "CMAKE_SYSTEM_NAME = ${CMAKE_SYSTEM_NAME}")

IF(SSS_HAVE_KSDK)
    INCLUDE_DIRECTORIES(${SIMW_TOP_DIR}/sss/port/ksdk)
ELSE()
    INCLUDE_DIRECTORIES(${SIMW_TOP_DIR}/sss/port/default)
ENDIF()

# .. Checks and balances ########

IF(NOT
   CMAKE_C_COMPILER_ID
   STREQUAL
   "GNU"
)
    IF(WithCodeCoverage)
        MESSAGE(FATAL_ERROR "Code coverage only with GCC")
    ENDIF()
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS AND SSS_HAVE_RTOS_DEFAULT)
    MESSAGE(FATAL_ERROR "Can not set SSS_HAVE_RTOS_FREERTOS AND SSS_HAVE_RTOS_DEFAULT")
ENDIF()

IF(SSS_HAVE_SMCOM_JRCP_V2 AND SSS_HAVE_SMCOM_JRCP_V1)
    MESSAGE(FATAL_ERROR "Can not select both SSS_HAVE_SMCOM_JRCP_V2 AND SSS_HAVE_SMCOM_JRCP_V1")
ENDIF()

IF(SSS_HAVE_APPLET_A71CH AND SSS_HAVE_SMCOM_T1OI2C)
    MESSAGE(FATAL_ERROR "Can not set both 'SSS_HAVE_APPLET_A71CH' AND 'SSS_HAVE_SMCOM_T1OI2C'")
ENDIF()

IF(SSS_HAVE_SMCOM_RC663_VCOM)
    IF(NOT WithNXPNFCRdLib)
        MESSAGE(FATAL_ERROR "'SSS_HAVE_SMCOM_RC663_VCOM' Needs 'WithNXPNFCRdLib'")
    ENDIF()
ENDIF()

IF(WithNXPNFCRdLib)
    IF(SSS_HAVE_HOST_PCLINUX)
        MESSAGE(FATAL_ERROR "Can not set both 'WithNXPNFCRdLib' AND 'SSS_HAVE_HOST_PCLINUX'")
    ENDIF()

    IF(NOT SSS_HAVE_HOST_LPCXPRESSO55S)
        MESSAGE(FATAL_ERROR " 'WithNXPNFCRdLib' Can only work with 'lpcxpresso55s'")
    ENDIF()

ENDIF()

IF(SSS_HAVE_MBEDTLS_ALT)
    IF(SSS_HAVE_APPLET_A71CL OR SSS_HAVE_APPLET_SE05X_L)
        MESSAGE(FATAL_ERROR "Can not set both 'ALT ' AND 'CL'")
    ENDIF()
ENDIF()

IF(SSS_HAVE_KSDK)
    IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
        MESSAGE(FATAL_ERROR "Can not set both 'KSDK ' AND 'OPENSSL'")
    ENDIF()
ENDIF()

IF(SSS_HAVE_APPLET_A71CL OR SSS_HAVE_APPLET_SE05X_L)
    IF(SSS_HAVE_SCP_SCP03_SSS OR SSS_HAVE_SCP_SCP03_HOSTCRYPTO)
        MESSAGE(FATAL_ERROR "Can not use SCP03 for CL")
    ENDIF()
ENDIF()

IF(SSS_HAVE_APPLET_A71CH AND SSS_HAVE_APPLET_A71CH_SIM)
    IF(WithSCP02_HostCrypto)
        MESSAGE(FATAL_ERROR "Can not use SCP02 for CH")
    ENDIF()
ENDIF()


IF(SSS_HAVE_Applet_None)
    IF(NOT SSS_HAVE_MBEDTLS_ALT_NONE)
        MESSAGE(FATAL_ERROR "Can not use SW Crypto with mebdTLS ALT")
    ENDIF()
ENDIF()

IF(SSS_HAVE_MBEDTLS_ALT_PSA)
    IF(NOT SSS_HAVE_HOSTCRYPTO_MBEDTLS)
        MESSAGE(FATAL_ERROR "Cannot use SSS_HAVE_MBEDTLS_ALT_PSA without SSS_HAVE_HOSTCRYPTO_MBEDTLS")
    ENDIF()
    IF(SSS_HAVE_MBEDTLS_3_X)
        MESSAGE(FATAL_ERROR "Cannot use SSS_HAVE_MBEDTLS_ALT_PSA with SSS_HAVE_MBEDTLS_3_X. Select SSS_HAVE_MBEDTLS_2_X")
    ENDIF()
ENDIF()

IF(SSS_HAVE_APPLET_SE05X_IOT)
    IF(SSS_HAVE_SMCOM_SCI2C)
        MESSAGE(FATAL_ERROR "Can not use SCI2C with SE05X")
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    IF(WithSharedLIB)
        MESSAGE(FATAL_ERROR "Cannot use WithSharedLIB=ON with SSS_HAVE_HOSTCRYPTO_MBEDTLS")
    ENDIF()
ENDIF()

IF(SSS_HAVE_APPLET_SE05X_IOT)
    # .. Every one must not know what is the current auth matchanism.
    # .. Only the logic which is opening or testing it knows this.
    # .. This way, we ensure at run time, the host library is able
    # .. to use selected auth strategy.
    MACRO(EXPOSE_SE05X_AUTH_STRATEGY)
        SET(NEED_AUTH OFF)
        SET(NEED_CRYPTO OFF)
        SET(NEED_ECKey OFF)
        IF("${PTMW_SE05X_Auth}" STREQUAL "None")
            # OK
        ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "PlatfSCP03")
            SET(NEED_CRYPTO ON)
        ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "UserID")
            SET(NEED_AUTH ON)
        ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "AESKey")
            SET(NEED_AUTH ON)
            SET(NEED_CRYPTO ON)
        ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "ECKey")
            SET(NEED_AUTH ON)
            SET(NEED_CRYPTO ON)
            SET(NEED_ECKey ON)
        ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "UserID_PlatfSCP03")
            SET(NEED_AUTH ON)
            SET(NEED_CRYPTO ON)
        ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "AESKey_PlatfSCP03")
            SET(NEED_AUTH ON)
            SET(NEED_CRYPTO ON)
        ELSEIF("${PTMW_SE05X_Auth}" STREQUAL "ECKey_PlatfSCP03")
            SET(NEED_AUTH ON)
            SET(NEED_CRYPTO ON)
            SET(NEED_ECKey ON)
        ELSE()
            MESSAGE(SEND_ERROR "For 'PTMW_SE05X_Auth' '${PTMW_SE05X_Auth}' is not suppored.")
        ENDIF()
        IF(${NEED_AUTH})
            IF(NOT ${SSSFTR_SE05X_AuthSession})
                MESSAGE(SEND_ERROR "For 'PTMW_SE05X_Auth=${PTMW_SE05X_Auth}' 'SSSFTR_SE05X_AuthSession' Should be ON")
            ENDIF()
        ENDIF()
        IF(${NEED_CRYPTO})
            IF(NOT ${SSS_HAVE_SCP_SCP03_SSS})
                MESSAGE(SEND_ERROR "For 'PTMW_SE05X_Auth=${PTMW_SE05X_Auth}' 'SSS_HAVE_SCP_SCP03_SSS' Should be ON")
            ENDIF()
            IF(NOT ${SSSFTR_SW_AES})
                MESSAGE(SEND_ERROR "For 'PTMW_SE05X_Auth=${PTMW_SE05X_Auth}' 'SSSFTR_SW_AES' Should be ON")
            ENDIF()
        ENDIF()
        IF(${NEED_ECKey})
            IF(NOT ${SSSFTR_SE05X_AuthECKey})
                MESSAGE(SEND_ERROR "For 'PTMW_SE05X_Auth=${PTMW_SE05X_Auth}' 'SSSFTR_SE05X_AuthECKey' Should be ON")
            ENDIF()
            IF(NOT ${SSSFTR_SW_ECC})
                MESSAGE(SEND_ERROR "For 'PTMW_SE05X_Auth=${PTMW_SE05X_Auth}' 'SSSFTR_SW_ECC' Should be ON")
            ENDIF()
        ENDIF()
        IF(${SSSFTR_SE05X_AuthECKey})
            IF(NOT ${SSSFTR_SE05X_AuthSession})
                MESSAGE(SEND_ERROR "For 'SSSFTR_SE05X_AuthECKey' 'SSSFTR_SE05X_AuthSession' Should be ON")
            ENDIF()
            IF(NOT ${SSSFTR_SW_ECC})
                MESSAGE(SEND_ERROR "For 'SSSFTR_SE05X_AuthECKey' 'SSSFTR_SW_ECC' Should be ON")
            ENDIF()
            IF(NOT ${SSSFTR_SE05X_ECC})
                MESSAGE(SEND_ERROR "For 'SSSFTR_SE05X_AuthECKey' 'SSSFTR_SE05X_ECC' Should be ON")
            ENDIF()
        ENDIF()
    ENDMACRO()

    MESSAGE(STATUS "PTMW_SE05X_Auth - ${PTMW_SE05X_Auth}")
ELSE(SSS_HAVE_APPLET_SE05X_IOT)
    MACRO(EXPOSE_SE05X_AUTH_STRATEGY)

    ENDMACRO()
ENDIF(SSS_HAVE_APPLET_SE05X_IOT)

IF(SSS_HAVE_APPLET_A71CH OR SSS_HAVE_APPLET_A71CH_SIM)
    IF(NOT("${PTMW_SE05X_Auth}" STREQUAL "None"))
        MESSAGE(FATAL_ERROR "Cannot use this combination for A71CH")
    ENDIF()
ENDIF()

INCLUDE(scripts/cmake_options_check.cmake)

IF(SSS_HAVE_APPLET_SE051_UWB)
   IF(NOT SSS_HAVE_SE05X_VER_GTE_07_02)
        MESSAGE(FATAL_ERROR "SE051_UWB to be used with version 7_X or later")
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOST_FRDMMCXA153 AND SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    MESSAGE(FATAL_ERROR "Cannot use SSS_HAVE_HOST_FRDMMCXA153 with SSS_HAVE_HOSTCRYPTO_MBEDTLS")
ENDIF()

IF(SSS_HAVE_HOST_FRDMMCXN947 AND SSS_HAVE_HOSTCRYPTO_MBEDTLS AND SSS_HAVE_MBEDTLS_2_X)
    MESSAGE(FATAL_ERROR "Cannot use SSS_HAVE_HOST_FRDMMCXN947 with SSS_HAVE_MBEDTLS_2_X")
ENDIF()

# .. By default, we don't have it
SET(SSS_HAVE_ECC 0)
SET(SSS_HAVE_RSA 0)
# .. SET(SSS_HAVE_FIPS
# ..     OFF
# ..     CACHE BOOL "Compile Tests with/without FIPS Mode aware"
# .. )
SET(SSS_HAVE_EC_ED 0) #Edwards Curve.
SET(SSS_HAVE_EC_MONT 0) #Montgomery Curve.
SET(SSS_HAVE_TLS_HANDSHAKE 0) #TLS Handshake.
SET(SSS_HAVE_IMPORT 0) #TLS IMPORT.

# .. Based on variant, we enable and expose that feature.
IF(SSS_HAVE_APPLET_A71CH OR SSS_HAVE_APPLET_A71CH_SIM)
    SET(SSS_HAVE_ECC 1)
ENDIF()

IF(SSS_HAVE_APPLET_SE05X_A)
    SET(SSS_HAVE_ECC 1)
ENDIF()

IF(SSS_HAVE_APPLET_SE05X_B)
    SET(SSS_HAVE_RSA 1)
ENDIF()

IF(SSS_HAVE_APPLET_SE05X_C)
    SET(SSS_HAVE_ECC 1)
    SET(SSS_HAVE_RSA 1)
    SET(SSS_HAVE_EC_ED 1)
    SET(SSS_HAVE_EC_MONT 1)
    SET(SSS_HAVE_TLS_HANDSHAKE 1)
    SET(SSS_HAVE_IMPORT 1)
ENDIF()

IF(SSS_HAVE_APPLET_SE051_UWB)
    SET(SSS_HAVE_ECC 1)
    SET(SSS_HAVE_RSA 1)
    SET(SSS_HAVE_EC_ED 0)
    SET(SSS_HAVE_EC_MONT 0)
    SET(SSS_HAVE_TLS_HANDSHAKE 1)
    SET(SSS_HAVE_IMPORT 1)
ENDIF()

IF (NOT SSS_HAVE_APPLET_NONE)
    SET(SSS_HAVE_MIFARE_DESFIRE 1) #MIFARE DESFire.
    SET(SSS_HAVE_PBKDF2 1) #PBKDF2.
ENDIF()

IF(SSS_HAVE_APPLET_AUTH)
    SET(SSS_HAVE_ECC 1)
    SET(SSS_HAVE_RSA 0)
    SET(SSS_HAVE_EC_ED 0)
    SET(SSS_HAVE_EC_MONT 0)
    SET(SSS_HAVE_TLS_HANDSHAKE 1)
    SET(SSS_HAVE_IMPORT 1)
    SET(SSS_HAVE_MIFARE_DESFIRE 0)
    SET(SSS_HAVE_PBKDF2 0)
ENDIF()

IF(SSS_HAVE_APPLET_SE050_E)
    SET(SSS_HAVE_ECC 1)
    SET(SSS_HAVE_RSA 0)
    SET(SSS_HAVE_EC_ED 1)
    SET(SSS_HAVE_EC_MONT 1)
    SET(SSS_HAVE_TLS_HANDSHAKE 1)
    SET(SSS_HAVE_IMPORT 1)
ENDIF()

IF(SSS_HAVE_APPLET_SE051_H)
    SET(SSS_HAVE_ECC 1)
    SET(SSS_HAVE_RSA 1)
    SET(SSS_HAVE_EC_ED 1)
    SET(SSS_HAVE_EC_MONT 1)
    SET(SSS_HAVE_TLS_HANDSHAKE 1)
    SET(SSS_HAVE_IMPORT 1)
ENDIF()

IF(WithNXPNFCRdLib)
    SET(SSS_HAVE_NXPNFCRDLIB 1)
ELSE()
    SET(SSS_HAVE_NXPNFCRDLIB 0)
ENDIF()

IF(SSS_HAVE_KSDK)
    SET(NFC_663_SPI ON)
    SET(NFC_663_VCOM OFF)
ELSE()
    SET(NFC_663_SPI OFF)
    SET(NFC_663_VCOM ON)
ENDIF()

IF(SSS_HAVE_SBL_SBL_LPC55S)
    IF(NOT SSS_HAVE_HOST_LPCXPRESSO55S_S)
        MESSAGE(FATAL_ERROR "Use secure host for SBL bootable applications.")
    ENDIF()
ENDIF()
SET(eSEName "eSEName-NA")
IF(SSS_HAVE_APPLET_A7XX)
    SET(eSEName "a71xx")
ENDIF()
IF(SSS_HAVE_APPLET_SE050_EAR)
    SET(eSEName "SE050_EAR")
ENDIF()
IF(SSS_HAVE_APPLET_SE05X_IOT)
    SET(eSEName "se05x")
ENDIF()

SET(NXPProprietary ON)

IF(WithAccessMgr_UnixSocket)
    IF(NOT SSS_HAVE_HOST_LINUX_LIKE)
        MESSAGE(FATAL_ERROR "Access Manager with Unix scoket is supported only on Linux platform.")
    ENDIF()
    ADD_DEFINITIONS(-DACCESS_MGR_UNIX_SOCKETS)
ENDIF()

IF(NOT SSSFTR_SE05X_RSA)
    SET(SSS_HAVE_RSA 0)
ENDIF()
