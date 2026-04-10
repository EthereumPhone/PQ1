# Copyright 2018-2022,2024-2025 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
# #############################################################
# This file is generated using a script
# #############################################################
#


### PTMW_Applet : The Secure Element Applet
# 
# You can compile host library for different Applets listed below.
# Please note, some of these Applets may be for NXP Internal use only.

doPTMW_Applet_None_ON="-DPTMW_Applet=None" #Compiling without any Applet Support

doPTMW_Applet_SE05X_A_ON="-DPTMW_Applet=SE05X_A" #SE050 Type A (ECC)

doPTMW_Applet_SE05X_B_ON="-DPTMW_Applet=SE05X_B" #SE050 Type B (RSA)

doPTMW_Applet_SE05X_C_ON="-DPTMW_Applet=SE05X_C" #SE050 (Super set of A + B), SE051, SE052

doPTMW_Applet_SE051_UWB_ON="-DPTMW_Applet=SE051_UWB" #SE051UWB (Similar to SE05x)

doPTMW_Applet_SE051_H_ON="-DPTMW_Applet=SE051_H" #SE051 with SPAKE Support

doPTMW_Applet_AUTH_ON="-DPTMW_Applet=AUTH" #AUTH

doPTMW_Applet_SE050_E_ON="-DPTMW_Applet=SE050_E" #SE050E

doPTMW_Applet_LoopBack_ON="-DPTMW_Applet=LoopBack" #NXP Internal testing Applet


### PTMW_SE05X_Ver : Configures supported applet version.
# Set it to match the version used on the SE.
# Examples: for SE050A/B/C/F set 03_XX, for SE050E/51/A5000/SE052 set 07_02.
# 
# 

doPTMW_SE05X_Ver_03_XX_ON="-DPTMW_SE05X_Ver=03_XX" #SE050A/B/C/F

doPTMW_SE05X_Ver_07_02_ON="-DPTMW_SE05X_Ver=07_02" #SE050E/51/A5000/SE052


### PTMW_Host : Host where the software stack is running
# 
# e.g. Windows, PC Linux, Embedded Linux, Kinetis like embedded platform

doPTMW_Host_Darwin_ON="-DPTMW_Host=Darwin" #OS X / Macintosh

doPTMW_Host_PCLinux32_ON="-DPTMW_Host=PCLinux32" #PC/Laptop Linux with 32bit libraries

doPTMW_Host_PCLinux64_ON="-DPTMW_Host=PCLinux64" #PC/Laptop Linux with 64bit libraries

doPTMW_Host_PCWindows_ON="-DPTMW_Host=PCWindows" #PC/Laptop Windows

doPTMW_Host_Cygwin_ON="-DPTMW_Host=Cygwin" #Using Cygwin

doPTMW_Host_frdmk64f_ON="-DPTMW_Host=frdmk64f" #Embedded Kinetis Freedom K64F

doPTMW_Host_evkmimxrt1060_ON="-DPTMW_Host=evkmimxrt1060" #Embedded Kinetis i.MX RT 1060

doPTMW_Host_evkmimxrt1170_ON="-DPTMW_Host=evkmimxrt1170" #Embedded Kinetis i.MX RT1170

doPTMW_Host_frdmmcxn947_ON="-DPTMW_Host=frdmmcxn947" #Embedded Kinetis Freedom MCXN947

doPTMW_Host_frdmmcxa153_ON="-DPTMW_Host=frdmmcxa153" #Embedded Kinetis Freedom MCXA153

doPTMW_Host_lpcxpresso55s_ON="-DPTMW_Host=lpcxpresso55s" #Embedded LPCXpresso55s (No demarcation of secure/non-secure world)

doPTMW_Host_lpcxpresso55s_ns_ON="-DPTMW_Host=lpcxpresso55s_ns" #Non Secure world of LPCXpresso55s

doPTMW_Host_lpcxpresso55s_s_ON="-DPTMW_Host=lpcxpresso55s_s" #Secure world of LPCXpresso55s

doPTMW_Host_iMXLinux_ON="-DPTMW_Host=iMXLinux" #Embedded Linux on i.MX

doPTMW_Host_Raspbian_ON="-DPTMW_Host=Raspbian" #Embedded Linux on RaspBerry PI

doPTMW_Host_Android_ON="-DPTMW_Host=Android" #Android

doPTMW_Host_Win10IoT_ON="-DPTMW_Host=Win10IoT" #Windows 10 IoT Core


### PTMW_SMCOM : Communication Interface
# 
# How the host library communicates to the Secure Element.
# This may be directly over an I2C interface on embedded platform.
# Or sometimes over Remote protocol like JRCP_V1 / JRCP_V1_AM / JRCP_V2 / VCOM from PC.

doPTMW_SMCOM_None_ON="-DPTMW_SMCOM=None" #Not using any Communication layer

doPTMW_SMCOM_JRCP_V2_ON="-DPTMW_SMCOM=JRCP_V2" #Socket Interface New Implementation

#Socket Interface Old Implementation.
# This is the interface used from Host PC when when we run jrcpv1_server
# from the linux PC.

doPTMW_SMCOM_JRCP_V1_ON="-DPTMW_SMCOM=JRCP_V1"

doPTMW_SMCOM_JRCP_V1_AM_ON="-DPTMW_SMCOM=JRCP_V1_AM" #JRCP_V1 extended with Access manager features

doPTMW_SMCOM_VCOM_ON="-DPTMW_SMCOM=VCOM" #Virtual COM Port

doPTMW_SMCOM_T1oI2C_ON="-DPTMW_SMCOM=T1oI2C" #T=1 over I2C for SE050

doPTMW_SMCOM_T1oI2C_GP1_0_ON="-DPTMW_SMCOM=T1oI2C_GP1_0" #GP Spec

doPTMW_SMCOM_RC663_VCOM_ON="-DPTMW_SMCOM=RC663_VCOM" #Via RC663 Over VCOM Interface from Windows PC

doPTMW_SMCOM_PN7150_ON="-DPTMW_SMCOM=PN7150" #NFC Interface using PN7150

doPTMW_SMCOM_Thread_ON="-DPTMW_SMCOM=Thread" #Thread Mode interface

doPTMW_SMCOM_PCSC_ON="-DPTMW_SMCOM=PCSC" #CCID PC/SC reader interface


### PTMW_HostCrypto : Counterpart Crypto on Host
# 
# What is being used as a cryptographic library on the host.
# As of now only OpenSSL / mbedTLS is supported

doPTMW_HostCrypto_MBEDTLS_ON="-DPTMW_HostCrypto=MBEDTLS" #Use mbedTLS as host crypto

doPTMW_HostCrypto_OPENSSL_ON="-DPTMW_HostCrypto=OPENSSL" #Use OpenSSL as host crypto

#User Implementation of Host Crypto
# e.g. Files at ``sss/src/user/crypto`` have low level AES/CMAC primitives.
# The files at ``sss/src/user`` use those primitives.
# This becomes an example for users with their own AES Implementation
# This then becomes integration without mbedTLS/OpenSSL for SCP03 / AESKey.
# 
# .. note:: ECKey abstraction is not implemented/available yet.

doPTMW_HostCrypto_User_ON="-DPTMW_HostCrypto=User"

#NO Host Crypto
# Note, this is unsecure and only provided for experimentation
# on platforms that do not have an mbedTLS PORT
# Many :ref:`sssftr-control` have to be disabled to have a valid build.

doPTMW_HostCrypto_None_ON="-DPTMW_HostCrypto=None"


### PTMW_RTOS : Choice of Operating system
# 
# Default would mean nothing special.
# i.e. Without any RTOS on embedded system, or default APIs on PC/Linux

doPTMW_RTOS_Default_ON="-DPTMW_RTOS=Default" #No specific RTOS. Either bare matal on embedded system or native linux or Windows OS

doPTMW_RTOS_FreeRTOS_ON="-DPTMW_RTOS=FreeRTOS" #Free RTOS for embedded systems


### PTMW_mbedTLS_ALT : ALT Engine implementation for mbedTLS
# 
# When set to None, mbedTLS would not use ALT Implementation to connect to / use Secure Element.
# This needs to be set to SSS for Cloud Demos over SSS APIs

doPTMW_mbedTLS_ALT_SSS_ON="-DPTMW_mbedTLS_ALT=SSS" #Use SSS Layer ALT implementation

doPTMW_mbedTLS_ALT_PSA_ON="-DPTMW_mbedTLS_ALT=PSA" #Enable TF-M based on PSA as ALT

#Not using any mbedTLS_ALT
# 
# When this is selected, cloud demos can not work with mbedTLS

doPTMW_mbedTLS_ALT_None_ON="-DPTMW_mbedTLS_ALT=None"


### PTMW_SCP : Secure Channel Protocol
# 
# In case we enable secure channel to Secure Element, which interface to be used.

doPTMW_SCP_None_ON="-DPTMW_SCP=None" #

doPTMW_SCP_SCP03_SSS_ON="-DPTMW_SCP=SCP03_SSS" #Use SSS Layer for SCP.  Used for SE050 family.


### PTMW_FIPS : Enable or disable FIPS
# 
# This selection mostly impacts tests, and generally not the actual Middleware

doPTMW_FIPS_None_ON="-DPTMW_FIPS=None" #NO FIPS

doPTMW_FIPS_SE050_ON="-DPTMW_FIPS=SE050" #SE050 IC FIPS

doPTMW_FIPS_140_2_ON="-DPTMW_FIPS=140_2" #FIPS 140-2

doPTMW_FIPS_140_3_ON="-DPTMW_FIPS=140_3" #FIPS 140-3


### PTMW_SBL : Enable/Disable SBL Bootable support
# 
# This option is to enable/disable boot from SBL by switching linker address

doPTMW_SBL_None_ON="-DPTMW_SBL=None" #Not SBL bootable

doPTMW_SBL_SBL_LPC55S_ON="-DPTMW_SBL=SBL_LPC55S" #SE050 based LPC55S SBL bootable


### PTMW_SE05X_Auth : SE050 Authentication
# 
# This settings is used by examples to connect using various options
# to authenticate with the Applet.
# The SE05X_Auth options can be changed for MCU-SDK Demos and Examples.
# To change SE05X_Auth option follow below steps.
# Set flag ``SSS_HAVE_SCP_SCP03_SSS`` to 1 and Reset flag ``SSS_HAVE_SCP_NONE`` to 0.
# To change SE05X_Auth option other than ``None`` and  ``PlatfSCP03``,
# execute se05x_Delete_and_test_provision.exe in order to provision the Authentication Key.
# To change SE05X_Auth option to ``ECKey`` or ``ECKey_PlatfSCP03``,
# Set additional flag ``SSS_HAVE_HOSTCRYPTO_ANY`` to 1.

doPTMW_SE05X_Auth_None_ON="-DPTMW_SE05X_Auth=None" #Use the default session (i.e. session less) login

doPTMW_SE05X_Auth_UserID_ON="-DPTMW_SE05X_Auth=UserID" #Do User Authentication with UserID

doPTMW_SE05X_Auth_PlatfSCP03_ON="-DPTMW_SE05X_Auth=PlatfSCP03" #Use Platform SCP for connection to SE

#Do User Authentication with AES Key
# Earlier this was called AppletSCP03

doPTMW_SE05X_Auth_AESKey_ON="-DPTMW_SE05X_Auth=AESKey"

#Do User Authentication with EC Key
# Earlier this was called FastSCP

doPTMW_SE05X_Auth_ECKey_ON="-DPTMW_SE05X_Auth=ECKey"

doPTMW_SE05X_Auth_UserID_PlatfSCP03_ON="-DPTMW_SE05X_Auth=UserID_PlatfSCP03" #UserID and PlatfSCP03

doPTMW_SE05X_Auth_AESKey_PlatfSCP03_ON="-DPTMW_SE05X_Auth=AESKey_PlatfSCP03" #AESKey and PlatfSCP03

doPTMW_SE05X_Auth_ECKey_PlatfSCP03_ON="-DPTMW_SE05X_Auth=ECKey_PlatfSCP03" #ECKey and PlatfSCP03


### PTMW_Log : Logging

doPTMW_Log_Default_ON="-DPTMW_Log=Default" #Default Logging

doPTMW_Log_Verbose_ON="-DPTMW_Log=Verbose" #Very Verbose logging

doPTMW_Log_Silent_ON="-DPTMW_Log=Silent" #Totally silent logging

doPTMW_Log_SeggerRTT_ON="-DPTMW_Log=SeggerRTT" #Segger Real Time Transfer (For Test Automation, NXP Internal)


### CMAKE_BUILD_TYPE : See https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html
# 
# For embedded builds, this choices sets optimization levels.
# For MSVC builds, build type is selected from IDE As well

doCMAKE_BUILD_TYPE_Debug_ON="-DCMAKE_BUILD_TYPE=Debug" #For developer

doCMAKE_BUILD_TYPE_Release_ON="-DCMAKE_BUILD_TYPE=Release" #Optimization enabled and debug symbols removed

doCMAKE_BUILD_TYPE_RelWithDebInfo_ON="-DCMAKE_BUILD_TYPE=RelWithDebInfo" #Optimization enabled but with debug symbols

doCMAKE_BUILD_TYPE__ON="-DCMAKE_BUILD_TYPE=" #Empty Allowed


### PTMW_OpenSSL : For PC, which OpenSSL to pick up
# 
# On Linux based builds, this option has no impact, because the build system
# picks up the default available/installed OpenSSL from the system directly.

doPTMW_OpenSSL_1_1_1_ON="-DPTMW_OpenSSL=1_1_1" #Use 1.1.1 version (Only applicable on PC)

doPTMW_OpenSSL_3_0_ON="-DPTMW_OpenSSL=3_0" #Use 3.0 version (Only applicable on PC)


### PTMW_MBedTLS : Which MBedTLS version to choose

doPTMW_MBedTLS_2_X_ON="-DPTMW_MBedTLS=2_X" #Use 2.X version

doPTMW_MBedTLS_3_X_ON="-DPTMW_MBedTLS=3_X" #Use 3.X version


### PTMW_SE_RESET_LOGIC : Reset logic of Secure Element. The value of this will be used for 'SE_RESET_LOGIC' define in 'se05x_ic_reset' function. Select 1 (Active High) for SE050 and 51. Select 0 (Active low) for SE052.

doPTMW_SE_RESET_LOGIC_1_ON="-DPTMW_SE_RESET_LOGIC=1" #reset logic is set to 1

doPTMW_SE_RESET_LOGIC_0_ON="-DPTMW_SE_RESET_LOGIC=0" #reset logic is set to 0
# SE05X Secure Element : Symmetric AES

doSSSFTR_SE05X_AES_ON="-DSSSFTR_SE05X_AES=ON"

doSSSFTR_SE05X_AES_OFF="-DSSSFTR_SE05X_AES=OFF"
# SE05X Secure Element : Elliptic Curve Cryptography

doSSSFTR_SE05X_ECC_ON="-DSSSFTR_SE05X_ECC=ON"

doSSSFTR_SE05X_ECC_OFF="-DSSSFTR_SE05X_ECC=OFF"
# SE05X Secure Element : RSA

doSSSFTR_SE05X_RSA_ON="-DSSSFTR_SE05X_RSA=ON"

doSSSFTR_SE05X_RSA_OFF="-DSSSFTR_SE05X_RSA=OFF"
# SE05X Secure Element : KEY operations : SET Key

doSSSFTR_SE05X_KEY_SET_ON="-DSSSFTR_SE05X_KEY_SET=ON"

doSSSFTR_SE05X_KEY_SET_OFF="-DSSSFTR_SE05X_KEY_SET=OFF"
# SE05X Secure Element : KEY operations : GET Key

doSSSFTR_SE05X_KEY_GET_ON="-DSSSFTR_SE05X_KEY_GET=ON"

doSSSFTR_SE05X_KEY_GET_OFF="-DSSSFTR_SE05X_KEY_GET=OFF"
# SE05X Secure Element : Authenticate via ECKey

doSSSFTR_SE05X_AuthECKey_ON="-DSSSFTR_SE05X_AuthECKey=ON"

doSSSFTR_SE05X_AuthECKey_OFF="-DSSSFTR_SE05X_AuthECKey=OFF"
# SE05X Secure Element : Allow creation of user/authenticated session.
#
# If the intended deployment only uses Platform SCP
# Or it is a pure session less integration, this can
# save some code size.

doSSSFTR_SE05X_AuthSession_ON="-DSSSFTR_SE05X_AuthSession=ON"

doSSSFTR_SE05X_AuthSession_OFF="-DSSSFTR_SE05X_AuthSession=OFF"
# SE05X Secure Element : Allow creation/deletion of Crypto Objects
#
# If disabled, new Crytpo Objects are neither created and
# old/existing Crypto Objects are not deleted.
# It is assumed that during provisioning phase, the required
# Crypto Objects are pre-created or they are never going to
# be needed.

doSSSFTR_SE05X_CREATE_DELETE_CRYPTOOBJ_ON="-DSSSFTR_SE05X_CREATE_DELETE_CRYPTOOBJ=ON"

doSSSFTR_SE05X_CREATE_DELETE_CRYPTOOBJ_OFF="-DSSSFTR_SE05X_CREATE_DELETE_CRYPTOOBJ=OFF"
# Software : Symmetric AES

doSSSFTR_SW_AES_ON="-DSSSFTR_SW_AES=ON"

doSSSFTR_SW_AES_OFF="-DSSSFTR_SW_AES=OFF"
# Software : Elliptic Curve Cryptography

doSSSFTR_SW_ECC_ON="-DSSSFTR_SW_ECC=ON"

doSSSFTR_SW_ECC_OFF="-DSSSFTR_SW_ECC=OFF"
# Software : RSA

doSSSFTR_SW_RSA_ON="-DSSSFTR_SW_RSA=ON"

doSSSFTR_SW_RSA_OFF="-DSSSFTR_SW_RSA=OFF"
# Software : KEY operations : SET Key

doSSSFTR_SW_KEY_SET_ON="-DSSSFTR_SW_KEY_SET=ON"

doSSSFTR_SW_KEY_SET_OFF="-DSSSFTR_SW_KEY_SET=OFF"
# Software : KEY operations : GET Key

doSSSFTR_SW_KEY_GET_ON="-DSSSFTR_SW_KEY_GET=ON"

doSSSFTR_SW_KEY_GET_OFF="-DSSSFTR_SW_KEY_GET=OFF"
# Software : Used as a test counterpart
#
# e.g. Major part of the mebdTLS SSS layer is purely used for
# testing of Secure Element implementation, and can be avoided
# fully during many production scenarios.

doSSSFTR_SW_TESTCOUNTERPART_ON="-DSSSFTR_SW_TESTCOUNTERPART=ON"

doSSSFTR_SW_TESTCOUNTERPART_OFF="-DSSSFTR_SW_TESTCOUNTERPART=OFF"

# Compile in NXP NFC RdLib support
doWithNXPNFCRdLib_ON="-DWithNXPNFCRdLib=ON"
doWithNXPNFCRdLib_OFF="-DWithNXPNFCRdLib=OFF"

# Compile With open62541 Support
doWithOPCUA_open62541_ON="-DWithOPCUA_open62541=ON"
doWithOPCUA_open62541_OFF="-DWithOPCUA_open62541=OFF"

# Create and use shared libraries
doWithSharedLIB_ON="-DWithSharedLIB=ON"
doWithSharedLIB_OFF="-DWithSharedLIB=OFF"

# Compile Access Manager with UNIX socket support (Default is STREAM sockets).
doWithAccessMgr_UnixSocket_ON="-DWithAccessMgr_UnixSocket=ON"
doWithAccessMgr_UnixSocket_OFF="-DWithAccessMgr_UnixSocket=OFF"

# NXP Internal
doNXPInternal_ON="-DNXPInternal=ON"
doNXPInternal_OFF="-DNXPInternal=OFF"

# Compile with Code Coverage
doWithCodeCoverage_ON="-DWithCodeCoverage=ON"
doWithCodeCoverage_OFF="-DWithCodeCoverage=OFF"

# Include code from ../customer/tpm2
doWithExtCustomerTPMCode_ON="-DWithExtCustomerTPMCode=ON"
doWithExtCustomerTPMCode_OFF="-DWithExtCustomerTPMCode=OFF"
