#
# Copyright 2019,2020,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

# Don't do an in-source build
# ###########################
#if(${PROJECT_SOURCE_DIR} STREQUAL ${PROJECT_BINARY_DIR})
#    message( "  In-source builds are not allowed." )
#    message( "Create a specific build directories under tls_client" )
#    message( "  mkdir build" )
#    message( "  cd build" )
#    message( "  cmake ../." )
#    message( FATAL_ERROR "  In-source builds not allowed.  Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt and CMakeFiles folder." )
#endif()
#
#MESSAGE("(1) ${PROJECT_SOURCE_DIR}")
#MESSAGE("(2) ${PROJECT_BINARY_DIR}")

PROJECT(tls_client)

INCLUDE(/usr/local/share/se05x/cmake_options_installed.cmake)

SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE Debug)

# Applet specific settings
IF(SSS_HAVE_APPLET_SE05X_A OR SSS_HAVE_APPLET_SE05X_B OR SSS_HAVE_APPLET_SE05X_C OR SSS_HAVE_APPLET_SE050_E OR SSS_HAVE_APPLET_SE051_H OR SSS_HAVE_APPLET_AUTH)
    MESSAGE("Secure Element: SE05X")
    SET(SE_LIB libse05x)
ELSE()
    MESSAGE(ERROR "Invalid Applet")
ENDIF(SSS_HAVE_APPLET_SE05X_A OR SSS_HAVE_APPLET_SE05X_B OR SSS_HAVE_APPLET_SE05X_C OR SSS_HAVE_APPLET_SE050_E OR SSS_HAVE_APPLET_SE051_H OR SSS_HAVE_APPLET_AUTH)

# Interface specific settings
IF(SSS_HAVE_SMCOM_JRCP_V2)
    MESSAGE("JRCP V2 interface")
    ADD_DEFINITIONS(-DSMCOM_JRCP_V2)
ELSEIF(SSS_HAVE_SMCOM_JRCP_V1)
    MESSAGE("JRCP V1 interface")
ELSEIF(SSS_HAVE_SMCOM_SCI2C)
    MESSAGE("SCI2C interface")
ELSEIF(SSS_HAVE_SMCOM_T1OI2C)
    MESSAGE("T1oI2C interface")
    ADD_DEFINITIONS(-DT1oI2C -DT1oI2C_UM11225)
ELSE()
    MESSAGE(ERROR "No supported/known SMCOM implementation available")
ENDIF(SSS_HAVE_SMCOM_JRCP_V2)

FIND_PACKAGE(OpenSSL) # Find the OpenSSL Package
IF(OPENSSL_FOUND)
    MESSAGE("Found: ${OPENSSL_CRYPTO_LIBRARY} and ${OPENSSL_SSL_LIBRARY}")
    INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
    ADD_DEFINITIONS(-DOPENSSL_LOAD_CONF)
ELSE()
    MESSAGE(ERROR "OpenSSL required")
ENDIF()

INCLUDE_DIRECTORIES(
    /usr/local/include/se05x
    ../common
    ../../../hostlib/hostLib/libCommon/log
)

ADD_EXECUTABLE(
    tlsSe050Client
    ../common/snw_sss.cpp
    ../common/snw_util.cpp
    src/tlsSe050Client.cpp
)

MESSAGE("OPENSSL_CRYPTO_LIBRARY: " ${OPENSSL_CRYPTO_LIBRARY})

MESSAGE("OPENSSL_SSL_LIBRARY: " ${OPENSSL_SSL_LIBRARY})

# Comment / put to false to link against static libraries
SET(LINK_TO_SHARED TRUE)

IF(SSS_HAVE_Host_Cygwin)
    MESSAGE("Cygwin Host")
    SET(MY_LIBRARIES_PREFIX "/usr/local/lib/")
    IF(LINK_TO_SHARED)
        MESSAGE("Linking to shared libraries")
        SET(MY_LIB_EXTENSION "dll.a")
    ELSE()
        MESSAGE("Linking to static libraries")
        SET(MY_LIB_EXTENSION "a")
    ENDIF(LINK_TO_SHARED)
ELSE()
    SET(MY_LIBRARIES_PREFIX "")
    IF(LINK_TO_SHARED)
        MESSAGE("Linking to shared libraries")
        SET(MY_LIB_EXTENSION "so")
    ELSE()
        MESSAGE("Linking to static libraries")
        SET(MY_LIB_EXTENSION "a")
    ENDIF(LINK_TO_SHARED)
ENDIF(SSS_HAVE_Host_Cygwin)

TARGET_LINK_LIBRARIES(
    tlsSe050Client
    ${MY_LIBRARIES_PREFIX}libSSS_APIs.${MY_LIB_EXTENSION}
    ${MY_LIBRARIES_PREFIX}${SE_LIB}.${MY_LIB_EXTENSION}
    ${MY_LIBRARIES_PREFIX}liba7x_utils.${MY_LIB_EXTENSION}
    ${MY_LIBRARIES_PREFIX}libsmCom.${MY_LIB_EXTENSION}
    ${MY_LIBRARIES_PREFIX}libex_common.${MY_LIB_EXTENSION}
    ${MY_LIBRARIES_PREFIX}libmwlog.${MY_LIB_EXTENSION}
    ${OPENSSL_CRYPTO_LIBRARY}
    ${OPENSSL_SSL_LIBRARY}
)

IF(SSS_HAVE_SMCOM_JRCP_V2)
    TARGET_LINK_LIBRARIES(tlsSe050Client ${MY_LIBRARIES_PREFIX}libjrcplib.${MY_LIB_EXTENSION})
ENDIF(SSS_HAVE_SMCOM_JRCP_V2)

IF(NXPInternal)
    ADD_EXECUTABLE(
        tstTlsSe050Client
        ../common/snw_sss.cpp
        ../common/snw_util.cpp
        tst/tstTlsSe050Client.cpp
    )

    TARGET_LINK_LIBRARIES(
        tstTlsSe050Client
        ${MY_LIBRARIES_PREFIX}libSSS_APIs.${MY_LIB_EXTENSION}
        ${MY_LIBRARIES_PREFIX}${SE_LIB}.${MY_LIB_EXTENSION}
        ${MY_LIBRARIES_PREFIX}liba7x_utils.${MY_LIB_EXTENSION}
        ${MY_LIBRARIES_PREFIX}libsmCom.${MY_LIB_EXTENSION}
        ${MY_LIBRARIES_PREFIX}libex_common.${MY_LIB_EXTENSION}
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
        # libstdc++.${MY_LIB_EXTENSION}
    )

    IF(SSS_HAVE_SMCOM_JRCP_V2)
        TARGET_LINK_LIBRARIES(tstTlsSe050Client ${MY_LIBRARIES_PREFIX}libjrcplib.${MY_LIB_EXTENSION})
    ENDIF(SSS_HAVE_SMCOM_JRCP_V2)

    ADD_EXECUTABLE(ecdhKeyAgreement ../common/snw_sss.cpp tst/ecdhKeyAgreement.c)

    TARGET_LINK_LIBRARIES(
        ecdhKeyAgreement
        ${MY_LIBRARIES_PREFIX}libSSS_APIs.${MY_LIB_EXTENSION}
        ${MY_LIBRARIES_PREFIX}${SE_LIB}.${MY_LIB_EXTENSION}
        ${MY_LIBRARIES_PREFIX}liba7x_utils.${MY_LIB_EXTENSION}
        ${MY_LIBRARIES_PREFIX}libsmCom.${MY_LIB_EXTENSION}
        ${MY_LIBRARIES_PREFIX}libex_common.${MY_LIB_EXTENSION}
        # libstdc++.${MY_LIB_EXTENSION}
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
    )

    IF(SSS_HAVE_SMCOM_JRCP_V2)
        TARGET_LINK_LIBRARIES(ecdhKeyAgreement ${MY_LIBRARIES_PREFIX}libjrcplib.${MY_LIB_EXTENSION})
    ENDIF(SSS_HAVE_SMCOM_JRCP_V2)

    ADD_EXECUTABLE(
        tstTlsSe050ClientConnectionLoop
        ../common/snw_sss.cpp
        ../common/snw_util.cpp
        tst/tstTlsSe050ClientConnectionLoop.cpp
    )

    TARGET_LINK_LIBRARIES(
        tstTlsSe050ClientConnectionLoop
        ${MY_LIBRARIES_PREFIX}libSSS_APIs.${MY_LIB_EXTENSION}
        ${MY_LIBRARIES_PREFIX}${SE_LIB}.${MY_LIB_EXTENSION}
        ${MY_LIBRARIES_PREFIX}liba7x_utils.${MY_LIB_EXTENSION}
        ${MY_LIBRARIES_PREFIX}libsmCom.${MY_LIB_EXTENSION}
        ${MY_LIBRARIES_PREFIX}libex_common.${MY_LIB_EXTENSION}
        # libstdc++.${MY_LIB_EXTENSION}
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
    )

    IF(SSS_HAVE_SMCOM_JRCP_V2)
        TARGET_LINK_LIBRARIES(tstTlsSe050ClientConnectionLoop ${MY_LIBRARIES_PREFIX}libjrcplib.${MY_LIB_EXTENSION})
    ENDIF(SSS_HAVE_SMCOM_JRCP_V2)

ENDIF(NXPInternal)
