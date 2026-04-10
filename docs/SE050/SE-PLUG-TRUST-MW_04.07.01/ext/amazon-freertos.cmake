# Copyright 2019,2024 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

SET(DEMOS_KSDK_DIR ${SIMW_TOP_DIR}/demos/ksdk)

PROJECT(freertos-kernel)

FILE(
    GLOB
    files
    freertos/freertos-kernel/*.c
    amazon-freertos.cmake
)

IF(SSS_HAVE_HOST_PCWINDOWS)
    FILE(
        GLOB
        port_files
        freertos/freertos-kernel/portable/MemMang/heap_4.c
        ${DEMOS_KSDK_DIR}/x86pc/*.h
        ext/TraceRecorder/*.c
    )
ENDIF()

IF(SSS_HAVE_HOST_FRDMK64F)
    FILE(
        GLOB
        port_files
        freertos/freertos-kernel/portable/GCC/ARM_CM4F/*.c
        freertos/freertos-kernel/portable/MemMang/heap_4.c
        ${SIMW_TOP_DIR}/demos/ksdk/common/freertos/*.c
    )
ENDIF()

IF(SSS_HAVE_HOST_EVKMIMXRT1060 OR SSS_HAVE_HOST_EVKMIMXRT1170)
    FILE(
        GLOB
        port_files
        freertos/freertos-kernel/portable/GCC/ARM_CM4F/*.c
        freertos/freertos-kernel/portable/MemMang/heap_4.c
        ${SIMW_TOP_DIR}/demos/ksdk/common/freertos/*.c
    )
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S OR SSS_HAVE_HOST_FRDMMCXN947 OR SSS_HAVE_HOST_FRDMMCXA153)
    FILE(
        GLOB
        port_files
        freertos/freertos-kernel/portable/GCC/ARM_CM33_NTZ/non_secure/*.c
        freertos/freertos-kernel/portable/MemMang/heap_4.c
        ${SIMW_TOP_DIR}/demos/ksdk/common/freertos/*.c
    )
ENDIF()

IF(
    SSS_HAVE_APPLET_A7XX
    OR SSS_HAVE_APPLET_SE050_EAR
    OR SSS_HAVE_APPLET_SE05X_IOT
    OR SSS_HAVE_APPLET_LOOPBACK
)
    LIST(
        APPEND
        port_files
        ${SIMW_TOP_DIR}/hostlib/hostLib/libCommon/infra/sm_demo_utils_rtos.c
    )
ENDIF()

ADD_LIBRARY(${PROJECT_NAME} ${files} ${port_files})

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC freertos/freertos-kernel/include
    PUBLIC ${SIMW_TOP_DIR}/sss/ex/inc
    PUBLIC ${DEMOS_KSDK_DIR}/common
    PUBLIC aws_iot/iot-reference/examples/common/logging
)

IF(SSS_HAVE_HOST_PCWINDOWS)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ${DEMOS_KSDK_DIR}/x86pc
        PUBLIC ext/TraceRecorder/include
        PUBLIC ext/TraceRecorder/config
    )
ENDIF()

IF(SSS_HAVE_HOST_FRDMK64F)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC freertos/freertos-kernel/portable/GCC/ARM_CM4F)
ENDIF()

IF(SSS_HAVE_HOST_EVKMIMXRT1060 OR SSS_HAVE_HOST_EVKMIMXRT1170)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC freertos/freertos-kernel/portable/GCC/ARM_CM4F)
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S OR SSS_HAVE_HOST_FRDMMCXA153 OR SSS_HAVE_HOST_FRDMMCXN947)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME} PUBLIC freertos/freertos-kernel/portable/GCC/ARM_CM33_NTZ/non_secure
    )
ENDIF()

ADD_DEFINITIONS(-DSSS_USE_FTR_FILE)


IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE
            /wd4127 # conditional expression is constant
    )
ENDIF()


#IF(SSS_HAVE_HOST_LPCXPRESSO55S)
#  MESSAGE("No FreeRTOS IP")
#ELSE()

PROJECT(freertos-ip)

FILE(
    GLOB
    files
    freertos/corejson/source/*.c
    freertos/corepkcs11/source/core_pkcs11.c
    freertos/coremqtt/source/*.c
    freertos/backoffalgorithm/source/*.c
    freertos/corepkcs11/source/*.c
    aws_iot/iot-reference/examples/common/
    aws_iot/iot-reference/examples/common/logging/logging.c
    amazon-freertos.cmake
)

IF(SSS_HAVE_HOST_PCWINDOWS)
    FILE(
        GLOB
        port_files
        ${DEMOS_KSDK_DIR}/x86pc/*.h
        ${DEMOS_KSDK_DIR}/x86pc/aws_run-time-stats-utils.c
        ${DEMOS_KSDK_DIR}/x86pc/aws_entropy_hardware_poll.c
        ${DEMOS_KSDK_DIR}/x86pc/application_utils.c
        ${DEMOS_KSDK_DIR}/x86pc/win_pcap/*.h
    )
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS AND ENABLE_CLOUD_DEMOS AND SSS_HAVE_MBEDTLS_ALT)
    LIST(
        APPEND
        port_files
        ${DEMOS_KSDK_DIR}/x86pc/main.c
    )
ENDIF()

IF(SSS_HAVE_KSDK)

    IF(NOT (SSS_HAVE_HOST_LPCXPRESSO55S OR SSS_HAVE_HOST_FRDMMCXA153))
        FILE(
            GLOB
            port_files
            mcu-sdk/middleware/lwip/src/core/*.c
            mcu-sdk/middleware/lwip/src/core/ipv4/*.c
            mcu-sdk/middleware/lwip/src/api/*.c
            mcu-sdk/middleware/lwip/src/netif/ethernet.c
            mcu-sdk/middleware/lwip/port/ethernetif.c
            mcu-sdk/middleware/lwip/port/ethernetif_mmac.c
            mcu-sdk/middleware/lwip/port/enet_ethernetif.c
            mcu-sdk/middleware/lwip/port/sys_arch.c
            mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_enet.c
            aws_iot/iot-reference/Middleware/FreeRTOS/transport_mbedtls/*.c
        )
        IF(SSS_HAVE_HOST_FRDMMCXN947)
            LIST(
                APPEND
                port_files
                mcu-sdk/middleware/lwip/port/enet_ethernetif_lpc.c
            )
        ELSE()
            LIST(
                APPEND
                port_files
                mcu-sdk/middleware/lwip/port/enet_ethernetif_kinetis.c
            )     
        ENDIF()
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    FILE(
        GLOB
        port_files
        aws_iot/iot-reference/Middleware/FreeRTOS/transport_mbedtls_wifi_serial/*.c
    )
ENDIF()

IF(SSS_HAVE_MBEDTLS_ALT OR SSS_HAVE_HOST_FRDMMCXN947)
    FILE(
        GLOB
        alt_files
        ${SIMW_TOP_DIR}/sss/plugin/pkcs11/*.c
        ${SIMW_TOP_DIR}/sss/plugin/pkcs11/port/*.c
        ${DEMOS_KSDK_DIR}/common/common_cloud.c
    )
ENDIF()

ADD_LIBRARY(
    ${PROJECT_NAME}
    ${files}
    ${port_files}
    ${alt_files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC freertos/corepkcs11/source/include
    PUBLIC mcu-sdk/middleware/pkcs11
    PUBLIC freertos/corejson/source/include
    PUBLIC freertos/coremqtt/source/include
    PUBLIC freertos/coremqtt/source/interface
    PUBLIC freertos/backoffalgorithm/source/include
    PUBLIC aws_iot/iot-reference/Middleware/FreeRTOS/transport_mbedtls
    PUBLIC aws_iot/iot-reference/Middleware/FreeRTOS/transport_mbedtls_wifi_serial
)

IF(SSS_HAVE_HOST_PCWINDOWS)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ${DEMOS_KSDK_DIR}/x86pc
        PUBLIC ${DEMOS_KSDK_DIR}/common
    )
ENDIF()

IF(SSS_HAVE_MBEDTLS_ALT OR SSS_HAVE_HOST_FRDMMCXN947)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ../sss/ex/inc
        PUBLIC ${SIMW_TOP_DIR}/sss/plugin/pkcs11
        PUBLIC ${SIMW_TOP_DIR}/sss/plugin/pkcs11/port
    )
ENDIF()

IF(SSS_HAVE_KSDK)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ../demos/ksdk/common
        PUBLIC ../demos/ksdk/gcp
        PUBLIC mcu-sdk/middleware/lwip/port
        PUBLIC mcu-sdk/middleware/lwip/src
        PUBLIC mcu-sdk/middleware/lwip/src/include
    )
ENDIF()

TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${DEMOS_KSDK_DIR}/common)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    mbedtls
    freertos-kernel
    ex_common
)

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} wifi_serial_mwm)
ENDIF()

IF(SSS_HAVE_APPLET_A7XX OR SSS_HAVE_APPLET_SE050_EAR)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} a7x_utils)
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} wpcap)
ENDIF()

#ENDIF() #FreeRTOS IP

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-error=unused-variable
        PRIVATE -Wno-unused-variable
        PRIVATE -Wno-address-of-packed-member
        PRIVATE -Wno-unused-function
        PRIVATE -Wno-array-bounds
    )
    SIMW_DISABLE_EXTRA_WARNINGS(${PROJECT_NAME})

ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE
            /wd4310 # cast truncates constant value
            /wd4127 # conditional expression is constant
            /wd4189 # local variable is initialized but not referenced
            /wd4005 # macro redefinition
            /wd4456 # hides previous local declaration
            /wd4101 # unreferenced local variable
            /wd4267 # possible loss of data
            /wd4295 # array is too small to include a terminating null character
            /wd4057 # differs in indirection to slightly different base types
            /wd4200 # nonstandard extension used: zero-sized array in struct/union
            /wd4055 # type cast: from data pointer to function pointer
            /wd4701 # potentially uninitialized local variable
    )
ENDIF()
