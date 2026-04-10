#
# Copyright 2018,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
IF(NOT SSS_HAVE_KSDK)
    MESSAGE(FATAL_ERROR "Not to be included without KSDK")
ENDIF()

SET(CMAKE_EXECUTABLE_SUFFIX ".axf")

IF(NXPInternal)
    SET(
        WARNINGS_FLAGS
        "\
        -Wextra \
        -Werror=implicit-function-declaration \
        -Werror=incompatible-pointer-types \
        -Werror=unused-function"
    )
    ADD_COMPILE_OPTIONS(
        -Wextra
        -Wno-format
        -Wno-unused-parameter
        -Wno-unknown-pragmas
        -Wno-missing-field-initializers
        -Wno-missing-braces
        -Wno-error=clobbered
        -Wno-error=implicit-fallthrough
    )

    SET(WARNINGS_FLAGS "${WARNINGS_FLAGS} -Werror")
ENDIF()

MACRO(SIMW_DISABLE_EXTRA_WARNINGS PROJECT_NAME)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-error=missing-field-initializers
        PRIVATE -Wno-missing-field-initializers
        PRIVATE -Wno-error=sign-compare
        PRIVATE -Wno-sign-compare
        PRIVATE -Wno-error=unused-parameter
        PRIVATE -Wno-unused-parameter
        PRIVATE -Wno-error=implicit-fallthrough
        PRIVATE -Wno-implicit-fallthrough
        PRIVATE -Wno-error=missing-field-initializers
        PRIVATE -Wno-missing-field-initializers
        PRIVATE -Wno-error=type-limits
    )
ENDMACRO()

# IF(SSS_HAVE_HOST_FRDMK64F) LINK_DIRECTORIES(${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/mmcau/asm-cm4-cm7) ENDIF()

MACRO(CREATE_BINARY PROJECT_NAME)
    SET(_FLAGS_L_MAP " -Xlinker -Map=${CMAKE_BINARY_DIR}/bin/${PROJECT_NAME}.map ")

    IF(SSS_HAVE_HOST_LPCXPRESSO55S_S)
        SET(
            _FLAGS_L_IMPLIB
            " \
        -Xlinker \
        --out-implib=${SIMW_TOP_DIR}/binaries/${PROJECT_NAME}_CMSE_lib.o \
    "
        )
    ENDIF()

    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${_FLAGS_L_IMPLIB} ${_FLAGS_L_MAP} ")

    ADD_CUSTOM_COMMAND(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary ${PROJECT_NAME}${CMAKE_EXECUTABLE_SUFFIX} ${PROJECT_NAME}.bin
        WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
        COMMENT "${PROJECT_NAME}${CMAKE_EXECUTABLE_SUFFIX} -> ${PROJECT_NAME}.bin"
    )
ENDMACRO()

MACRO(
    COPY_TO_SOURCEDIR
    PROJECT_NAME
    TARGET_DIRNAME
    TARGET_SUFFIX
)
    IF(NXPInternal)
        IF(
            CMAKE_BUILD_TYPE
            STREQUAL
            "Release"
        )
            ADD_CUSTOM_COMMAND(
                TARGET ${PROJECT_NAME}
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}.bin
                        ${SIMW_TOP_DIR}/${TARGET_DIRNAME}/${PROJECT_NAME}-${TARGET_SUFFIX}-${KSDK_BoardName}.bin
                COMMENT
                    "Copy ${PROJECT_NAME}.bin to ${TARGET_DIRNAME}/${PROJECT_NAME}-${TARGET_SUFFIX}-${KSDK_BoardName}.bin"
            )
        ENDIF()
    ELSE()
        ADD_CUSTOM_COMMAND(
            TARGET ${PROJECT_NAME}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}.bin
                    ${SIMW_TOP_DIR}/${TARGET_DIRNAME}/${PROJECT_NAME}-${eSMCOM}-${KSDK_BoardName}.bin
            COMMENT "Copy ${PROJECT_NAME}.bin to ${TARGET_DIRNAME}/${PROJECT_NAME}-${eSMCOM}-${KSDK_BoardName}.bin"
        )
    ENDIF()

ENDMACRO()

MACRO(
    COPY_TO_SOURCEDIR_RENAME
    PROJECT_NAME
    PROJECT_RENAMED
    TARGET_DIRNAME
    TARGET_SUFFIX
)
    IF(NXPInternal)
        IF(
            CMAKE_BUILD_TYPE
            STREQUAL
            "Release"
        )
            ADD_CUSTOM_COMMAND(
                TARGET ${PROJECT_NAME}
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}.bin
                        ${SIMW_TOP_DIR}/${TARGET_DIRNAME}/${PROJECT_RENAMED}-${TARGET_SUFFIX}-${KSDK_BoardName}.bin
                COMMENT
                    "Copy ${PROJECT_NAME}.bin to ${TARGET_DIRNAME}/${PROJECT_RENAMED}-${TARGET_SUFFIX}-${KSDK_BoardName}.bin"
            )
        ENDIF()
    ELSE()
        ADD_CUSTOM_COMMAND(
            TARGET ${PROJECT_NAME}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}.bin
                    ${SIMW_TOP_DIR}/${TARGET_DIRNAME}/${PROJECT_RENAMED}-${eSMCOM}-${KSDK_BoardName}.bin
            COMMENT "Copy ${PROJECT_NAME}.bin to ${TARGET_DIRNAME}/${PROJECT_RENAMED}-${eSMCOM}-${KSDK_BoardName}.bin"
        )
    ENDIF()

ENDMACRO()

ENABLE_LANGUAGE(ASM)

INCLUDE_DIRECTORIES(
    ${SIMW_TOP_DIR}/demos/ksdk/common/freertos/boards/${KSDK_BoardName}
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/project_template
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}/se_hostlib_examples/cloud_demo
    ${SIMW_TOP_DIR}/demos/ksdk/common/boards/${KSDK_BoardName}
    ${SIMW_TOP_DIR}/ext/mcu-sdk/CMSIS/Include
    ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/mmcau
    ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/debug_console
    ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/shell
    ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities/str
    ${SIMW_TOP_DIR}/ext/mcu-sdk/platform/utilities
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/drivers
    ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/utilities
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/serial_manager
    ${SIMW_TOP_DIR}/ext/mcu-sdk/components/uart
)

IF(SSS_HAVE_HOST_FRDMMCXN947 OR SSS_HAVE_HOST_FRDMMCXA153)
    INCLUDE_DIRECTORIES(
        ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/periph
    )
ENDIF()

LINK_DIRECTORIES(${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/mmcau/asm-cm4-cm7)

ADD_DEFINITIONS(
    -D__NEWLIB__
    -D__USE_CMSIS
    -DPRINTF_ADVANCED_ENABLE=1
    -DSCANF_ADVANCED_ENABLE=0
    -DSCANF_FLOAT_ENABLE=0
    -DSDK_DEBUGCONSOLE=1
    -DSDK_DEBUGCONSOLE_UART=1
    -DDEBUG_CONSOLE_RX_ENABLE=0
    -DSERIAL_PORT_TYPE_UART=1
)

SET(
    _FLAGS_COMMON
    " \
    -Wall \
    -fno-common \
    -ffunction-sections \
    -fdata-sections \
    -ffreestanding \
    -fno-builtin \
    -mthumb \
    -mapcs"
)

SET(_FLAGS_COMMON "${_FLAGS_COMMON} ${WARNINGS_FLAGS}")

SET(
    _FLAGS_C_COMMON
    " ${_FLAGS_COMMON} \
    -D_POSIX_SOURCE \
    -MMD -MP \
    -std=gnu99 \
    -fomit-frame-pointer "
)
SET(
    _FLAGS_CXX_COMMON
    " ${_FLAGS_COMMON} \
    -MMD -MP \
    -fno-rtti -fno-exceptions "
)
SET(_FLAGS_DEBUG_COMMON " -g -DDEBUG -O0 ")
SET(_FLAGS_RELEASE_COMMON " -DNDEBUG -Os ")
SET(
    _FLAGS_L_COMMON
    " \
    -Xlinker --gc-sections \
    -Xlinker -static \
    -Xlinker --sort-section=alignment \
    -Xlinker --print-memory-usage"
)
# -Xlinker -z \ -Xlinker muldefs ")

IF(SSS_HAVE_HOST_FRDMK64F)
    INCLUDE(scripts/ksdk_frdmk64f.cmake)
ELSEIF(SSS_HAVE_HOST_EVKMIMXRT1060)
    INCLUDE(scripts/ksdk_evkmimxrt1060.cmake)
ELSEIF(SSS_HAVE_HOST_EVKMIMXRT1170)
    INCLUDE(scripts/ksdk_evkmimxrt1170.cmake)
ELSEIF(SSS_HAVE_HOST_FRDMMCXN947)
    INCLUDE(scripts/ksdk_frdmmcxn947.cmake)
ELSEIF(SSS_HAVE_HOST_FRDMMCXA153)
    INCLUDE(scripts/ksdk_frdmmcxa153.cmake)
ELSEIF(
    SSS_HAVE_HOST_LPCXPRESSO55S
    OR SSS_HAVE_HOST_LPCXPRESSO55S_NS
    OR SSS_HAVE_HOST_LPCXPRESSO55S_S
)
    SET(_FLAGS_DEBUG_COMMON " -O1 ")
    INCLUDE(scripts/ksdk_lpcxpresso55s.cmake)
ELSEIF(SSS_HAVE_HOST_LPCXPRESSO55S_S)
    INCLUDE(scripts/ksdk_lpcxpresso55s.cmake)
ENDIF()

SET(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} \
    -D__STARTUP_CLEAR_BSS ${_FLAGS_COMMON} ${_FLAGS_CPU} "
)
SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} \
    ${CMAKE_ASM_FLAGS} -DDEBUG -g"
)
SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE} \
    ${CMAKE_ASM_FLAGS} -DNDEBUG "
)
SET(CMAKE_ASM_FLAGS_RELWITHDEBINFO "${CMAKE_ASM_FLAGS_RELWITHDEBINFO} \
    ${CMAKE_ASM_FLAGS} -DNDEBUG "
)

SET(CMAKE_C_FLAGS " ${CMAKE_C_FLAGS} ${_FLAGS_C_COMMON} ${_FLAGS_CPU} ")
SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} \
    ${_FLAGS_DEBUG_COMMON} "
)
SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} \
    ${_FLAGS_RELEASE_COMMON} "
)
SET(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} \
    ${_FLAGS_RELEASE_COMMON} "
)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    ${_FLAGS_CXX_COMMON} ${_FLAGS_CPU} "
)
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} \
    ${_FLAGS_DEBUG_COMMON}"
)
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} \
    ${_FLAGS_RELEASE_COMMON}"
)
SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} \
    ${_FLAGS_RELEASE_COMMON}"
)
SET(
    _FLAGS_L_ALL
    "${_FLAGS_L_ALL} \
    ${_FLAGS_L_COMMON} \
    ${_FLAGS_L_SPECS} \
    ${_FLAGS_L_MEM} \
    ${_FLAGS_L_LD} \
    "
)
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} \
    -g ${_FLAGS_L_ALL}"
)
SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} \
    ${_FLAGS_L_ALL}"
)
SET(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} \
    ${_FLAGS_L_ALL}"
)
