# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

# This file includes extra build system logic that is enabled when
# CONFIG_EL2GO_SIGN_USING_NXPIMAGE=y.
#
# It builds signed binaries using nxpimage as a post-processing step
# after zephyr/zephyr.bin(SPE) and tfm_s.bin(NSPE) are created in the build directory.
#
# Important Note: Make sure SPSDK is in the PATH.
#
# Since this file is brought in via include(), we do the work in a
# function to avoid polluting the top-level scope.

function(sign_s_ns)
    message(STATUS "Signing using \'nxpimage\'")

    find_program(SPSDK "spsdk" NO_CMAKE_PATH NO_CMAKE_ENVIRONMENT_PATH)

    if(SPSDK)
        message(STATUS "SPSDK found with: ${SPSDK}")
    else()
        message(FATAL_ERROR
            "SPSDK not found in PATH! Please either add SPSDK to PATH or
                disable \'CONFIG_EL2GO_SIGN_USING_NXPIMAGE\' in prj.conf")
    endif()

    set(PRIVATE_KEY "")
    set(CERT_BLOCK "")

    # Take private key from prj.conf first, else from env. variable
    if(NOT CONFIG_EL2GO_PRIVATE_KEY)
        if(NOT DEFINED ENV{CONFIG_EL2GO_PRIVATE_KEY})
            message(FATAL_ERROR "EL2GO Private Key neither set in CONFIG_EL2GO_PRIVATE_KEY prj.conf file nor in CONFIG_EL2GO_PRIVATE_KEY environment variable")
        else()
            set(PRIVATE_KEY $ENV{CONFIG_EL2GO_PRIVATE_KEY})
        endif()
    else()
        set(PRIVATE_KEY ${CONFIG_EL2GO_PRIVATE_KEY})
    endif()

    if(NOT CONFIG_EL2GO_CERT_BLOCK)
        if(NOT DEFINED ENV{CONFIG_EL2GO_CERT_BLOCK})
            message(FATAL_ERROR "EL2GO Certificate Block
            neither set in CONFIG_EL2GO_CERT_BLOCK prj.conf file
            nor in CONFIG_EL2GO_CERT_BLOCK environment variable")
        else()
            set(CERT_BLOCK $ENV{CONFIG_EL2GO_CERT_BLOCK})
        endif()
    else()
        set(CERT_BLOCK ${CONFIG_EL2GO_CERT_BLOCK})
    endif()

    # Addresses and values
    set(FCB_SIZE "0xC00")
    set(PADDING_SIZE "0x400")

    # Paths
    set(FCB_BIN "${CMAKE_BINARY_DIR}/tfm/bin/fcb.bin")
    set(TFM_S_HEADERLESS_BIN "${CMAKE_BINARY_DIR}/tfm/bin/tfm_s_headerless.bin")

    set_property(GLOBAL APPEND PROPERTY extra_post_build_commands
        COMMAND ${CMAKE_COMMAND}
        -DFCB_SIZE:INTERNAL=${FCB_SIZE}
        -DPADDING_SIZE:INTERNAL=${PADDING_SIZE}
        -DFCB_BIN:INTERNAL=${FCB_BIN}
        -DTFM_S_HEADERLESS_BIN:INTERNAL=${TFM_S_HEADERLESS_BIN}
        -P ${CMAKE_CURRENT_LIST_DIR}/extract_boot_header.cmake)

    set_property(GLOBAL APPEND PROPERTY extra_post_build_commands
        COMMAND ${CMAKE_COMMAND}
        -DFCB_SIZE:INTERNAL=${FCB_SIZE}
        -DPADDING_SIZE:INTERNAL=${PADDING_SIZE}
        -DFCB_BIN:INTERNAL=${FCB_BIN}
        -DTFM_S_HEADERLESS_BIN:INTERNAL=${TFM_S_HEADERLESS_BIN}
        -DCONFIG_EL2GO_PRIVATE_KEY:INTERNAL=${PRIVATE_KEY}
        -DCONFIG_EL2GO_CERT_BLOCK:INTERNAL=${CERT_BLOCK}
        -P ${CMAKE_CURRENT_LIST_DIR}/merge_and_sign.cmake)

    set_property(GLOBAL APPEND PROPERTY extra_post_build_commands
        COMMAND ${CMAKE_OBJCOPY}
        -I binary
        -O ihex
        --change-addresses=0x8000000
        ${CMAKE_BINARY_DIR}/zephyr/zephyr.bin
        ${CMAKE_BINARY_DIR}/zephyr/zephyr.hex)

    set_property(TARGET runners_yaml_props_target PROPERTY hex_file ${CMAKE_BINARY_DIR}/zephyr/zephyr.hex)
endfunction()

sign_s_ns()
