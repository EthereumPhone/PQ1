# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

function(remove_boot_header)
    message(STATUS "Remove boot header and extract FCBs")
    set(TFM_S_BIN "${CMAKE_BINARY_DIR}/../tfm/bin/tfm_s.bin")
    set(HEADER_PADDING "0x00")

    message(STATUS "Header size: ${FCB_SIZE} bytes")

    # Extract FCBs
    execute_process(COMMAND nxpimage -vv utils binary-image extract
        -b ${TFM_S_BIN}
        -a ${HEADER_PADDING}
        -s ${FCB_SIZE}
        -o ${FCB_BIN}
        OUTPUT_VARIABLE NXPIMAGE_OUTPUT
        COMMAND_ERROR_IS_FATAL ANY)
    message(STATUS "${NXPIMAGE_OUTPUT}")

    # Extract s part without FCBs and header
    execute_process(COMMAND nxpimage -vv utils binary-image extract
        -b ${TFM_S_BIN}
        -a ${FCB_SIZE}
        -s 0x00
        -o ${TFM_S_HEADERLESS_BIN}
        OUTPUT_VARIABLE NXPIMAGE_OUTPUT
        COMMAND_ERROR_IS_FATAL ANY)
    message(STATUS "${NXPIMAGE_OUTPUT}")
endfunction()

remove_boot_header()
