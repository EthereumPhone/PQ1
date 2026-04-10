# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

function(merge_and_sign)
    message(STATUS "Merge TF-M SPE and NSPE image")
    set(FLASH_S_SIZE "0x9F000")
    set(FLASH_START_ADDRESS "0x8000000")
    set(TFM_MERGED_HEADERLESS_BIN
        "${CMAKE_BINARY_DIR}/../tfm/bin/tfm_merged_headerless.bin")
    set(SIGNED_OUTPUT_BIN "${CMAKE_BINARY_DIR}/zephyr.bin")
    set(TFM_NS_BIN "${CMAKE_BINARY_DIR}/zephyr.bin")
    set(TFM_MERGED_HEADERLESS_SIGNED_BIN
        "${CMAKE_BINARY_DIR}/../tfm/bin/tfm_merged_headerless_signed.bin")
    set(TFM_MERGE_YML "${CMAKE_BINARY_DIR}/../tfm/tfm_merge.yml")
    set(TFM_SIGN_YML "${CMAKE_BINARY_DIR}/../tfm/tfm_sign.yml")
    set(SB_MERGE_YML "${CMAKE_BINARY_DIR}/../tfm/sb_merge.yml")

    # Merge s and ns image
    file(WRITE ${TFM_MERGE_YML}
        "
        name: TF-M Merged
        pattern: zeros
        regions:
          - binary_file:
              name: TF-M (S Part)
              path: ${TFM_S_HEADERLESS_BIN}
          - binary_file:
              name: TF-M (NS Part)
              path: ${TFM_NS_BIN}
              offset: ${FLASH_S_SIZE}")
    execute_process(COMMAND nxpimage -vv utils binary-image merge
        -c ${TFM_MERGE_YML}
        -o ${TFM_MERGED_HEADERLESS_BIN}
        OUTPUT_VARIABLE NXPIMAGE_OUTPUT
        COMMAND_ERROR_IS_FATAL ANY)
    message(STATUS "${NXPIMAGE_OUTPUT}")

    # Sign merged image
    math(EXPR OUTPUT_IMAGE_EXECUTION_ADDRESS
        "${FLASH_START_ADDRESS} + ${PADDING_SIZE} + ${FCB_SIZE}")
    file(WRITE ${TFM_SIGN_YML}
        "
        family: rw61x
        outputImageExecutionTarget: xip
        outputImageAuthenticationType: signed
        masterBootOutputFile: ${TFM_MERGED_HEADERLESS_SIGNED_BIN}
        inputImageFile: ${TFM_MERGED_HEADERLESS_BIN}
        outputImageExecutionAddress: ${OUTPUT_IMAGE_EXECUTION_ADDRESS}
        certBlock: ${CONFIG_EL2GO_CERT_BLOCK}
        signPrivateKey: ${CONFIG_EL2GO_PRIVATE_KEY}
        enableTrustZone: true")

    execute_process(COMMAND nxpimage -vv mbi export
        -c ${TFM_SIGN_YML}
        OUTPUT_VARIABLE NXPIMAGE_OUTPUT
        COMMAND_ERROR_IS_FATAL ANY)
    message(STATUS "${NXPIMAGE_OUTPUT}")

    # Append FCBs and header again
    math(EXPR OFFSET "${PADDING_SIZE} + ${FCB_SIZE}")
    file(WRITE ${SB_MERGE_YML}
        "
        name: TF-M Secureboot
        pattern: zeros
        regions:
          - binary_block:
              name: Padding
              size: ${PADDING_SIZE}
              pattern: zeros
          - binary_file:
              name: FCB
              path: ${FCB_BIN}
              offset: ${PADDING_SIZE}
          - binary_file:
              name: TF-M Signed (S & NS Part)
              path: ${TFM_MERGED_HEADERLESS_SIGNED_BIN}
              offset: ${OFFSET}")

    execute_process(COMMAND nxpimage -vv utils binary-image merge
        -c ${SB_MERGE_YML}
        -o ${SIGNED_OUTPUT_BIN}
        OUTPUT_VARIABLE NXPIMAGE_OUTPUT
        COMMAND_ERROR_IS_FATAL ANY)
    message(STATUS "${NXPIMAGE_OUTPUT}")
endfunction()

merge_and_sign()
