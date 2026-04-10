/*--------------------------------------------------------------------------*/
/* Copyright 2021 NXP                                                       */
/*                                                                          */
/* NXP Confidential. This software is owned or controlled by NXP and may    */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms. If you do not agree to be bound by the applicable license */
/* terms, then you may not retain, install, activate or otherwise use the   */
/* software.                                                                */
/*--------------------------------------------------------------------------*/

/** @file  cbc_mac.c
 *  @brief alternative implementation of AES CBC-MAC with CSS IP
 */

#include <cbc_mac_alt.h>
#include <mbedtls/ccm.h>
#include <mbedtls/platform.h>
#include <platform_hw_ip.h>
#include <mcuxClCss.h>
#include <string.h>

#if !defined(MBEDTLS_CCM_USE_AES_CBC_MAC) || !defined(MBEDTLS_AES_CTX_ALT)
#error the alternative implementations shall be enabled together
#endif

int mbedtls_aes_cbc_mac(mbedtls_aes_context *ctx,
                        size_t length,
                        unsigned char *iv,
                        const unsigned char *pInput)
{

    mcuxClCss_CmacOption_t cmac_options = { 0 };
    cmac_options.bits.extkey = MCUXCLCSS_CMAC_EXTERNAL_KEY_ENABLE;

    /* Set options to UPDATE (i.e., neither initialize nor finalize) for cbc-mac operation */
    cmac_options.bits.initialize = MCUXCLCSS_CMAC_INITIALIZE_DISABLE;
    cmac_options.bits.finalize = MCUXCLCSS_CMAC_FINALIZE_DISABLE;

    uint8_t *pKey = (uint8_t *) ctx->pKey;
    size_t key_length = ctx->keyLength;
    size_t nr_full_blocks = length / 16u;
    size_t len_last_block = length - (nr_full_blocks * 16u);

    /* Initialize CSS */
    int ret_hw_init = mbedtls_hw_init();
    if (0 != ret_hw_init) {
        return MBEDTLS_ERR_CCM_HW_ACCEL_FAILED;
    }

    /* process all complete blocks */
    if (nr_full_blocks > 0u) {
        /* call mcuxClCss_Cmac_Async on full blocks */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(resultFullBlocks, tokenFullBlocks,
                                             mcuxClCss_Cmac_Async(cmac_options,
                                                                  0, /* keyIdx is ignored */
                                                                  pKey,
                                                                  key_length,
                                                                  (uint8_t const *) pInput,
                                                                  (nr_full_blocks * 16u),
                                                                  (uint8_t *) iv));

        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async) != tokenFullBlocks) ||
            (MCUXCLCSS_STATUS_OK_WAIT != resultFullBlocks)) {
            return MBEDTLS_ERR_CCM_HW_ACCEL_FAILED;
        }

        /* wait for mcuxClCss_Cmac_Async. */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssWaitFullBlocks, tokenCssWaitFullBlocks,
                                             mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != tokenCssWaitFullBlocks) ||
            (MCUXCLCSS_STATUS_OK != retCssWaitFullBlocks)) {
            return MBEDTLS_ERR_CCM_HW_ACCEL_FAILED;
        }

        pInput += (nr_full_blocks * 16u);
    }

    /* process last block */
    if (len_last_block > 0u) {
        // pad with zeros
        uint8_t last_block[16];
        (void) memset(last_block, 0, 16);
        (void) memcpy(last_block, pInput, len_last_block);

        /* call mcuxClCss_Cmac_Async on padded last block */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(resultLastBlock, tokenLastBlock,
                                             mcuxClCss_Cmac_Async(cmac_options,
                                                                  0, /* keyIdx is ignored */
                                                                  pKey,
                                                                  key_length,
                                                                  last_block,
                                                                  16u,
                                                                  (uint8_t *) iv));

        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async) != tokenLastBlock) ||
            (MCUXCLCSS_STATUS_OK_WAIT != resultLastBlock)) {
            return MBEDTLS_ERR_CCM_HW_ACCEL_FAILED;
        }

        /* wait for mcuxClCss_Cmac_Async. */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssWaitLastBlock, tokenCssWaitLastBlock,
                                             mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != tokenCssWaitLastBlock) ||
            (MCUXCLCSS_STATUS_OK != retCssWaitLastBlock)) {
            return MBEDTLS_ERR_CCM_HW_ACCEL_FAILED;
        }
    }

    return 0;
}
