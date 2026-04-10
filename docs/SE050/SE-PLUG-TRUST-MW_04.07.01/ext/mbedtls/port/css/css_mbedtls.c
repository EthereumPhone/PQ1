/*
 * Copyright 2019-2021 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "fsl_css.h"           // Power Down Wake-up Init
#include "platform_hw_ip.h"
#include "css_mbedtls.h"
#include "fsl_common.h"

#if !defined(MBEDTLS_MCUX_CSS_PKC_API)

static uint32_t g_isCryptoHWInitialized = CSS_PKC_CRYPTOHW_NONINITIALIZED;

__WEAK uint32_t __stack_chk_guard;

__WEAK void __stack_chk_fail(void)
{
    while (1) {
    }
    ;
}

int mbedtls_hw_init(void)
{
    status_t status;

    if (g_isCryptoHWInitialized == CSS_PKC_CRYPTOHW_NONINITIALIZED) {
        /* Enable CSS and related clocks */
        status = CSS_PowerDownWakeupInit(CSS);
        if (status != kStatus_Success) {
            return status;
        }

    } else {
        return kStatus_Success;
    }

    return status;
}


/******************************************************************************/
/******************** CRYPTO_InitHardware **************************************/
/******************************************************************************/
/*!
 * @brief Application init for various Crypto blocks.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic init for Crypto Hw acceleration and Hw entropy modules.
 */
status_t CRYPTO_InitHardware(void)
{
    status_t status;

    /* Enable CSS and related clocks */
    status = CSS_PowerDownWakeupInit(CSS);
    if (status != kStatus_Success) {
        return kStatus_Fail;
    }

    g_isCryptoHWInitialized = CSS_PKC_CRYPTOHW_INITIALIZED;

    return status;
}

#endif /* !defined(MBEDTLS_MCUX_CSS_PKC_API) */
