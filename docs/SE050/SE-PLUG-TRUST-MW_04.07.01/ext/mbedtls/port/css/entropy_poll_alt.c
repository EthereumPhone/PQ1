/*
 * Copyright 2019-2020 MCUX
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <mcuxClCss.h>               // Interface to the entire mcuxClCss component
#include <mcuxCsslFlowProtection.h>  // Code flow protection
#include <css_mbedtls.h>
#include <platform_hw_ip.h>

/* Entropy poll callback for a hardware source */
#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{

    /* Initialize CSS and it's PRNG if not already initialized */
    mbedtls_hw_init();

    /* Call CSS to get random data */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Prng_GetRandom(output, len));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Prng_GetRandom) != token) ||
        (MCUXCLCSS_STATUS_OK != result)) {
        return kStatus_Fail;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    *olen = len;

    return 0;

}
#endif /* MBEDTLS_ENTROPY_HARDWARE_ALT */
