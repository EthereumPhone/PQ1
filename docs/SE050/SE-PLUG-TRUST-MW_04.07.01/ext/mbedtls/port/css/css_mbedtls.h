/*
 * Copyright 2021 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CSS_MBEDTLS_H
#define CSS_MBEDTLS_H


#ifdef __cplusplus
extern "C" {
#endif

#define CSS_PKC_CRYPTOHW_INITIALIZED       (0xF0F0F0F0)
#define CSS_PKC_CRYPTOHW_NONINITIALIZED    (0x0F0F0F0F)

int fsl_mbedtls_printf(const char *fmt_s, ...);
status_t CRYPTO_InitHardware(void);

#ifdef __cplusplus
}
#endif

#endif /* CSS_MBEDTLS_H */
