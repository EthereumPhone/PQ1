/*
 * Copyright 2022 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ELS_MBEDTLS_H
#define ELS_MBEDTLS_H

#ifdef __cplusplus
extern "C" {
#endif

#define ELS_PKC_CRYPTOHW_INITIALIZED    (0xF0F0F0F0U)
#define ELS_PKC_CRYPTOHW_NONINITIALIZED (0x0F0F0F0FU)

int fsl_mbedtls_printf(const char *fmt_s, ...);
status_t CRYPTO_InitHardware(void);

#ifdef __cplusplus
}
#endif

#endif /* ELS_MBEDTLS_H */
