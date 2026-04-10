/*
 * Copyright 2022 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ELS_PKC_MBEDTLS_H
#define ELS_PKC_MBEDTLS_H

#ifdef __cplusplus
extern "C" {
#endif


#if defined(MBEDTLS_THREADING_C)
/* Threading mutex implementations for mbedTLS. */
#include "mbedtls/threading.h"
#include "threading_alt.h"
#endif


#define ELS_PKC_CRYPTOHW_INITIALIZED    (0xF0F0F0F0U)
#define ELS_PKC_CRYPTOHW_NONINITIALIZED (0x0F0F0F0FU)

int fsl_mbedtls_printf(const char *fmt_s, ...);
status_t CRYPTO_InitHardware(void);

#if defined(MBEDTLS_THREADING_C)
/* MUTEX FOR HW Modules*/
extern mbedtls_threading_mutex_t mbedtls_threading_hwcrypto_els_mutex;
extern mbedtls_threading_mutex_t mbedtls_threading_hwcrypto_pkc_mutex;
#endif /* defined(MBEDTLS_THREADING_C) */

#ifdef __cplusplus
}
#endif

#endif /* ELS_PKC_MBEDTLS_H */
