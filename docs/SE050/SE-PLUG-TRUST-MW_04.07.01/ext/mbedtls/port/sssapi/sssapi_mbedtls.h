#if 0
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
/*
 * Copyright 2019-2021 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSSAPI_MBEDTLS_H
#define SSSAPI_MBEDTLS_H

#if defined(MBEDTLS_NXP_ELEMU200)
#define SSS_SUBSYSTEM (kType_SSS_Elemu200)
#elif defined(MBEDTLS_NXP_ELEMU300)
#define SSS_SUBSYSTEM (kType_SSS_Elemu300)
#else
#define SSS_SUBSYSTEM (kType_SSS_Software)
#endif

#define SSS_MAX_SUBSYTEM_WAIT          (0xFFFFFFFFu)
#define SSS_PUBLIC_KEY_PART_EXPORTABLE (0xF0u)
#define SSS_FULL_KEY_EXPORTABLE        (0xFFu)
#define SSS_CRYPTOHW_INITIALIZED       (0xF0F0F0F0u)
#define SSS_CRYPTOHW_NONINITIALIZED    (0x0F0F0F0Fu)

#ifdef __cplusplus
extern "C" {
#endif

#include "fsl_sss_mgmt.h"
#include "fsl_sss_sscp.h"
#include "fsl_sscp_mu.h"

extern sss_sscp_key_store_t g_keyStore;
extern sss_sscp_session_t g_sssSession;
extern sscp_context_t g_sscpContext;

status_t CRYPTO_InitHardware(void);
status_t CRYPTO_ReinitHardware(void);

#ifdef __cplusplus
}
#endif

#endif /* SSSAPI_MBEDTLS_H */
#else
/*
 * Copyright 2019-2021 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSSAPI_MBEDTLS_H
#define SSSAPI_MBEDTLS_H

#if defined(MBEDTLS_NXP_ELEMU200)
#define SSS_SUBSYSTEM (kType_SSS_Elemu200)
#elif defined(MBEDTLS_NXP_ELEMU300)
#define SSS_SUBSYSTEM (kType_SSS_Elemu300)
#else
#define SSS_SUBSYSTEM (kType_SSS_Software)
#endif

#define SSS_MAX_SUBSYTEM_WAIT       (0xFFFFFFFFu)
#define SSS_CRYPTOHW_INITIALIZED    (0xF0F0F0F0)
#define SSS_CRYPTOHW_NONINITIALIZED (0x0F0F0F0F)

#define SSS_KEYPROP_OPERATION_NONE (0x00000000u)
#define SSS_KEYPROP_OPERATION_AES  (0x00000001u)
#define SSS_KEYPROP_OPERATION_MAC  (0x00000002u)
#define SSS_KEYPROP_OPERATION_AEAD (0x00000004u)
#define SSS_KEYPROP_OPERATION_ASYM (0x00000008u)
#define SSS_KEYPROP_OPERATION_KDF  (0x00000010u)
#define SSS_KEYPROP_NO_PLAIN_READ  (0x00008000u)

#ifdef __cplusplus
extern "C" {
#endif

#include "fsl_sss_mgmt.h"
#include "fsl_sss_sscp.h"
#include "fsl_sscp_mu.h"

extern sss_sscp_key_store_t g_keyStore;
extern sss_sscp_session_t g_sssSession;
extern sscp_context_t g_sscpContext;

status_t CRYPTO_InitHardware(void);
status_t CRYPTO_ReinitHardware(void);




#ifdef __cplusplus
}
#endif

#endif /* SSSAPI_MBEDTLS_H */
#endif /* KW45_A0_SUPPORT */
#endif
