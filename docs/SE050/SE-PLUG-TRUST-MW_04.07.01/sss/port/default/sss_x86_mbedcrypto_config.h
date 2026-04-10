/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
/* Copyright 2021 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* clang-format off */

#ifndef __MBEDTLS_USER_CONFIG_H__
#define __MBEDTLS_USER_CONFIG_H__

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if defined(MBEDTLS_AES_ALT)
    #undef MBEDTLS_AES_ALT
#endif // MBEDTLS_AES_ALT
#if defined(MBEDTLS_AES_SETKEY_ENC_ALT)
    #undef MBEDTLS_AES_SETKEY_ENC_ALT
#endif // MBEDTLS_AES_SETKEY_ENC_ALT
#if defined(MBEDTLS_AES_SETKEY_DEC_ALT)
    #undef MBEDTLS_AES_SETKEY_DEC_ALT
#endif // MBEDTLS_AES_SETKEY_DEC_ALT
#if defined(MBEDTLS_AES_ENCRYPT_ALT)
    #undef MBEDTLS_AES_ENCRYPT_ALT
#endif // MBEDTLS_AES_ENCRYPT_ALT
#if defined(MBEDTLS_AES_DECRYPT_ALT)
    #undef MBEDTLS_AES_DECRYPT_ALT
#endif // MBEDTLS_AES_DECRYPT_ALT

/*
 * When replacing the elliptic curve module, pleace consider, that it is
 * implemented with two .c files:
 *      - ecp.c
 *      - ecp_curves.c
 * You can replace them very much like all the other MBEDTLS__MODULE_NAME__ALT
 * macros as described above. The only difference is that you have to make sure
 * that you provide functionality for both .c files.
 */
#if defined(MBEDTLS_ECP_ALT)
    #undef MBEDTLS_ECP_ALT
#endif // MBEDTLS_ECP_ALT
#if defined(MBEDTLS_ECDH_ALT)
    #undef MBEDTLS_ECDH_ALT
#endif // MBEDTLS_ECDH_ALT
#if defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT)
    #undef MBEDTLS_ECDH_GEN_PUBLIC_ALT
#endif // MBEDTLS_ECDH_GEN_PUBLIC_ALT
#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
    #undef MBEDTLS_ECDH_COMPUTE_SHARED_ALT
#endif // MBEDTLS_ECDH_COMPUTE_SHARED_ALT

#if (SSS_HAVE_RSA)
#if defined(MBEDTLS_RSA_ALT)
    #undef MBEDTLS_RSA_ALT
#endif // MBEDTLS_RSA_ALT
#endif // SSS_HAVE_RSA
/**
 * - MBEDTLS_ECDSA_VERIFY_ALT
 * To use SE for all public key ecdsa verify operation, enable MBEDTLS_ECDSA_VERIFY_ALT
 */
// #ifndef MBEDTLS_ECDSA_VERIFY_ALT
//     #define MBEDTLS_ECDSA_VERIFY_ALT
// #endif // MBEDTLS_ECDSA_VERIFY_ALT

#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    #undef MBEDTLS_ECP_DP_CURVE25519_ENABLED
#endif //MBEDTLS_ECP_DP_CURVE25519_ENABLED

#if defined(MBEDTLS_SELF_TEST)
    #undef MBEDTLS_SELF_TEST
#endif // MBEDTLS_SELF_TEST

#ifndef MBEDTLS_CMAC_C
    #define MBEDTLS_CMAC_C
#endif // MBEDTLS_CMAC_C

#ifndef MBEDTLS_FS_IO
    #define MBEDTLS_FS_IO
#endif // MBEDTLS_FS_IO
#ifndef MBEDTLS_PSA_CRYPTO_C
    #define MBEDTLS_PSA_CRYPTO_C
#endif // MBEDTLS_PSA_CRYPTO_C
#ifndef MBEDTLS_PSA_CRYPTO_STORAGE_C
    #define MBEDTLS_PSA_CRYPTO_STORAGE_C
#endif // MBEDTLS_PSA_CRYPTO_STORAGE_C
#ifndef MBEDTLS_PSA_ITS_FILE_C
    #define MBEDTLS_PSA_ITS_FILE_C
#endif // MBEDTLS_PSA_ITS_FILE_C
#ifndef MBEDTLS_PSA_CRYPTO_SE_C
    #define MBEDTLS_PSA_CRYPTO_SE_C
#endif // MBEDTLS_PSA_CRYPTO_SE_C
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    #undef MBEDTLS_ECDSA_DETERMINISTIC
#endif // MBEDTLS_ECDSA_DETERMINISTIC
#ifndef MBEDTLS_PSA_CRYPTO_DRIVERS
    #define MBEDTLS_PSA_CRYPTO_DRIVERS
#endif // MBEDTLS_PSA_CRYPTO_DRIVERS

#include <fsl_sss_types.h>

#ifndef MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_MEMORY
#endif

#if defined(MBEDTLS_PLATFORM_STD_CALLOC)
#undef MBEDTLS_PLATFORM_STD_CALLOC
#endif // MBEDTLS_PLATFORM_STD_CALLOC

#if defined(MBEDTLS_PLATFORM_STD_FREE)
#undef MBEDTLS_PLATFORM_STD_FREE
#endif // MBEDTLS_PLATFORM_STD_FREE

#if defined(MBEDTLS_PLATFORM_CALLOC_MACRO)
#undef MBEDTLS_PLATFORM_CALLOC_MACRO
#endif // MBEDTLS_PLATFORM_CALLOC_MACRO

#if defined(MBEDTLS_PLATFORM_FREE_MACRO)
#undef MBEDTLS_PLATFORM_FREE_MACRO
#endif // MBEDTLS_PLATFORM_FREE_MACRO

#define MBEDTLS_PLATFORM_CALLOC_MACRO SSS_CALLOC
#define MBEDTLS_PLATFORM_FREE_MACRO SSS_FREE
/* clang-format on */

#endif // __MBEDTLS_USER_CONFIG_H__
