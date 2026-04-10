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
/* Copyright 2021-2024 NXP
 */

/* clang-format off */

#ifndef __MBEDTLS_USER_CONFIG_H__
#define __MBEDTLS_USER_CONFIG_H__

// Reduce RAM usage.
// More info: https://tls.mbed.org/kb/how-to/reduce-mbedtls-memory-and-storage-footprint
#define MBEDTLS_ECP_FIXED_POINT_OPTIM 0 /* To reduce peak memory usage */
#define MBEDTLS_SSL_MAX_CONTENT_LEN (1024 * 16) /* Reduce SSL frame buffer. */
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_MPI_WINDOW_SIZE 1
#define MBEDTLS_ECP_WINDOW_SIZE 2
#define MBEDTLS_MPI_MAX_SIZE 512 /* Maximum number of bytes for usable MPIs. */
#define MBEDTLS_ECP_MAX_BITS 521 /* Maximum bit size of groups */

#ifndef MBEDTLS_USE_PSA_CRYPTO
    #define MBEDTLS_USE_PSA_CRYPTO
#endif // MBEDTLS_USE_PSA_CRYPTO

#ifndef MBEDTLS_PSA_CRYPTO_STORAGE_C
    #define MBEDTLS_PSA_CRYPTO_STORAGE_C
#endif // MBEDTLS_PSA_CRYPTO_STORAGE_C

#ifndef MBEDTLS_PK_HAVE_ECDSA
    #define MBEDTLS_PK_HAVE_ECDSA
#endif // MBEDTLS_PK_HAVE_ECDSA

#define MBEDTLS_DEBUG_C

#ifndef MBEDTLS_ERROR_C
#define MBEDTLS_ERROR_C
#endif
//memory allocation function
void * pvPortCalloc( size_t xNum,
                     size_t xSize );
void vPortFree( void * pv );
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO pvPortCalloc
#define MBEDTLS_PLATFORM_FREE_MACRO vPortFree


#if !defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
    #define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP192R1_ENABLED

#if !defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
    #define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP224R1_ENABLED

#if !defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
    #define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP384R1_ENABLED

#if !defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
    #define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP384R1_ENABLED

#if !defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
    #define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP521R1_ENABLED

#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
    #undef MBEDTLS_ECP_DP_SECP192K1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP192K1_ENABLED

#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
    #undef MBEDTLS_ECP_DP_SECP224K1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP224K1_ENABLED

#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
    #undef MBEDTLS_ECP_DP_SECP256K1_ENABLED
#endif // MBEDTLS_ECP_DP_SECP256K1_ENABLED

#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
    #undef MBEDTLS_ECP_DP_BP256R1_ENABLED
#endif // MBEDTLS_ECP_DP_BP256R1_ENABLED

#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
    #undef MBEDTLS_ECP_DP_BP384R1_ENABLED
#endif // MBEDTLS_ECP_DP_BP384R1_ENABLED

#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
    #undef MBEDTLS_ECP_DP_BP512R1_ENABLED
#endif // MBEDTLS_ECP_DP_BP512R1_ENABLED

#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    #undef MBEDTLS_ECP_DP_CURVE25519_ENABLED
#endif // MBEDTLS_ECP_DP_CURVE25519_ENABLED

#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
    #undef MBEDTLS_ECP_DP_CURVE448_ENABLED
#endif // MBEDTLS_ECP_DP_CURVE448_ENABLED

#endif /* __MBEDTLS_USER_CONFIG_H__ */
