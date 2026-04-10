/*
 *  FIPS-180-2 compliant SHA-256 implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The SHA-256 Secure Hash Standard was published by NIST in 2002.
 *
 *  http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
 */
/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SHA256_C)

#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf printf
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif /* MBEDTLS_PLATFORM_C */

#define SHA256_VALIDATE_RET(cond) MBEDTLS_INTERNAL_VALIDATE_RET(cond, \
                                                                MBEDTLS_ERR_SHA256_BAD_INPUT_DATA)
#define SHA256_VALIDATE(cond)     MBEDTLS_INTERNAL_VALIDATE(cond)

#if defined(MBEDTLS_SHA256_ALT)


/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n, b, i)                                                                              \
    do                                                                                                      \
    {                                                                                                       \
        (n) = \
            ((uint32_t) (b)[(i)] << \
        24) | ((uint32_t) (b)[(i) + 1] << 16) | ((uint32_t) (b)[(i) + 2] << 8) | \
            ((uint32_t) (b)[(i) + 3]);                                                                     \
    } while (0)
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, b, i)                     \
    do                                             \
    {                                              \
        (b)[(i)]     = (unsigned char) ((n) >> 24); \
        (b)[(i) + 1] = (unsigned char) ((n) >> 16); \
        (b)[(i) + 2] = (unsigned char) ((n) >> 8);  \
        (b)[(i) + 3] = (unsigned char) ((n));       \
    } while (0)
#endif

void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
    SHA256_VALIDATE(ctx != NULL);

    (void) memset(ctx, 0, sizeof(mbedtls_sha256_context));
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sha256_context));
}

void mbedtls_sha256_clone(mbedtls_sha256_context *dst, const mbedtls_sha256_context *src)
{
    SHA256_VALIDATE(dst != NULL);
    SHA256_VALIDATE(src != NULL);

    *dst = *src;
}

/*
 * SHA-256 context setup
 */
int mbedtls_sha256_starts_ret(mbedtls_sha256_context *ctx, int is224)
{
    SHA256_VALIDATE_RET(ctx != NULL);
    SHA256_VALIDATE_RET(is224 == 0 || is224 == 1);
    int ret;
    sss_algorithm_t alg;
    if (is224 == 1) {
        alg = kAlgorithm_SSS_SHA224;
    } else {
        alg = kAlgorithm_SSS_SHA256;
    }
    if (CRYPTO_InitHardware() != kStatus_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_digest_context_init(&ctx->ctx, &g_sssSession, alg,
                                            kMode_SSS_Digest) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_digest_init(&ctx->ctx) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else {
        ret = 0;
    }
    return ret;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224)
{
    (void) mbedtls_sha256_starts_ret(ctx, is224);
}
#endif

#if defined(MBEDTLS_SHA256_PROCESS_ALT)
int mbedtls_internal_sha256_process(mbedtls_sha256_context *ctx, const unsigned char data[64])
{
    status_t ret;
    if (CRYPTO_InitHardware() != kStatus_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_digest_update(&ctx->ctx, (uint8_t *) (uintptr_t) data,
                                      64) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else {
        ret = 0;
    }
    return ret;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_process(mbedtls_sha256_context *ctx, const unsigned char data[64])
{
    (void) mbedtls_internal_sha256_process(ctx, data);
}
#endif
#endif /* !MBEDTLS_SHA256_PROCESS_ALT */

/*
 * SHA-256 process buffer
 */
int mbedtls_sha256_update_ret(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen)
{
    int ret;
    if (CRYPTO_InitHardware() != kStatus_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_digest_update(&ctx->ctx, (uint8_t *) (uintptr_t) input,
                                      ilen) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else {
        ret = 0;
    }
    return ret;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_update(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen)
{
    (void) mbedtls_sha256_update_ret(ctx, input, ilen);
}
#endif

/*
 * SHA-256 final digest
 */
int mbedtls_sha256_finish_ret(mbedtls_sha256_context *ctx, unsigned char output[32])
{
    int ret;
    size_t len = ctx->ctx.digestFullLen;
    if (CRYPTO_InitHardware() != kStatus_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_digest_finish(&ctx->ctx, output, &len) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else {
        ret = 0;
    }
    (void) sss_sscp_digest_context_free(&ctx->ctx);
    return ret;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char output[32])
{
    (void) mbedtls_sha256_finish_ret(ctx, output);
}
#endif
#endif /* MBEDTLS_SHA256_ALT */

#if defined(NXP_MBEDTLS_SHA256_ALT)
/*
 * output = SHA-256( input buffer )
 */
int mbedtls_sha256_ret(const unsigned char *input, size_t ilen, unsigned char output[32], int is224)
{
    sss_sscp_digest_t dctx;
    sss_algorithm_t alg;
    int ret;
    size_t size = 32u;
    if (is224 == 1) {
        alg = kAlgorithm_SSS_SHA224;
    } else {
        alg = kAlgorithm_SSS_SHA256;
    }
    if (CRYPTO_InitHardware() != kStatus_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_digest_context_init(&dctx, &g_sssSession, alg,
                                            kMode_SSS_Digest) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else {
        sss_status_t st;
        st = sss_sscp_digest_one_go(&dctx, input, ilen, output, &size);
        ret = (st == kStatus_SSS_Success) ? 0 : MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        (void) sss_sscp_digest_context_free(&dctx);
    }
    return ret;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256(const unsigned char *input, size_t ilen, unsigned char output[32], int is224)
{
    (void) mbedtls_sha256_ret(input, ilen, output, is224);
}
#endif
#endif /* NXP_MBEDTLS_SHA256_ALT */

#endif /* MBEDTLS_SHA256_C */
