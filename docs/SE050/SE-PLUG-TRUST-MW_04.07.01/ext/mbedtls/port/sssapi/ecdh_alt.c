/*
 *  Elliptic curve Diffie-Hellman
 *
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

/*
 * Copyright 2019-2021 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 * RFC 4492
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_ECDH_C)
#if defined(MBEDTLS_ECDH_ALT)
#include "mbedtls/ecdh.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#include "fsl_debug_console.h"
#include "sss_crypto.h"

/* Parameter validation macros based on platform_util.h */
#define ECDH_VALIDATE_RET(cond)    \
    MBEDTLS_INTERNAL_VALIDATE_RET(cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA)
#define ECDH_VALIDATE(cond)        \
    MBEDTLS_INTERNAL_VALIDATE(cond)

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
typedef mbedtls_ecdh_context mbedtls_ecdh_context_mbed;
#endif

static mbedtls_ecp_group_id mbedtls_ecdh_grp_id(
    const mbedtls_ecdh_context *ctx)
{
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ctx->grp.id;
#else
    return ctx->grp_id;
#endif
}

#define MBEDTLS_MPI_S_HAVE_OBJECT (155)
#define MBEDTLS_MPI_N_HAVE_OBJECT (1u)

/* NXP added */
#if !defined(MBEDTLS_ECDH_CANDO_ALT)
int mbedtls_ecdh_can_do(mbedtls_ecp_group_id gid)
{
    /* At this time, all groups support ECDH. */
    (void) gid;
    return 1;
}
#endif /* MBEDTLS_ECDH_CANDO_ALT */

#if !defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT)
/*
 * Generate public key (restartable version)
 *
 * Note: this internal function relies on its caller preserving the value of
 * the output parameter 'd' across continuation calls. This would not be
 * acceptable for a public function but is OK here as we control call sites.
 */
static int ecdh_gen_public_restartable(mbedtls_ecp_group *grp,
                                       mbedtls_mpi *d,
                                       mbedtls_ecp_point *Q,
                                       int (*f_rng)(void *, unsigned char *, size_t),
                                       void *p_rng,
                                       mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* If multiplication is in progress, we already generated a privkey */
#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx == NULL || rs_ctx->rsm == NULL)
#endif
    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(grp, d, f_rng, p_rng));

    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_restartable(grp, Q, d, &grp->G,
                                                f_rng, p_rng, rs_ctx));

cleanup:
    return ret;
}

/*
 * Generate public key
 */
int mbedtls_ecdh_gen_public(mbedtls_ecp_group *grp,
                            mbedtls_mpi *d,
                            mbedtls_ecp_point *Q,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    ECDH_VALIDATE_RET(grp != NULL);
    ECDH_VALIDATE_RET(d != NULL);
    ECDH_VALIDATE_RET(Q != NULL);
    ECDH_VALIDATE_RET(f_rng != NULL);
    return ecdh_gen_public_restartable(grp, d, Q, f_rng, p_rng, NULL);
}
#endif /* !MBEDTLS_ECDH_GEN_PUBLIC_ALT */

#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
/*
 * Compute shared secret (SEC1 3.3.1)
 */
static int ecdh_compute_shared_restartable(mbedtls_ecp_group *grp,
                                           mbedtls_mpi *z,
                                           const mbedtls_ecp_point *Q,
                                           const mbedtls_mpi *d,
                                           int (*f_rng)(void *, unsigned char *, size_t),
                                           void *p_rng,
                                           mbedtls_ecp_restart_ctx *rs_ctx)
{

    int ret = 0;

    sss_sscp_derive_key_t dCtx;
    size_t coordinateLen     = (grp->pbits + 7u) / 8u;
    size_t coordinateBitsLen = grp->pbits;

    sss_sscp_object_t pEcdhPubKey;
    sss_sscp_object_t sharedSecret;
    sss_sscp_object_t *pSecretKey = NULL;
    bool bFreeSecretKey = false;

    size_t keySize           = SSS_ECP_KEY_SZ(coordinateLen);
    uint8_t *pubKey          = mbedtls_calloc(keySize, sizeof(uint8_t));

    if (CRYPTO_InitHardware() != kStatus_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_key_object_init(&pEcdhPubKey, &g_keyStore) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_key_object_allocate_handle(&pEcdhPubKey,
                                                   0u,
                                                   kSSS_KeyPart_Public,
                                                   kSSS_CipherType_EC_NIST_P,
                                                   3u * coordinateLen,
                                                   SSS_KEYPROP_OPERATION_KDF) !=
               kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if ((ret = mbedtls_mpi_write_binary(&Q->X, pubKey, coordinateLen)) != 0) {
    } else if ((ret =
                    mbedtls_mpi_write_binary(&Q->Y, &pubKey[coordinateLen], coordinateLen)) != 0) {
    } else if (SSS_KEY_STORE_SET_KEY(&pEcdhPubKey,
                                     (const uint8_t *) pubKey,
                                     keySize,
                                     coordinateBitsLen,
                                     kSSS_KeyPart_Public) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_key_object_init(&sharedSecret, &g_keyStore) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_key_object_allocate_handle(&sharedSecret,
                                                   0u,
                                                   kSSS_KeyPart_Default,
                                                   kSSS_CipherType_AES,
                                                   coordinateLen,
                                                   SSS_KEYPROP_OPERATION_NONE
                                                   ) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    /* Check if private key is sw or ELE200 generated */
    if ((d->s == MBEDTLS_MPI_S_HAVE_OBJECT) && (d->n == MBEDTLS_MPI_N_HAVE_OBJECT)) {
        pSecretKey = (sss_sscp_object_t *) (uintptr_t) d->p;
        bFreeSecretKey = true;
    } else {
        sss_sscp_object_t secretKey;
        pSecretKey = &secretKey;

        /* Load secret key into SSS */
        if (sss_sscp_key_object_init(pSecretKey, &g_keyStore) != kStatus_SSS_Success) {
            ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        } else if (sss_sscp_key_object_allocate_handle(pSecretKey,
                                                       0u,
                                                       kSSS_KeyPart_Private,
                                                       kSSS_CipherType_EC_NIST_P,
                                                       coordinateLen,
                                                       SSS_KEYPROP_OPERATION_KDF
                                                       ) != kStatus_SSS_Success) {
            ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        } else if ((ret = mbedtls_mpi_write_binary(d, pubKey, coordinateLen)) != 0) {
            ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        } else if (SSS_KEY_STORE_SET_KEY(pSecretKey, (const uint8_t *) pubKey, coordinateLen,
                                         coordinateBitsLen,
                                         kSSS_KeyPart_Private) != kStatus_SSS_Success) {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }
    }

    if (sss_sscp_derive_key_context_init(&dCtx, &g_sssSession, pSecretKey, kAlgorithm_SSS_ECDH,
                                         kMode_SSS_ComputeSharedSecret) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_asymmetric_dh_derive_key(&dCtx, &pEcdhPubKey,
                                                 &sharedSecret) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_key_store_get_key(&g_keyStore, &sharedSecret, pubKey, &coordinateLen,
                                          &coordinateBitsLen,
                                          (sss_key_part_t) NULL) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if ((ret = mbedtls_mpi_read_binary(z, pubKey, coordinateLen)) != 0) {
    } else {
        ret = 0;
    }
    (void) sss_sscp_derive_key_context_free(&dCtx);
    (void) SSS_KEY_OBJ_FREE(&pEcdhPubKey);
    (void) SSS_KEY_OBJ_FREE(&sharedSecret);
    mbedtls_platform_zeroize(pubKey, keySize);
    mbedtls_free(pubKey);

    if (bFreeSecretKey) {
        (void) SSS_KEY_OBJ_FREE(pSecretKey);
    }

    return ret;
}
#else
static int ecdh_compute_shared_restartable(mbedtls_ecp_group *grp,
                                           mbedtls_mpi *z,
                                           const mbedtls_ecp_point *Q,
                                           const mbedtls_mpi *d,
                                           int (*f_rng)(void *, unsigned char *, size_t),
                                           void *p_rng,
                                           mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point P;

    mbedtls_ecp_point_init(&P);

    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_restartable(grp, &P, d, Q,
                                                f_rng, p_rng, rs_ctx));

    if (mbedtls_ecp_is_zero(&P)) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(z, &P.X));

cleanup:
    mbedtls_ecp_point_free(&P);

    return ret;
}

#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp,
                                mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q,
                                const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
    ECDH_VALIDATE_RET(grp != NULL);
    ECDH_VALIDATE_RET(Q != NULL);
    ECDH_VALIDATE_RET(d != NULL);
    ECDH_VALIDATE_RET(z != NULL);
    return ecdh_compute_shared_restartable(grp, z, Q, d, f_rng, p_rng, NULL);
}


static void ecdh_init_internal(mbedtls_ecdh_context_mbed *ctx)
{
    mbedtls_ecp_group_init(&ctx->grp);
    mbedtls_mpi_init(&ctx->d);
    mbedtls_ecp_point_init(&ctx->Q);
    mbedtls_ecp_point_init(&ctx->Qp);
    mbedtls_mpi_init(&ctx->z);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_init(&ctx->rs);
#endif
}

/*
 * Initialize context
 */
void mbedtls_ecdh_init(mbedtls_ecdh_context *ctx)
{
    ECDH_VALIDATE(ctx != NULL);

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    ecdh_init_internal(ctx);
    mbedtls_ecp_point_init(&ctx->Vi);
    mbedtls_ecp_point_init(&ctx->Vf);
    mbedtls_mpi_init(&ctx->_d);
#else
    memset(ctx, 0, sizeof(mbedtls_ecdh_context));

    ctx->var = MBEDTLS_ECDH_VARIANT_NONE;
#endif
    ctx->point_format     = MBEDTLS_ECP_PF_UNCOMPRESSED;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    ctx->restart_enabled = 0;
#endif
    ctx->isKeyInitialized = false;
}

static int ecdh_setup_internal(mbedtls_ecdh_context_mbed *ctx,
                               mbedtls_ecp_group_id grp_id)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_ecp_group_load(&ctx->grp, grp_id);
    if (ret != 0) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    return 0;
}

/*
 * Setup context
 */
int mbedtls_ecdh_setup(mbedtls_ecdh_context *ctx, mbedtls_ecp_group_id grp_id)
{
    ECDH_VALIDATE_RET(ctx != NULL);

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_setup_internal(ctx, grp_id);
#else
    switch (grp_id) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECP_DP_CURVE25519:
            ctx->point_format = MBEDTLS_ECP_PF_COMPRESSED;
            ctx->var = MBEDTLS_ECDH_VARIANT_EVEREST;
            ctx->grp_id = grp_id;
            return mbedtls_everest_setup(&ctx->ctx.everest_ecdh, grp_id);
#endif
        default:
            ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;
            ctx->var          = MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0;
            ctx->grp_id       = grp_id;
            ecdh_init_internal(&ctx->ctx.mbed_ecdh);
            return ecdh_setup_internal(&ctx->ctx.mbed_ecdh, grp_id);
    }
#endif
}

static void ecdh_free_internal(mbedtls_ecdh_context_mbed *ctx)
{
    mbedtls_ecp_group_free(&ctx->grp);
    mbedtls_mpi_free(&ctx->d);
    mbedtls_ecp_point_free(&ctx->Q);
    mbedtls_ecp_point_free(&ctx->Qp);
    mbedtls_mpi_free(&ctx->z);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_free(&ctx->rs);
#endif
}

#if defined(MBEDTLS_ECP_RESTARTABLE)
/*
 * Enable restartable operations for context
 */
void mbedtls_ecdh_enable_restart(mbedtls_ecdh_context *ctx)
{
    ECDH_VALIDATE(ctx != NULL);

    ctx->restart_enabled = 1;
}
#endif

/*
 * Free context
 */
void mbedtls_ecdh_free(mbedtls_ecdh_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->isKeyInitialized) {
        (void) SSS_KEY_OBJ_FREE(&ctx->key);
    }

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    mbedtls_ecp_point_free(&ctx->Vi);
    mbedtls_ecp_point_free(&ctx->Vf);
    mbedtls_mpi_free(&ctx->_d);
    ecdh_free_internal(ctx);
#else
    switch (ctx->var) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            mbedtls_everest_free(&ctx->ctx.everest_ecdh);
            break;
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            ecdh_free_internal(&ctx->ctx.mbed_ecdh);
            break;
        default:
            /* All the cases have been listed above, the default clause should not be reached. */
            break;
    }

    ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;
    ctx->var          = MBEDTLS_ECDH_VARIANT_NONE;
    ctx->grp_id       = MBEDTLS_ECP_DP_NONE;
#endif
}


static int ecdh_make_params_internal(mbedtls_ecdh_context_mbed *ctx,
                                     size_t *olen,
                                     int point_format,
                                     unsigned char *buf,
                                     size_t blen,
                                     int (*f_rng)(void *, unsigned char *, size_t),
                                     void *p_rng,
                                     int restart_enabled)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t grp_len, pt_len;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if (ctx->grp.pbits == 0u) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (restart_enabled) {
        rs_ctx = &ctx->rs;
    }
#else
    (void) restart_enabled;
#endif


#if defined(MBEDTLS_ECP_RESTARTABLE)
    if ((ret = ecdh_gen_public_restartable(&ctx->grp, &ctx->d, &ctx->Q,
                                           f_rng, p_rng, rs_ctx)) != 0) {
        return ret;
    }
#else
    if ((ret = mbedtls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q,
                                       f_rng, p_rng)) != 0) {
        return ret;
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    if ((ret = mbedtls_ecp_tls_write_group(&ctx->grp, &grp_len, buf, blen)) != 0) {
        return ret;
    }

    buf += grp_len;
    blen -= grp_len;

    if ((ret =
             mbedtls_ecp_tls_write_point(&ctx->grp, &ctx->Q, point_format, &pt_len, buf,
                                         blen)) != 0) {
        return ret;
    }

    *olen = grp_len + pt_len;
    return 0;
}

/*
 * Setup and write the ServerKeyExchange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int mbedtls_ecdh_make_params(mbedtls_ecdh_context *ctx,
                             size_t *olen,
                             unsigned char *buf,
                             size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int restart_enabled = 0;
    ECDH_VALIDATE_RET(ctx != NULL);
    ECDH_VALIDATE_RET(olen != NULL);
    ECDH_VALIDATE_RET(buf != NULL);
    ECDH_VALIDATE_RET(f_rng != NULL);

    (void) restart_enabled;

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_make_params_internal(ctx,
                                     olen,
                                     ctx->point_format,
                                     buf,
                                     blen,
                                     f_rng,
                                     p_rng,
                                     restart_enabled);
#else
    switch (ctx->var) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return mbedtls_everest_make_params(&ctx->ctx.everest_ecdh, olen,
                                               buf, blen, f_rng, p_rng);
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_make_params_internal(&ctx->ctx.mbed_ecdh,
                                             olen,
                                             ctx->point_format,
                                             buf,
                                             blen,
                                             f_rng,
                                             p_rng,
                                             restart_enabled);
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_read_params_internal(mbedtls_ecdh_context_mbed *ctx,
                                     const unsigned char **buf,
                                     const unsigned char *end)
{
    return mbedtls_ecp_tls_read_point(&ctx->grp,
                                      &ctx->Qp,
                                      buf,
                                      end - *buf);
}

/*
 * Read the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int mbedtls_ecdh_read_params(mbedtls_ecdh_context *ctx,
                             const unsigned char **buf,
                             const unsigned char *end)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_group_id grp_id;
    ECDH_VALIDATE_RET(ctx != NULL);
    ECDH_VALIDATE_RET(buf != NULL);
    ECDH_VALIDATE_RET(*buf != NULL);
    ECDH_VALIDATE_RET(end != NULL);

    if ((ret = mbedtls_ecp_tls_read_group_id(&grp_id, buf, end - *buf)) != 0) {
        return ret;
    }

    if ((ret = mbedtls_ecdh_setup(ctx, grp_id)) != 0) {
        return ret;
    }

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_read_params_internal(ctx, buf, end);
#else
    switch (ctx->var) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return mbedtls_everest_read_params(&ctx->ctx.everest_ecdh,
                                               buf, end);
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_read_params_internal(&ctx->ctx.mbed_ecdh, buf, end);
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_get_params_internal(mbedtls_ecdh_context_mbed *ctx,
                                    const mbedtls_ecp_keypair *key,
                                    mbedtls_ecdh_side side)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* If it's not our key, just import the public part as Qp */
    if (side == MBEDTLS_ECDH_THEIRS) {
        return mbedtls_ecp_copy(&ctx->Qp, &key->Q);
    }

    /* Our key: import public (as Q) and private parts */
    if (side != MBEDTLS_ECDH_OURS) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (((ret = mbedtls_ecp_copy(&ctx->Q, &key->Q)) != 0) ||
        ((ret = mbedtls_mpi_copy(&ctx->d, &key->d)) != 0)) {
        return ret;
    }

    return 0;
}

/*
 * Get parameters from a keypair
 */
int mbedtls_ecdh_get_params(mbedtls_ecdh_context *ctx,
                            const mbedtls_ecp_keypair *key,
                            mbedtls_ecdh_side side)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECDH_VALIDATE_RET(ctx != NULL);
    ECDH_VALIDATE_RET(key != NULL);
    ECDH_VALIDATE_RET(side == MBEDTLS_ECDH_OURS ||
                      side == MBEDTLS_ECDH_THEIRS);

    if (mbedtls_ecdh_grp_id(ctx) == MBEDTLS_ECP_DP_NONE) {
        /* This is the first call to get_params(). Set up the context
         * for use with the group. */
        if ((ret = mbedtls_ecdh_setup(ctx, key->grp.id)) != 0) {
            return ret;
        }
    } else {
        /* This is not the first call to get_params(). Check that the
         * current key's group is the same as the context's, which was set
         * from the first key's group. */
        if (mbedtls_ecdh_grp_id(ctx) != key->grp.id) {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
    }

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_get_params_internal(ctx, key, side);
#else
    switch (ctx->var) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
        {
            mbedtls_everest_ecdh_side s = side == MBEDTLS_ECDH_OURS ?
                                          MBEDTLS_EVEREST_ECDH_OURS :
                                          MBEDTLS_EVEREST_ECDH_THEIRS;
            return mbedtls_everest_get_params(&ctx->ctx.everest_ecdh,
                                              key, s);
        }
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_get_params_internal(&ctx->ctx.mbed_ecdh, key, side);
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

int mbedtls_ecdh_make_public(mbedtls_ecdh_context *ctx,
                             size_t *olen,
                             unsigned char *buf,
                             size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    ECDH_VALIDATE_RET(ctx != NULL);
    size_t coordinateLen     = (ctx->ctx.mbed_ecdh.grp.pbits + 7u) / 8u;
    size_t coordinateBitsLen = ctx->ctx.mbed_ecdh.grp.pbits;
    size_t keySize           = 2u * coordinateLen;
    uint8_t *pubKey = NULL;
    do {
        pubKey = mbedtls_calloc(keySize, sizeof(uint8_t));
        if (pubKey == NULL) {
            break;
        }
        if (CRYPTO_InitHardware() != kStatus_Success) {
            mbedtls_platform_zeroize(pubKey, keySize);
            mbedtls_free(pubKey);
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }
        if (ctx->isKeyInitialized == false) {
            if (sss_sscp_key_object_init(&ctx->key, &g_keyStore) != kStatus_SSS_Success) {
                (void) SSS_KEY_OBJ_FREE(&ctx->key);
                break; \
            }
            /* Allocate key handle */
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
            if (sss_sscp_key_object_allocate_handle(&ctx->key,
                                                    0u,
                                                    kSSS_KeyPart_Pair,
                                                    kSSS_CipherType_EC_NIST_P,
                                                    3u * coordinateLen,
                                                    SSS_PUBLIC_KEY_PART_EXPORTABLE) !=
                kStatus_SSS_Success)
#else
            if (sss_sscp_key_object_allocate_handle(&ctx->key,
                                                    0u,
                                                    kSSS_KeyPart_Pair,
                                                    kSSS_CipherType_EC_NIST_P,
                                                    3u * coordinateLen,
                                                    SSS_KEYPROP_OPERATION_KDF) !=
                kStatus_SSS_Success)
#endif
            {
                (void) SSS_KEY_OBJ_FREE(&ctx->key);
                break;;
            }
            ctx->isKeyInitialized = true;
        }
        if (SSS_ECP_GENERATE_KEY(&ctx->key, coordinateBitsLen) != kStatus_SSS_Success) {
            break;
        }
        if (SSS_KEY_STORE_GET_PUBKEY(&ctx->key,
                                     pubKey,
                                     &keySize,
                                     &coordinateBitsLen) != kStatus_SSS_Success) {
            break;
        }
        if ((ret = mbedtls_mpi_read_binary(&ctx->ctx.mbed_ecdh.Q.X, pubKey, coordinateLen)) != 0) {
            break;
        }
        if ((ret =
                 mbedtls_mpi_read_binary(&ctx->ctx.mbed_ecdh.Q.Y, &pubKey[coordinateLen],
                                         coordinateLen)) != 0) {
            break;
        }
        if ((ret = mbedtls_mpi_lset(&ctx->ctx.mbed_ecdh.Q.Z, 1)) != 0) {
            break;
        }

        mbedtls_ecp_tls_write_point(&ctx->ctx.mbed_ecdh.grp,
                                    &ctx->ctx.mbed_ecdh.Q,
                                    ctx->point_format,
                                    olen,
                                    buf,
                                    blen);
        ret = 0;
    } while (0);

    if (pubKey != NULL) {
        mbedtls_platform_zeroize(pubKey, keySize);
        mbedtls_free(pubKey);
    }
    return ret;
}

static int ecdh_read_public_internal(mbedtls_ecdh_context_mbed *ctx,
                                     const unsigned char *buf,
                                     size_t blen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;

    if ((ret = mbedtls_ecp_tls_read_point(&ctx->grp, &ctx->Qp, &p, blen)) != 0) {
        return ret;
    }

    if ((size_t) (p - buf) != blen) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    return 0;
}

/*
 * Parse and import the client's public value
 */
int mbedtls_ecdh_read_public(mbedtls_ecdh_context *ctx, const unsigned char *buf, size_t blen)
{
    ECDH_VALIDATE_RET(ctx != NULL);
    ECDH_VALIDATE_RET(buf != NULL);

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_read_public_internal(ctx, buf, blen);
#else
    switch (ctx->var) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return mbedtls_everest_read_public(&ctx->ctx.everest_ecdh,
                                               buf, blen);
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_read_public_internal(&ctx->ctx.mbed_ecdh, buf, blen);
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

/*
 * Derive and export the shared secret
 */
int mbedtls_ecdh_calc_secret(mbedtls_ecdh_context *ctx,
                             size_t *olen,
                             unsigned char *buf,
                             size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int ret = 0;
    ECDH_VALIDATE_RET(ctx != NULL);

    sss_sscp_derive_key_t dCtx;
    size_t coordinateLen     = (ctx->ctx.mbed_ecdh.grp.pbits + 7u) / 8u;
    size_t coordinateBitsLen = ctx->ctx.mbed_ecdh.grp.pbits;
    size_t keySize           = SSS_ECP_KEY_SZ(coordinateLen);
    uint8_t *pubKey          = mbedtls_calloc(keySize, sizeof(uint8_t));
    if (CRYPTO_InitHardware() != kStatus_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_key_object_init(&ctx->peerPublicKey, &g_keyStore) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
    else if (sss_sscp_key_object_allocate_handle(&ctx->peerPublicKey,
                                                 1u,
                                                 kSSS_KeyPart_Pair,
                                                 kSSS_CipherType_EC_NIST_P,
                                                 3u * coordinateLen,
                                                 SSS_PUBLIC_KEY_PART_EXPORTABLE) !=
             kStatus_SSS_Success)
#else
    else if (sss_sscp_key_object_allocate_handle(&ctx->peerPublicKey,
                                                 1u,
                                                 kSSS_KeyPart_Public,
                                                 kSSS_CipherType_EC_NIST_P,
                                                 3u * coordinateLen,
                                                 SSS_KEYPROP_OPERATION_KDF) != kStatus_SSS_Success)
#endif
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if ((ret =
                    mbedtls_mpi_write_binary(&ctx->ctx.mbed_ecdh.Qp.X, pubKey,
                                             coordinateLen)) != 0) {
    } else if ((ret =
                    mbedtls_mpi_write_binary(&ctx->ctx.mbed_ecdh.Qp.Y, &pubKey[coordinateLen],
                                             coordinateLen)) != 0) {
    } else if (SSS_KEY_STORE_SET_KEY(&ctx->peerPublicKey,
                                     (const uint8_t *) pubKey,
                                     keySize,
                                     coordinateBitsLen,
                                     kSSS_KeyPart_Public) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_key_object_init(&ctx->sharedSecret, &g_keyStore) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_key_object_allocate_handle(&ctx->sharedSecret,
                                                   2u,
                                                   kSSS_KeyPart_Default,
                                                   kSSS_CipherType_AES,
                                                   coordinateLen,
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
                                                   SSS_FULL_KEY_EXPORTABLE
#else
                                                   SSS_KEYPROP_OPERATION_NONE
#endif
                                                   ) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_derive_key_context_init(&dCtx, &g_sssSession, &ctx->key,
                                                kAlgorithm_SSS_ECDH,
                                                kMode_SSS_ComputeSharedSecret) !=
               kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_asymmetric_dh_derive_key(&dCtx, &ctx->peerPublicKey,
                                                 &ctx->sharedSecret) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_key_store_get_key(&g_keyStore, &ctx->sharedSecret, pubKey, &coordinateLen,
                                          &coordinateBitsLen,
                                          (sss_key_part_t) NULL) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if ((ret = mbedtls_mpi_read_binary(&ctx->ctx.mbed_ecdh.z, pubKey, coordinateLen)) != 0) {
    } else {
        ret = 0;
    }
    (void) sss_sscp_derive_key_context_free(&dCtx);
    (void) SSS_KEY_OBJ_FREE(&ctx->peerPublicKey);
    (void) SSS_KEY_OBJ_FREE(&ctx->sharedSecret);

    mbedtls_platform_zeroize(pubKey, keySize);
    mbedtls_free(pubKey);
    return ret;
}

/* test suite functions*/
#if defined(MBEDTLS_SELF_TEST)
static int ecdh_calc_secret_internal(mbedtls_ecdh_context_mbed *ctx,
                                     size_t *olen,
                                     unsigned char *buf,
                                     size_t blen,
                                     int (*f_rng)(void *, unsigned char *, size_t),
                                     void *p_rng,
                                     int restart_enabled)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if (ctx == NULL || ctx->grp.pbits == 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (restart_enabled) {
        rs_ctx = &ctx->rs;
    }
#else
    (void) restart_enabled;
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if ((ret = ecdh_compute_shared_restartable(&ctx->grp, &ctx->z, &ctx->Qp,
                                               &ctx->d, f_rng, p_rng,
                                               rs_ctx)) != 0) {
        return ret;
    }
#else
    if ((ret = mbedtls_ecdh_compute_shared(&ctx->grp, &ctx->z, &ctx->Qp,
                                           &ctx->d, f_rng, p_rng)) != 0) {
        return ret;
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    if (mbedtls_mpi_size(&ctx->z) > blen) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    *olen = ctx->grp.pbits / 8 + ((ctx->grp.pbits % 8) != 0);

    if (mbedtls_ecp_get_type(&ctx->grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        return mbedtls_mpi_write_binary_le(&ctx->z, buf, *olen);
    }

    return mbedtls_mpi_write_binary(&ctx->z, buf, *olen);
}

/*
 * Derive and export the shared secret
 */
int mbedtls_ecdh_calc_secret_sw(mbedtls_ecdh_context *ctx,
                                size_t *olen,
                                unsigned char *buf,
                                size_t blen,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
    int restart_enabled = 0;
    ECDH_VALIDATE_RET(ctx != NULL);
    ECDH_VALIDATE_RET(olen != NULL);
    ECDH_VALIDATE_RET(buf != NULL);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#endif

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_calc_secret_internal(ctx, olen, buf, blen, f_rng, p_rng, restart_enabled);
#else
    switch (ctx->var) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return mbedtls_everest_calc_secret(&ctx->ctx.everest_ecdh, olen,
                                               buf, blen, f_rng, p_rng);
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_calc_secret_internal(&ctx->ctx.mbed_ecdh, olen, buf,
                                             blen, f_rng, p_rng,
                                             restart_enabled);
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_make_public_internal(mbedtls_ecdh_context_mbed *ctx,
                                     size_t *olen,
                                     int point_format,
                                     unsigned char *buf,
                                     size_t blen,
                                     int (*f_rng)(void *, unsigned char *, size_t),
                                     void *p_rng,
                                     int restart_enabled)
{
    int ret;

    if (ctx->grp.pbits == 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    (void) restart_enabled;

    if ((ret = mbedtls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng)) != 0) {
        return ret;
    }

    return mbedtls_ecp_tls_write_point(&ctx->grp, &ctx->Q, point_format, olen, buf, blen);
}

/*
 * Setup and export the client public value
 */
int mbedtls_ecdh_make_public_sw(mbedtls_ecdh_context *ctx,
                                size_t *olen,
                                unsigned char *buf,
                                size_t blen,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
    int restart_enabled = 0;
    ECDH_VALIDATE_RET(ctx != NULL);
    ECDH_VALIDATE_RET(olen != NULL);
    ECDH_VALIDATE_RET(buf != NULL);
    ECDH_VALIDATE_RET(f_rng != NULL);

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_make_public_internal(ctx,
                                     olen,
                                     ctx->point_format,
                                     buf,
                                     blen,
                                     f_rng,
                                     p_rng,
                                     restart_enabled);
#else
    switch (ctx->var) {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_make_public_internal(&ctx->ctx.mbed_ecdh,
                                             olen,
                                             ctx->point_format,
                                             buf,
                                             blen,
                                             f_rng,
                                             p_rng,
                                             restart_enabled);
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
    size_t use_len;
    int rnd;

    if (rng_state != NULL) {
        rng_state = NULL;
    }

    while (len > 0U) {
        use_len = len;
        if (use_len > sizeof(int)) {
            use_len = sizeof(int);
        }
        rnd = rand();
        (void) memcpy(output, (unsigned char *) &rnd, use_len);
        output += use_len;
        len -= use_len;
    }

    return 0;
}

int mbedtls_ecdh_self_test(int verbose)
{
    int ret = 0;
    uint8_t buf[100];
    mbedtls_ecdh_context ecdhClient, ecdhServer;
    const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_list();
    size_t olen;

    for (uint32_t i = 0; curve_info->grp_id != MBEDTLS_ECP_DP_NONE; curve_info++, i++) {
        if (verbose != 0) {
            (void) mbedtls_printf("  ECDH %s - #%u: ", curve_info->name, i + 1u);
        }
        mbedtls_ecdh_init(&ecdhClient);
        mbedtls_ecdh_init(&ecdhServer);

        if ((ret = mbedtls_ecdh_setup(&ecdhClient, curve_info->grp_id)) != 0 ||
            (ret =
                 mbedtls_ecdh_make_public(&ecdhClient, &olen, buf, sizeof(buf), myrand,
                                          NULL)) != 0) {
            if (verbose != 0) {
                (void) mbedtls_printf("failed\n");
            }
            return ret;
        }
        if ((ret = mbedtls_ecdh_setup(&ecdhServer, curve_info->grp_id)) != 0 ||
            (ret =
                 mbedtls_ecdh_make_public_sw(&ecdhServer, &olen, buf, sizeof(buf), myrand,
                                             NULL)) != 0) {
            if (verbose != 0) {
                (void) mbedtls_printf("failed\n");
            }
            return ret;
        }

        (void) mbedtls_ecp_copy(&ecdhServer.ctx.mbed_ecdh.Qp, &ecdhClient.ctx.mbed_ecdh.Q);
        (void) mbedtls_ecp_copy(&ecdhClient.ctx.mbed_ecdh.Qp, &ecdhServer.ctx.mbed_ecdh.Q);

        ret = mbedtls_ecdh_calc_secret(&ecdhClient, &olen, buf, sizeof(buf), myrand, NULL);
        ret = mbedtls_ecdh_calc_secret_sw(&ecdhServer, &olen, buf, sizeof(buf), myrand, NULL);

        if (ret != 0 ||
            (ret =
                 memcmp(ecdhClient.ctx.mbed_ecdh.z.p, ecdhServer.ctx.mbed_ecdh.z.p,
                        sizeof(mbedtls_mpi_uint) * ecdhClient.ctx.mbed_ecdh.z.n)) != 0) {
            if (verbose != 0) {
                (void) mbedtls_printf("failed\n");
            }

            return ret;
        }
        mbedtls_ecdh_free(&ecdhServer);
        mbedtls_ecdh_free(&ecdhClient);

        if (verbose != 0) {
            (void) mbedtls_printf("passed\n");
        }
        if (verbose != 0) {
            (void) mbedtls_printf("\n");
        }
    }

    return ret;
}
#endif /* MBEDTLS_SELF_TEST */
#endif /*#if defined(MBEDTLS_ECDH_ALT) */
#endif /* MBEDTLS_ECDH_C */
