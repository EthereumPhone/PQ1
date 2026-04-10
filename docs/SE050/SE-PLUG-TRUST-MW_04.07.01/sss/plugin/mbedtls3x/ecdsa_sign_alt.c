/*
 *  Elliptic curve DSA
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


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#ifdef MBEDTLS_ECDSA_SIGN_ALT

#include <string.h>
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/private_access.h"
#include "fsl_sss_api.h"
#include "nxLog_App.h"
#include "nxEnsure.h"
#include "ex_sss_boot.h"

#define ECDSA_BUDGET(ops)
#define ECDSA_RS_ENTER(SUB) (void)rs_ctx
#define ECDSA_RS_LEAVE(SUB) (void)rs_ctx
#define ECDSA_RS_ECP NULL

#define SSS_MAGIC_NUMBER (0xB6B5A6A5)
#define SSS_MAGIC_NUMBER_OFFSET1 (2)
#define SSS_MAGIC_NUMBER_OFFSET2 (6)
#define SSS_KEY_ID_IN_REFKEY_OFFSET (10)

static sss_key_store_t *g_ecdsa_sign_keystore = NULL;
ex_sss_boot_ctx_t g_se05x_session_ctx = {0};

 /*
 * Set se05x session
 */
void sss_mbedtls_set_keystore_ecdsa_sign(sss_key_store_t *ssskeystore)
{
    g_ecdsa_sign_keystore = ssskeystore;
}

/*
 * Compute ECDSA signature of a hashed message
 */
static int derive_mpi(const mbedtls_ecp_group *grp, mbedtls_mpi *x,
                      const unsigned char *buf, size_t blen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n_size = (grp->nbits + 7) / 8;
    size_t use_size = blen > n_size ? n_size : blen;

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(x, buf, use_size));
    if (use_size * 8 > grp->nbits) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(x, use_size * 8 - grp->nbits));
    }

    /* While at it, reduce modulo N */
    if (mbedtls_mpi_cmp_mpi(x, &grp->N) >= 0) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(x, x, &grp->N));
    }

cleanup:
    return ret;
}

int mbedtls_ecdsa_sign_restartable(mbedtls_ecp_group *grp,
                                   mbedtls_mpi *r, mbedtls_mpi *s,
                                   const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                   int (*f_rng_blind)(void *, unsigned char *, size_t),
                                   void *p_rng_blind,
                                   mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret, key_tries, sign_tries;
    int *p_sign_tries = &sign_tries, *p_key_tries = &key_tries;
    mbedtls_ecp_point R;
    mbedtls_mpi k, e, t;
    mbedtls_mpi *pk = &k, *pr = r;

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    // if (!mbedtls_ecdsa_can_do(grp->id) || grp->N.p == NULL) {   =======> Commented for now, need to be fixed later
    //     return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    // }

    /* Make sure d is in range 1..n-1 */
    if (mbedtls_mpi_cmp_int(d, 1) < 0 || mbedtls_mpi_cmp_mpi(d, &grp->N) >= 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&k); mbedtls_mpi_init(&e); mbedtls_mpi_init(&t);

    ECDSA_RS_ENTER(sig);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->sig != NULL) {
        /* redirect to our context */
        p_sign_tries = &rs_ctx->sig->sign_tries;
        p_key_tries = &rs_ctx->sig->key_tries;
        pk = &rs_ctx->sig->k;
        pr = &rs_ctx->sig->r;

        /* jump to current step */
        if (rs_ctx->sig->state == ecdsa_sig_mul) {
            goto mul;
        }
        if (rs_ctx->sig->state == ecdsa_sig_modn) {
            goto modn;
        }
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    *p_sign_tries = 0;
    do {
        if ((*p_sign_tries)++ > 10) {
            ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }

        /*
         * Steps 1-3: generate a suitable ephemeral keypair
         * and set r = xR mod n
         */
        *p_key_tries = 0;
        do {
            if ((*p_key_tries)++ > 10) {
                ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }

            MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(grp, pk, f_rng, p_rng));

#if defined(MBEDTLS_ECP_RESTARTABLE)
            if (rs_ctx != NULL && rs_ctx->sig != NULL) {
                rs_ctx->sig->state = ecdsa_sig_mul;
            }

mul:
#endif
            MBEDTLS_MPI_CHK(mbedtls_ecp_mul_restartable(grp, &R, pk, &grp->G,
                                                        f_rng_blind,
                                                        p_rng_blind,
                                                        ECDSA_RS_ECP));
             MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pr, &R.MBEDTLS_PRIVATE(X), &grp->N));
        } while (mbedtls_mpi_cmp_int(pr, 0) == 0);

#if defined(MBEDTLS_ECP_RESTARTABLE)
        if (rs_ctx != NULL && rs_ctx->sig != NULL) {
            rs_ctx->sig->state = ecdsa_sig_modn;
        }

modn:
#endif
        /*
         * Accounting for everything up to the end of the loop
         * (step 6, but checking now avoids saving e and t)
         */
        ECDSA_BUDGET(MBEDTLS_ECP_OPS_INV + 4);

        /*
         * Step 5: derive MPI from hashed message
         */
        MBEDTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));

        /*
         * Generate a random value to blind inv_mod in next step,
         * avoiding a potential timing leak.
         */
        MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(grp, &t, f_rng_blind,
                                                p_rng_blind));

        /*
         * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
         */
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(s, pr, d));
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&e, &e, s));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&e, &e, &t));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pk, pk, &t));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pk, pk, &grp->N));
        MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(s, pk, &grp->N));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(s, s, &e));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(s, s, &grp->N));
    } while (mbedtls_mpi_cmp_int(s, 0) == 0);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->sig != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(r, pr));
    }
#endif

cleanup:
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&k); mbedtls_mpi_free(&e); mbedtls_mpi_free(&t);

    ECDSA_RS_LEAVE(sig);

    return ret;
}

int EcSignatureToRandS_alt(uint8_t *signature, size_t *sigLen, mbedtls_mpi *r, mbedtls_mpi *s)
{
    int ret = 1;
    ENSURE_OR_GO_EXIT(signature != NULL)
    ENSURE_OR_GO_EXIT(sigLen != NULL)
    ENSURE_OR_GO_EXIT(r != NULL)
    ENSURE_OR_GO_EXIT(s != NULL)

    unsigned char *p = (unsigned char *) signature;
    const unsigned char *end = signature + *sigLen;
    size_t len = 0;

    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    ENSURE_OR_GO_EXIT(ret == 0)

    ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_ECP_BAD_INPUT_DATA, MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    ENSURE_OR_GO_EXIT(p + len == end)

    ret = mbedtls_asn1_get_mpi(&p, end, r);
    ENSURE_OR_GO_EXIT(ret == 0)

    ret = mbedtls_asn1_get_mpi(&p, end, s);

exit:
    return ret;
}

int mbedtls_ecdsa_sign_o(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = 1;
    ENSURE_OR_GO_EXIT(grp != NULL);
    ENSURE_OR_GO_EXIT(r != NULL);
    ENSURE_OR_GO_EXIT(s != NULL);
    ENSURE_OR_GO_EXIT(d != NULL);
    ret = mbedtls_ecdsa_sign_restartable(grp, r, s, d, buf, blen,
                                          f_rng, p_rng, f_rng, p_rng, NULL);
exit:
    return ret;
}


/*
    grp – The context for the elliptic curve to use. This must be initialized and have group parameters set, for example through mbedtls_ecp_group_load().
    r – The MPI context in which to store the first part the signature. This must be initialized.
    s – The MPI context in which to store the second part the signature. This must be initialized.
    d – The private signing key. This must be initialized.
    buf – The content to be signed. This is usually the hash of the original data to be signed. This must be a readable buffer of length blen Bytes. It may be NULL if blen is zero.
    blen – The length of buf in Bytes.
    f_rng – The RNG function. This must not be NULL.
    p_rng – The RNG context to be passed to f_rng. This may be NULL if f_rng doesn’t need a context parameter.
*/
int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    uint8_t ref_key[128] = {0};
    size_t ref_key_len   = sizeof(ref_key);
    uint32_t magic_no1   = 0;
    uint32_t magic_no2   = 0;
    int mbedtls_ret      = 0;

    LOG_D("mbedtls_ecdsa_sign (%s)", __FILE__);

    ENSURE_OR_RETURN_ON_ERROR(grp != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(r != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(s != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(d != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(buf != NULL, 1);
    (void)f_rng;
    (void)p_rng;

    ref_key_len = mbedtls_mpi_size(d);
    mbedtls_ret = mbedtls_mpi_write_binary_le(d, ref_key, ref_key_len);
    ENSURE_OR_RETURN_ON_ERROR(mbedtls_ret == 0, mbedtls_ret);

    ENSURE_OR_RETURN_ON_ERROR(ref_key_len > (SSS_MAGIC_NUMBER_OFFSET2 + 3), 1);

    magic_no1 = (ref_key[SSS_MAGIC_NUMBER_OFFSET1 + 0] << 24) | (ref_key[SSS_MAGIC_NUMBER_OFFSET1 + 1] << 16) |
                (ref_key[SSS_MAGIC_NUMBER_OFFSET1 + 2] << 8) | ref_key[SSS_MAGIC_NUMBER_OFFSET1 + 3];
    magic_no2 = (ref_key[SSS_MAGIC_NUMBER_OFFSET2 + 0] << 24) | (ref_key[SSS_MAGIC_NUMBER_OFFSET2 + 1] << 16) |
                (ref_key[SSS_MAGIC_NUMBER_OFFSET2 + 2] << 8) | ref_key[SSS_MAGIC_NUMBER_OFFSET2 + 3];

    // Check if the key is reference key
    if ((magic_no1 == SSS_MAGIC_NUMBER) && (magic_no2 == SSS_MAGIC_NUMBER)) {
        int ret                    = 1;
        sss_status_t status        = kStatus_SSS_Success;
        uint8_t signature[140]     = {0};
        size_t signatureLen        = sizeof(signature);
        uint32_t key_id            = {0};
        sss_asymmetric_t ctx_asymm = {0};
        sss_object_t keyPair       = {0};
        sss_algorithm_t algorithm  = kAlgorithm_None;

        LOG_I("Reference key found. Use Secure element for ECDSA.");

        // Get Key id from Ref key
        key_id = ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 3];
        key_id = key_id << (1 * 8);
        ENSURE_OR_GO_CLEANUP(key_id <= UINT32_MAX - ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 2]);
        key_id += ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 2];
        key_id = key_id << (1 * 8);
        ENSURE_OR_GO_CLEANUP(key_id <= UINT32_MAX - ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 1]);
        key_id += ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 1];
        key_id = key_id << (1 * 8);
        ENSURE_OR_GO_CLEANUP(key_id <= UINT32_MAX - ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 0]);
        key_id += ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 0];

        // check for hash algorithm
        switch (blen) {
        case 20:
            algorithm = kAlgorithm_SSS_SHA1;
            break;
        case 28:
            algorithm = kAlgorithm_SSS_SHA224;
            break;
        case 32:
            algorithm = kAlgorithm_SSS_SHA256;
            break;
        case 48:
            algorithm = kAlgorithm_SSS_SHA384;
            break;
        case 64:
            algorithm = kAlgorithm_SSS_SHA512;
            break;
        default:
            LOG_E("Wrong input data length");
            goto cleanup;
        }

        /*
        * Create a new session if keystore is not assigned
        */
        if (!g_ecdsa_sign_keystore) {
            char *portName = NULL;

            LOG_W(
                "NOTE: The ALT implementation will open and close the session. All transient objects will be lost. \n \
            To avoid the session open in ALT, Use the sss_mbedtls_set_keystore_ecdsa_sign() api to pass the keystore.");

            status = ex_sss_boot_connectstring(0, NULL, &portName);
            ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

            status = ex_sss_boot_open(&g_se05x_session_ctx, portName);
            ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

            status = ex_sss_key_store_and_object_init(&g_se05x_session_ctx);
            ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

            status = sss_key_object_init(&keyPair, &g_se05x_session_ctx.ks);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success)
        }
        else {
            status = sss_key_object_init(&keyPair, g_ecdsa_sign_keystore);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success)
        }

        status = sss_key_object_get_handle(&keyPair, (uint32_t)key_id);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success)

        if (keyPair.keyStore != NULL) {
            status =
                sss_asymmetric_context_init(&ctx_asymm, keyPair.keyStore->session, &keyPair, algorithm, kMode_SSS_Sign);
        }
        else {
            /* No valid key store */
            status = kStatus_SSS_Fail;
        }
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success)

        LOG_I("ECDSA Sign using SE05x (Using key id %02X)", keyPair.keyId);
        status = sss_asymmetric_sign_digest(&ctx_asymm, (uint8_t *)buf, blen, signature, &signatureLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        if (0 != EcSignatureToRandS_alt(signature, &signatureLen, r, s)) {
            goto cleanup;
        }

        ret = 0;
    cleanup:
        if (ctx_asymm.session != NULL) {
            sss_asymmetric_context_free(&ctx_asymm);
        }
        if (keyPair.keyStore != NULL) {
            sss_key_object_free(&keyPair);
        }
        if (g_ecdsa_sign_keystore == NULL) {
            LOG_I("Close SE05x session");
            ex_sss_session_close(&g_se05x_session_ctx);
        }
        return ret;
    }
    else {
        LOG_I("Not a reference key. Rollback to software implementation of ecdsa sign");
        return mbedtls_ecdsa_sign_o(grp, r, s, d, buf, blen, f_rng, p_rng);
    }
}

#endif //#if MBEDTLS_ECDSA_SIGN_ALT