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

#ifdef MBEDTLS_ECDSA_VERIFY_ALT

#include <string.h>
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/private_access.h"
#include "fsl_sss_api.h"
#include "fsl_sss_util_asn1_der.h"
#include "ex_sss_boot.h"
#include "nxLog_App.h"
#include "nxEnsure.h"

/*
    Note: KeyId - 0x7D000011 is used to store the public key and do the ECDSA Verify.
    Assuming first time a nist256 key is set, only a nist256 key can be overwritten here for next ECDSA Verify.
    Any other key type if used, will result in error during set key.

    Solution -
    Enable `SSS_DELETE_SE05X_TMP_ECC_PUBLIC_KEY` to delete the key after every ECDSA Verify.
    This will ensure a new key is created next time and the implementation will work for all EC key types.
    NOTE THAT, THIS WILL RESULT IN NVM FLASH WRITES.
*/
#define SSS_DELETE_SE05X_TMP_ECC_PUBLIC_KEY 0
#define SSS_SE05X_TMP_ECC_PUBLIC_KEY_ID 0x7D000011

static sss_key_store_t *g_ecdsa_verify_keystore = NULL;
ex_sss_boot_ctx_t g_alt_se05x_session_ctx       = {0};

#define ECDSA_BUDGET(ops)
#define ECDSA_RS_ENTER(SUB) (void)rs_ctx
#define ECDSA_RS_LEAVE(SUB) (void)rs_ctx
#define ECDSA_RS_ECP NULL

/*
 * Set se05x session
 */
void sss_mbedtls_set_keystore_ecdsa_verify(sss_key_store_t *ssskeystore)
{
    g_ecdsa_verify_keystore = ssskeystore;
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

/*
 * Verify ECDSA signature of hashed message
 */

int mbedtls_ecdsa_verify_restartable(mbedtls_ecp_group *grp,
                                     const unsigned char *buf, size_t blen,
                                     const mbedtls_ecp_point *Q,
                                     const mbedtls_mpi *r,
                                     const mbedtls_mpi *s,
                                     mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi e, s_inv, u1, u2;
    mbedtls_ecp_point R;
    mbedtls_mpi *pu1 = &u1, *pu2 = &u2;

    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&e); mbedtls_mpi_init(&s_inv);
    mbedtls_mpi_init(&u1); mbedtls_mpi_init(&u2);

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if (!mbedtls_ecdsa_can_do(grp->id) || grp->N.MBEDTLS_PRIVATE(p) == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    ECDSA_RS_ENTER(ver);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ver != NULL) {
        /* redirect to our context */
        pu1 = &rs_ctx->ver->u1;
        pu2 = &rs_ctx->ver->u2;

        /* jump to current step */
        if (rs_ctx->ver->state == ecdsa_ver_muladd) {
            goto muladd;
        }
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    /*
     * Step 1: make sure r and s are in range 1..n-1
     */
    if (mbedtls_mpi_cmp_int(r, 1) < 0 || mbedtls_mpi_cmp_mpi(r, &grp->N) >= 0 ||
        mbedtls_mpi_cmp_int(s, 1) < 0 || mbedtls_mpi_cmp_mpi(s, &grp->N) >= 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 3: derive MPI from hashed message
     */
    MBEDTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));

    /*
     * Step 4: u1 = e / s mod n, u2 = r / s mod n
     */
    ECDSA_BUDGET(MBEDTLS_ECP_OPS_CHK + MBEDTLS_ECP_OPS_INV + 2);

    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&s_inv, s, &grp->N));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pu1, &e, &s_inv));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pu1, pu1, &grp->N));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pu2, r, &s_inv));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pu2, pu2, &grp->N));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ver != NULL) {
        rs_ctx->ver->state = ecdsa_ver_muladd;
    }

muladd:
#endif
    /*
     * Step 5: R = u1 G + u2 Q
     */
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd_restartable(grp,
                                                   &R, pu1, &grp->G, pu2, Q, ECDSA_RS_ECP));

    if (mbedtls_ecp_is_zero(&R)) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 6: convert xR to an integer (no-op)
     * Step 7: reduce xR mod n (gives v)
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&R.MBEDTLS_PRIVATE(X), &R.MBEDTLS_PRIVATE(X), &grp->N));

    /*
     * Step 8: check if v (that is, R.X) is equal to r
     */
    if (mbedtls_mpi_cmp_mpi(&R.MBEDTLS_PRIVATE(X), r) != 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&e); mbedtls_mpi_free(&s_inv);
    mbedtls_mpi_free(&u1); mbedtls_mpi_free(&u2);

    ECDSA_RS_LEAVE(ver);

    return ret;
}


int mbedtls_ecdsa_verify_o(mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *Q,
                         const mbedtls_mpi *r,
                         const mbedtls_mpi *s)
{
    return mbedtls_ecdsa_verify_restartable(grp, buf, blen, Q, r, s, NULL);
}

/*
grp – The ECP group to use. This must be initialized and have group parameters set, for example through mbedtls_ecp_group_load().
buf – The hashed content that was signed. This must be a readable buffer of length blen Bytes. It may be NULL if blen is zero.
blen – The length of buf in Bytes.
Q – The public key to use for verification. This must be initialized and setup.
r – The first integer of the signature. This must be initialized.
s – The second integer of the signature. This must be initialized.
*/

int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *Q,
                         const mbedtls_mpi *r,
                         const mbedtls_mpi *s)
{
    int ret                      = 1;
    uint8_t signature[256]       = {0};
    uint8_t rs_buf[80]           = {0};
    size_t signatureLen          = 0;
    size_t rs_buf_len            = 0;
    uint8_t publickey[256]       = {0};
    size_t publickeylen          = 0;
    size_t rawPublickeylen       = 0;
    uint32_t key_id              = SSS_SE05X_TMP_ECC_PUBLIC_KEY_ID;
    size_t keyBitLen             = 0;
    sss_asymmetric_t ctx_asymm   = {0};
    sss_object_t keyPair         = {0};
    sss_algorithm_t algorithm    = kAlgorithm_None;
    sss_cipher_type_t cipherType = kSSS_CipherType_NONE;
    sss_status_t status          = kStatus_SSS_Fail;
    char *portName               = NULL;

    LOG_D("mbedtls_ecdsa_verify (%s)", __FILE__);
    ENSURE_OR_GO_EXIT(grp != NULL)
    ENSURE_OR_GO_EXIT(buf != NULL)
    ENSURE_OR_GO_EXIT(Q != NULL)
    ENSURE_OR_GO_EXIT(r != NULL)
    ENSURE_OR_GO_EXIT(s != NULL)

    /*
    *  Create the signature
    *  Signature = {
    *  0x30, Remaining Length, Tag, R_length, R, Tag, S_length, S }
    */

    /* Set totoal length */
    signature[signatureLen++] = 0x30;
    if ((4 + mbedtls_mpi_size(r) + mbedtls_mpi_size(s)) > UINT8_MAX) {
        return -1;
    }
    signature[signatureLen++] = (unsigned char)(4 + mbedtls_mpi_size(r) + mbedtls_mpi_size(s));
    /* 4 ==> Tag + Lengthn + Tag + Length */

    /* Set R */
    rs_buf_len = mbedtls_mpi_size(r);
    ret        = mbedtls_mpi_write_binary(r, rs_buf, rs_buf_len);
    if (ret != 0) {
        return ret;
    }

    ret                       = -1;
    signature[signatureLen++] = 0x02;
    if ((rs_buf[0] & 0x80)) {
        ENSURE_OR_GO_EXIT(rs_buf_len + 1 <= UINT8_MAX);
        signature[signatureLen++] = (unsigned char)(rs_buf_len + 1);
        signature[signatureLen++] = 0x00;
        /* Increment total length */
        signature[1] += 1;
    }
    else {
        ENSURE_OR_GO_EXIT(rs_buf_len <= UINT8_MAX);
        signature[signatureLen++] = (unsigned char)rs_buf_len;
    }

    ENSURE_OR_GO_EXIT(signatureLen <= sizeof(signature));
    if ((sizeof(signature) - signatureLen) < rs_buf_len) {
        return -1;
    }
    ENSURE_OR_GO_EXIT(rs_buf_len <= sizeof(rs_buf));
    memcpy(&signature[signatureLen], rs_buf, rs_buf_len);
    signatureLen += rs_buf_len;

    /* Set S */
    rs_buf_len = mbedtls_mpi_size(s);
    ret        = mbedtls_mpi_write_binary(s, rs_buf, rs_buf_len);
    if (ret != 0) {
        return ret;
    }

    ret = -1;
    ENSURE_OR_GO_EXIT((signatureLen + 1) < sizeof(signature))
    signature[signatureLen++] = 0x02;
    if ((rs_buf[0] & 0x80)) {
        ENSURE_OR_GO_EXIT((signatureLen + 2) < sizeof(signature))
        ENSURE_OR_GO_EXIT(rs_buf_len + 1 <= UINT8_MAX);
        signature[signatureLen++] = (unsigned char)(rs_buf_len + 1);
        signature[signatureLen++] = 0x00;
        /* Increment total length */
        signature[1] += 1;
    }
    else {
        ENSURE_OR_GO_EXIT((signatureLen + 1) < sizeof(signature))
        ENSURE_OR_GO_EXIT(rs_buf_len <= UINT8_MAX);
        signature[signatureLen++] = (unsigned char)rs_buf_len;
    }

    ENSURE_OR_GO_EXIT(signatureLen <= sizeof(signature));
    if ((sizeof(signature) - signatureLen) < rs_buf_len) {
        return -1;
    }
    ENSURE_OR_GO_EXIT(rs_buf_len <= sizeof(rs_buf));
    memcpy(&signature[signatureLen], rs_buf, rs_buf_len);
    signatureLen += rs_buf_len;
    /* End of creating the signature*/

    switch (grp->id) {
    case MBEDTLS_ECP_DP_SECP192R1:
        memcpy(publickey, gecc_der_header_nist192, der_ecc_nistp192_header_len);
        publickeylen = der_ecc_nistp192_header_len;
        cipherType   = kSSS_CipherType_EC_NIST_P;
        keyBitLen    = 192;
        break;
    case MBEDTLS_ECP_DP_SECP224R1:
        memcpy(publickey, gecc_der_header_nist224, der_ecc_nistp224_header_len);
        publickeylen = der_ecc_nistp224_header_len;
        cipherType   = kSSS_CipherType_EC_NIST_P;
        keyBitLen    = 224;
        break;
    case MBEDTLS_ECP_DP_SECP256R1:
        memcpy(publickey, gecc_der_header_nist256, der_ecc_nistp256_header_len);
        publickeylen = der_ecc_nistp256_header_len;
        cipherType   = kSSS_CipherType_EC_NIST_P;
        keyBitLen    = 256;
        break;
    case MBEDTLS_ECP_DP_SECP384R1:
        memcpy(publickey, gecc_der_header_nist384, der_ecc_nistp384_header_len);
        publickeylen = der_ecc_nistp384_header_len;
        cipherType   = kSSS_CipherType_EC_NIST_P;
        keyBitLen    = 384;
        break;
    case MBEDTLS_ECP_DP_SECP521R1:
        memcpy(publickey, gecc_der_header_nist521, der_ecc_nistp521_header_len);
        publickeylen = der_ecc_nistp521_header_len;
        cipherType   = kSSS_CipherType_EC_NIST_P;
        keyBitLen    = 521;
        break;
    case MBEDTLS_ECP_DP_BP256R1:
        memcpy(publickey, gecc_der_header_bp256, der_ecc_bp256_header_len);
        publickeylen = der_ecc_bp256_header_len;
        cipherType   = kSSS_CipherType_EC_BRAINPOOL;
        keyBitLen    = 256;
        break;
    case MBEDTLS_ECP_DP_BP384R1:
        memcpy(publickey, gecc_der_header_bp384, der_ecc_bp384_header_len);
        publickeylen = der_ecc_bp384_header_len;
        cipherType   = kSSS_CipherType_EC_BRAINPOOL;
        keyBitLen    = 384;
        break;
    case MBEDTLS_ECP_DP_BP512R1:
        memcpy(publickey, gecc_der_header_bp512, der_ecc_bp512_header_len);
        publickeylen = der_ecc_bp512_header_len;
        cipherType   = kSSS_CipherType_EC_BRAINPOOL;
        keyBitLen    = 512;
        break;
    case MBEDTLS_ECP_DP_SECP192K1:
        memcpy(publickey, gecc_der_header_192k, der_ecc_192k_header_len);
        publickeylen = der_ecc_192k_header_len;
        cipherType   = kSSS_CipherType_EC_NIST_K;
        keyBitLen    = 192;
        break;
    case MBEDTLS_ECP_DP_SECP224K1:
        memcpy(publickey, gecc_der_header_224k, der_ecc_224k_header_len);
        publickeylen = der_ecc_224k_header_len;
        cipherType   = kSSS_CipherType_EC_NIST_K;
        keyBitLen    = 224;
        break;
    case MBEDTLS_ECP_DP_SECP256K1:
        memcpy(publickey, gecc_der_header_256k, der_ecc_256k_header_len);
        publickeylen = der_ecc_256k_header_len;
        cipherType   = kSSS_CipherType_EC_NIST_K;
        keyBitLen    = 256;
        break;
    default:
        LOG_I("Unsupported ec group found. Rolling back to software implementation of ecdsa verify");
        return mbedtls_ecdsa_verify_o(grp, buf, blen, Q, r, s);
    }

    // Check for SHA Algorithm
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
        goto exit;
    }

    ret = mbedtls_ecp_point_write_binary(
        grp, Q, 0, &rawPublickeylen, &publickey[publickeylen], (sizeof(publickey) - publickeylen));
    ENSURE_OR_GO_EXIT(ret == 0);
    ret = 1;

    publickeylen += rawPublickeylen;

    if (!g_ecdsa_verify_keystore) {
        LOG_W(
            "NOTE: The ALT implementation will open and close the session. All transient objects will be lost. \n \
        To avoid the session open in ALT, Use the sss_mbedtls_set_keystore_ecdsa_verify() api to pass the keystore.");

        status = ex_sss_boot_connectstring(0, NULL, &portName);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        status = ex_sss_boot_open(&g_alt_se05x_session_ctx, portName);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        status = ex_sss_key_store_and_object_init(&g_alt_se05x_session_ctx);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_object_init(&keyPair, &g_alt_se05x_session_ctx.ks);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }
    else {
        status = sss_key_object_init(&keyPair, g_ecdsa_verify_keystore);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }

    status = sss_key_object_allocate_handle(
        &keyPair, key_id, kSSS_KeyPart_Public, cipherType, publickeylen, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(keyPair.keyStore, &keyPair, publickey, publickeylen, keyBitLen, NULL, 0);
    if (status != kStatus_SSS_Success) {
        LOG_I(
            "The key id might have been used for storing different type of ec key \n. \
            Delete the key and try again OR use a different key id. (SSS_SE05X_TMP_ECC_PUBLIC_KEY_ID)");
        goto exit;
    }

    ENSURE_OR_GO_EXIT(keyPair.keyStore != NULL);
    status = sss_asymmetric_context_init(&ctx_asymm, keyPair.keyStore->session, &keyPair, algorithm, kMode_SSS_Verify);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    LOG_I("ECDSA Verify using SE05x (Using key id %02x)", keyPair.keyId);
    status = sss_asymmetric_verify_digest(&ctx_asymm, (uint8_t *)buf, blen, signature, signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

#if SSS_DELETE_SE05X_TMP_ECC_PUBLIC_KEY
    LOG_I("Delete key %x", SSS_SE05X_TMP_ECC_PUBLIC_KEY_ID);
    status = sss_key_store_erase_key(keyPair.keyStore, &keyPair);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
#endif

    ret = 0;
exit:
    if (ctx_asymm.session != NULL) {
        sss_asymmetric_context_free(&ctx_asymm);
    }
    if (keyPair.keyStore != NULL) {
        sss_key_object_free(&keyPair);
    }
    if (g_ecdsa_verify_keystore == NULL) {
        LOG_I("Close SE05x session");
        ex_sss_session_close(&g_alt_se05x_session_ctx);
    }
    return ret;
}

#endif //#ifdef MBEDTLS_ECDSA_VERIFY_ALT