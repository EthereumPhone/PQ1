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
 * References:
 *
 * SEC1 https://www.secg.org/sec1-v2.pdf
 * RFC 4492
 */

#include "common.h"

#if defined(MBEDTLS_ECDH_C)

#include "mbedtls/ecdh.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>
#include "fsl_sss_api.h"
#include "fsl_sss_util_asn1_der.h"
#include "nxLog_App.h"
#include "nxEnsure.h"
#include "ex_sss_boot.h"

#define SSS_SE05X_TMP_ECC_OTHER_PARTY_PUBLIC_KEY_ID (0x7D000041) // Used on host
#define SSS_SE05X_TMP_DERIVE_KEY_ID (0x7D000043) // Used on host

#define SSS_MAGIC_NUMBER (0xB6B5A6A5)
#define SSS_MAGIC_NUMBER_OFFSET1 (2)
#define SSS_MAGIC_NUMBER_OFFSET2 (6)
#define SSS_KEY_ID_IN_REFKEY_OFFSET (10)

static sss_key_store_t *g_ecdh_keystore      = NULL;
static sss_key_store_t *g_ecdh_host_keystore = NULL;
ex_sss_boot_ctx_t g_se05x_ecdh_session_ctx   = {0};

/*
 * Set se05x session
 */
void sss_mbedtls_set_keystore_ecdh(sss_key_store_t *se05x_keystore, sss_key_store_t *host_ks)
{
    g_ecdh_keystore      = se05x_keystore;
    g_ecdh_host_keystore = host_ks;
}


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

#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
/*
 * Compute shared secret (SEC1 3.3.1)
 */
static int ecdh_compute_shared_restartable(mbedtls_ecp_group *grp,
                                           mbedtls_mpi *z,
                                           const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
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

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int mbedtls_ecdh_compute_shared_o(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
    return ecdh_compute_shared_restartable(grp, z, Q, d,
                                           f_rng, p_rng, NULL);
}

/*
* return asn1 header length
*/
static int mbedtls_get_header_and_bit_Length(int groupid, int *headerLen, int *bitLen)
{
    switch (groupid) {
    case MBEDTLS_ECP_DP_SECP192R1:
        if (headerLen != NULL) {
            *headerLen = der_ecc_nistp192_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 192;
        }
        break;
    case MBEDTLS_ECP_DP_SECP224R1:
        if (headerLen != NULL) {
            *headerLen = der_ecc_nistp224_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 224;
        }
        break;
    case MBEDTLS_ECP_DP_SECP256R1:
        if (headerLen != NULL) {
            *headerLen = der_ecc_nistp256_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 256;
        }
        break;
    case MBEDTLS_ECP_DP_SECP384R1:
        if (headerLen != NULL) {
            *headerLen = der_ecc_nistp384_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 384;
        }
        break;
    case MBEDTLS_ECP_DP_SECP521R1:
        if (headerLen != NULL) {
            *headerLen = der_ecc_nistp521_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 521;
        }
        break;
    case MBEDTLS_ECP_DP_BP256R1:
        if (headerLen != NULL) {
            *headerLen = der_ecc_bp256_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 256;
        }
        break;
    case MBEDTLS_ECP_DP_BP384R1:
        if (headerLen != NULL) {
            *headerLen = der_ecc_bp384_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 384;
        }
        break;
    case MBEDTLS_ECP_DP_BP512R1:
        if (headerLen != NULL) {
            *headerLen = der_ecc_bp512_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 512;
        }
        break;
    case MBEDTLS_ECP_DP_SECP192K1:
        if (headerLen != NULL) {
            *headerLen = der_ecc_192k_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 192;
        }
        break;
    case MBEDTLS_ECP_DP_SECP224K1:
        if (headerLen != NULL) {
            *headerLen = der_ecc_224k_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 224;
        }
        break;
    case MBEDTLS_ECP_DP_SECP256K1:
        if (headerLen != NULL) {
            *headerLen = der_ecc_256k_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 256;
        }
        break;
    case MBEDTLS_ECP_DP_CURVE25519:
        if (headerLen != NULL) {
            *headerLen = der_ecc_mont_dh_25519_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 256;
        }
        break;
    case MBEDTLS_ECP_DP_CURVE448:
        if (headerLen != NULL) {
            *headerLen = der_ecc_mont_dh_448_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 448;
        }
        break;
    default:
        LOG_E("get_header_and_bit_Length: Group id not supported");
        return 1;
    }

    return 0;
}

int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
    int ret                                    = -1;
    int headerLen                              = 0;
    int keyBitLen                              = 0;
    uint8_t otherPublicKey[256]                = {0};
    size_t otherPublickeyLen                   = sizeof(otherPublicKey);
    sss_cipher_type_t otherPublickeycipherType = kSSS_CipherType_NONE;
    uint32_t publicKeyId                       = SSS_SE05X_TMP_ECC_OTHER_PARTY_PUBLIC_KEY_ID;
    uint8_t privateKey[128]                    = {0};
    size_t privateKeylen                       = 0;
    sss_object_t privateKeyObject              = {0};
    uint8_t buf[256]                           = {0};
    size_t bufByteLen                          = sizeof(buf);
    size_t bufbitLen                           = sizeof(buf) * 8;
    uint32_t deriveKeyId                       = SSS_SE05X_TMP_DERIVE_KEY_ID;
    sss_object_t publicKeyObject               = {0};
    sss_object_t deriveKeyObject               = {0};
    sss_status_t status                        = kStatus_SSS_Fail;
    sss_derive_key_t ctx_derive_key            = {0};
    uint32_t magic_no1                         = 0;
    uint32_t magic_no2                         = 0;
    uint32_t key_id                            = 0;
    int mbedtls_ret                            = 0;

    /* read the private key */
    privateKeylen = mbedtls_mpi_size(d);
    mbedtls_ret = mbedtls_mpi_write_binary_le(d, privateKey, privateKeylen);
    ENSURE_OR_RETURN_ON_ERROR(mbedtls_ret == 0, mbedtls_ret);

    /* Check if Key is reference key or not */
    magic_no1 = (privateKey[SSS_MAGIC_NUMBER_OFFSET1 + 0] << 24) | (privateKey[SSS_MAGIC_NUMBER_OFFSET1 + 1] << 16) |
                (privateKey[SSS_MAGIC_NUMBER_OFFSET1 + 2] << 8) | privateKey[SSS_MAGIC_NUMBER_OFFSET1 + 3];
    magic_no2 = (privateKey[SSS_MAGIC_NUMBER_OFFSET2 + 0] << 24) | (privateKey[SSS_MAGIC_NUMBER_OFFSET2 + 1] << 16) |
                (privateKey[SSS_MAGIC_NUMBER_OFFSET2 + 2] << 8) | privateKey[SSS_MAGIC_NUMBER_OFFSET2 + 3];

    if ((magic_no1 == SSS_MAGIC_NUMBER) && (magic_no2 == SSS_MAGIC_NUMBER)) {
        LOG_I("Reference key found. Use Secure element for ECDH.");

        // Get Key id from Ref key
        key_id = privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 3];
        key_id = key_id << (1 * 8);
        ENSURE_OR_GO_EXIT(key_id <= UINT32_MAX - privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 2]);
        key_id += privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 2];
        key_id = key_id << (1 * 8);
        ENSURE_OR_GO_EXIT(key_id <= UINT32_MAX - privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 1]);
        key_id += privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 1];
        key_id = key_id << (1 * 8);
        ENSURE_OR_GO_EXIT(key_id <= UINT32_MAX - privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 0]);
        key_id += privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 0];
    }
    else {
        LOG_I("Not a reference key. Rollback to software implementation of ECDH");
        return mbedtls_ecdh_compute_shared_o(grp, z, Q, d, f_rng, p_rng);
    }

    ret = mbedtls_get_header_and_bit_Length(grp->id, &headerLen, &keyBitLen);
    ENSURE_OR_GO_EXIT(ret == 0);

    /* read the other party public key */
    ret = mbedtls_ecp_point_write_binary(
        grp, Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &otherPublickeyLen, (otherPublicKey + headerLen), sizeof(otherPublicKey));
    ENSURE_OR_GO_EXIT(ret == 0);

    switch (grp->id) {
    case MBEDTLS_ECP_DP_SECP192R1:
        memcpy(otherPublicKey, gecc_der_header_nist192, der_ecc_nistp192_header_len);
        if ((SIZE_MAX - der_ecc_nistp192_header_len) < otherPublickeyLen) {
            return 1;
        }
        otherPublickeyLen        = otherPublickeyLen + der_ecc_nistp192_header_len;
        otherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
        break;
    case MBEDTLS_ECP_DP_SECP224R1:
        memcpy(otherPublicKey, gecc_der_header_nist224, der_ecc_nistp224_header_len);
        if ((SIZE_MAX - der_ecc_nistp224_header_len) < otherPublickeyLen) {
            return 1;
        }
        otherPublickeyLen        = otherPublickeyLen + der_ecc_nistp224_header_len;
        otherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
        break;
    case MBEDTLS_ECP_DP_SECP256R1:
        memcpy(otherPublicKey, gecc_der_header_nist256, der_ecc_nistp256_header_len);
        if ((SIZE_MAX - der_ecc_nistp256_header_len) < otherPublickeyLen) {
            return 1;
        }
        otherPublickeyLen        = otherPublickeyLen + der_ecc_nistp256_header_len;
        otherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
        break;
    case MBEDTLS_ECP_DP_SECP384R1:
        memcpy(otherPublicKey, gecc_der_header_nist384, der_ecc_nistp384_header_len);
        if ((SIZE_MAX - der_ecc_nistp384_header_len) < otherPublickeyLen) {
            return 1;
        }
        otherPublickeyLen        = otherPublickeyLen + der_ecc_nistp384_header_len;
        otherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
        break;
    case MBEDTLS_ECP_DP_SECP521R1:
        memcpy(otherPublicKey, gecc_der_header_nist521, der_ecc_nistp521_header_len);
        if ((SIZE_MAX - der_ecc_nistp521_header_len) < otherPublickeyLen) {
            return 1;
        }
        otherPublickeyLen        = otherPublickeyLen + der_ecc_nistp521_header_len;
        otherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
        break;
    case MBEDTLS_ECP_DP_BP256R1:
        memcpy(otherPublicKey, gecc_der_header_bp256, der_ecc_bp256_header_len);
        if ((SIZE_MAX - der_ecc_bp256_header_len) < otherPublickeyLen) {
            return 1;
        }
        otherPublickeyLen        = otherPublickeyLen + der_ecc_bp256_header_len;
        otherPublickeycipherType = kSSS_CipherType_EC_BRAINPOOL;
        break;
    case MBEDTLS_ECP_DP_BP384R1:
        memcpy(otherPublicKey, gecc_der_header_bp384, der_ecc_bp384_header_len);
        if ((SIZE_MAX - der_ecc_bp384_header_len) < otherPublickeyLen) {
            return 1;
        }
        otherPublickeyLen        = otherPublickeyLen + der_ecc_bp384_header_len;
        otherPublickeycipherType = kSSS_CipherType_EC_BRAINPOOL;
        break;
    case MBEDTLS_ECP_DP_BP512R1:
        memcpy(otherPublicKey, gecc_der_header_bp512, der_ecc_bp512_header_len);
        if ((SIZE_MAX - der_ecc_bp512_header_len) < otherPublickeyLen) {
            return 1;
        }
        otherPublickeyLen        = otherPublickeyLen + der_ecc_bp512_header_len;
        otherPublickeycipherType = kSSS_CipherType_EC_BRAINPOOL;
        break;
    case MBEDTLS_ECP_DP_SECP192K1:
        memcpy(otherPublicKey, gecc_der_header_192k, der_ecc_192k_header_len);
        if ((SIZE_MAX - der_ecc_192k_header_len) < otherPublickeyLen) {
            return 1;
        }
        otherPublickeyLen        = otherPublickeyLen + der_ecc_192k_header_len;
        otherPublickeycipherType = kSSS_CipherType_EC_NIST_K;
        break;
    case MBEDTLS_ECP_DP_SECP224K1:
        memcpy(otherPublicKey, gecc_der_header_224k, der_ecc_224k_header_len);
        if ((SIZE_MAX - der_ecc_224k_header_len) < otherPublickeyLen) {
            return 1;
        }
        otherPublickeyLen        = otherPublickeyLen + der_ecc_224k_header_len;
        otherPublickeycipherType = kSSS_CipherType_EC_NIST_K;
        break;
    case MBEDTLS_ECP_DP_SECP256K1:
        memcpy(otherPublicKey, gecc_der_header_256k, der_ecc_256k_header_len);
        if ((SIZE_MAX - der_ecc_256k_header_len) < otherPublickeyLen) {
            return 1;
        }
        otherPublickeyLen        = otherPublickeyLen + der_ecc_256k_header_len;
        otherPublickeycipherType = kSSS_CipherType_EC_NIST_K;
        break;
    case MBEDTLS_ECP_DP_CURVE25519:
        memcpy(otherPublicKey, gecc_der_header_mont_dh_25519, der_ecc_mont_dh_25519_header_len);
        if ((SIZE_MAX - der_ecc_mont_dh_25519_header_len) < otherPublickeyLen) {
            return 1;
        }
        otherPublickeyLen        = otherPublickeyLen + der_ecc_mont_dh_25519_header_len;
        otherPublickeycipherType = kSSS_CipherType_EC_MONTGOMERY;
        break;
    case MBEDTLS_ECP_DP_CURVE448:
        memcpy(otherPublicKey, gecc_der_header_mont_dh_448, der_ecc_mont_dh_448_header_len);
        if ((SIZE_MAX - der_ecc_mont_dh_448_header_len) < otherPublickeyLen) {
            return 1;
        }
        otherPublickeyLen        = otherPublickeyLen + der_ecc_mont_dh_448_header_len;
        otherPublickeycipherType = kSSS_CipherType_EC_MONTGOMERY;
        break;
    default:
        LOG_I("Unsupported ec group found. Rolling back to software implementation of ecdh");
        return mbedtls_ecdh_compute_shared_o(grp, z, Q, d, f_rng, p_rng);
    }

    if (!g_ecdh_keystore) {
        char *portName = NULL;

        LOG_W(
            "NOTE: The ALT implementation will open and close the session. All transient objects will be lost. \n \
        To avoid the session open in ALT, Use the sss_mbedtls_set_keystore_ecdh() api to pass the se05x keystore and host keystore.");

        /* open session */

        status = ex_sss_boot_connectstring(0, NULL, &portName);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        status = ex_sss_boot_open(&g_se05x_ecdh_session_ctx, portName);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        status = sss_host_session_open(
            &g_se05x_ecdh_session_ctx.host_session, kType_SSS_mbedTLS, 0, kSSS_ConnectionType_Plain, NULL);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        status = ex_sss_key_store_and_object_init(&g_se05x_ecdh_session_ctx);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        status =
            sss_host_key_store_context_init(&g_se05x_ecdh_session_ctx.host_ks, &g_se05x_ecdh_session_ctx.host_session);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        /* Initialise all SSS Objects */

        status = sss_key_object_init(&privateKeyObject, &g_se05x_ecdh_session_ctx.ks);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_object_init(&publicKeyObject, &g_se05x_ecdh_session_ctx.host_ks);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_object_init(&deriveKeyObject, &g_se05x_ecdh_session_ctx.host_ks);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }
    else {
        /* Initialise all SSS Objects */

        status = sss_key_object_init(&privateKeyObject, g_ecdh_keystore);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_object_init(&publicKeyObject, g_ecdh_host_keystore);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_object_init(&deriveKeyObject, g_ecdh_host_keystore);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }

    /* Get handle for key in SE */
    status = sss_key_object_get_handle(&privateKeyObject, key_id);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /* set other party public key in se05x */
    LOG_I("[ECDH] Set Public key in SE05x (Public key id %02x)", publicKeyId);

    status = sss_key_object_allocate_handle(&publicKeyObject,
        publicKeyId,
        kSSS_KeyPart_Public,
        otherPublickeycipherType,
        sizeof(otherPublicKey),
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        publicKeyObject.keyStore, &publicKeyObject, otherPublicKey, otherPublickeyLen, keyBitLen, NULL, 0);
    if (status != kStatus_SSS_Success) {
        LOG_I(
            "The key id might have been used for storing different type of ec key \n. \
            Delete the key and try again OR use a different key id. (SSS_SE05X_TMP_ECC_OTHER_PUBLIC_KEY_ID)");
        goto exit;
    }

    /* SSS object on host to store shared secret */
    status = sss_key_object_allocate_handle(
        &deriveKeyObject, deriveKeyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, 256, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /* Do derive key */
    LOG_I("ECDH using SE05x");

    if (privateKeyObject.keyStore != NULL) {
        status = sss_derive_key_context_init(&ctx_derive_key,
            privateKeyObject.keyStore->session,
            &privateKeyObject,
            kAlgorithm_SSS_ECDH,
            kMode_SSS_ComputeSharedSecret);
    }
    else {
        /* No valid key store */
        status = kStatus_SSS_Fail;
    }
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_derive_key_dh(&ctx_derive_key, &publicKeyObject, &deriveKeyObject);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_store_get_key(deriveKeyObject.keyStore, &deriveKeyObject, buf, &bufByteLen, &bufbitLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    if (grp->id == MBEDTLS_ECP_DP_CURVE25519) {
        ret = mbedtls_mpi_read_binary_le(z, buf, bufByteLen);
    }
    else {
        ret = mbedtls_mpi_read_binary(z, buf, bufByteLen);
    }
    ENSURE_OR_GO_EXIT(ret == 0);

exit:
    if (publicKeyObject.keyStore != NULL) {
        sss_key_object_free(&publicKeyObject);
    }
    if (privateKeyObject.keyStore != NULL) {
        sss_key_object_free(&privateKeyObject);
    }
    if (deriveKeyObject.keyStore != NULL) {
        sss_key_object_free(&deriveKeyObject);
    }
    if (ctx_derive_key.session != NULL) {
        sss_derive_key_context_free(&ctx_derive_key);
    }

    if (g_ecdh_keystore == NULL) {
        LOG_I("Close SE05x session");
        ex_sss_session_close(&g_se05x_ecdh_session_ctx);
    }

    return ret;
}
#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

#endif /* MBEDTLS_ECDH_C */
