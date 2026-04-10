/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "psa_alt_utils.h"

#include <stdio.h>
#include <string.h>

#include "ex_sss_boot.h"
#include "fsl_sss_api.h"
#include "fsl_sss_se05x_apis.h"
#include "fsl_sss_se05x_types.h"
#include "fsl_sss_util_asn1_der.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"
#include "nxEnsure.h"
#include "nxLog_App.h"
#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa_alt.h"
#include "psa_crypto_its.h"
#include "psa_crypto_se.h"
#include "se05x_APDU_apis.h"
#include "sss_psa_alt.h"

extern ex_sss_boot_ctx_t gPsaAltBootCtx;

// case PSA_ECC_CURVE_SECP192R1:         ((psa_ecc_curve_t) 0x0013)
// case PSA_ECC_CURVE_SECP224R1:         ((psa_ecc_curve_t) 0x0015)
// case PSA_ECC_CURVE_SECP256R1:         ((psa_ecc_curve_t) 0x0017)
// case PSA_ECC_CURVE_SECP384R1:         ((psa_ecc_curve_t) 0x0018)
// case PSA_ECC_CURVE_SECP521R1:         ((psa_ecc_curve_t) 0x0019)
// case PSA_ECC_CURVE_BRAINPOOL_P256R1:  ((psa_ecc_curve_t) 0x001a)
// case PSA_ECC_CURVE_BRAINPOOL_P384R1:  ((psa_ecc_curve_t) 0x001b)
// case PSA_ECC_CURVE_BRAINPOOL_P512R1:  ((psa_ecc_curve_t) 0x001c)
// case PSA_ECC_CURVE_SECP160K1:         ((psa_ecc_curve_t) 0x000f)
// case PSA_ECC_CURVE_SECP192K1:         ((psa_ecc_curve_t) 0x0012)
// case PSA_ECC_CURVE_SECP224K1:         ((psa_ecc_curve_t) 0x0014)
// case PSA_ECC_CURVE_SECP256K1:         ((psa_ecc_curve_t) 0x0016)
// case PSA_ECC_CURVE_CURVE25519:        ((psa_ecc_curve_t) 0x001d)     // Bernstein

/************************************************************************
 * Definitions
 ************************************************************************/
#define ID_ECPUBLICKEY                           \
    {                                            \
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 \
    }

static psa_status_t psa_ecc_curve_to_sss_cipher(const psa_ecc_curve_t ecc_curve, sss_cipher_type_t *sss_cipher);

static psa_status_t psa_algorithm_to_ecdsa_sign_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm);

static psa_status_t psa_algorithm_to_rsa_sign_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm);

static psa_status_t psa_algorithm_to_rsa_oaep_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm);

static int SetASNTLV(
    const uint8_t tag, const uint8_t *component, const size_t componentLen, uint8_t *key, size_t *keyLen);

static psa_status_t private_key_to_ec_pk_der(const uint8_t *prv_key,
    const size_t key_size,
    mbedtls_ecp_group_id grp_id,
    uint8_t *key_buffer,
    size_t *keyLen,
    size_t *bits);

static psa_status_t ec_point_to_pubkey_der(const uint8_t *ec_point,
    const size_t param_size,
    mbedtls_ecp_group_id grp_id,
    uint8_t *key_buffer,
    size_t *keyLen,
    size_t *bits);

static psa_status_t cipher_type_to_mbedtls_type(
    const sss_cipher_type_t sss_cipher, const size_t bits, mbedtls_ecp_group_id *grp_id);

static psa_status_t ec_pair_validate_input_size(
    const sss_cipher_type_t sss_cipher, const size_t bits, const size_t data_length);

static psa_status_t ec_pub_validate_input_size(
    const sss_cipher_type_t sss_cipher, const size_t bits, const size_t data_length);

psa_status_t validate_import_data(const sss_cipher_type_t sss_cipher,
    const sss_key_part_t sss_key_part,
    const uint8_t *data,
    const size_t data_length,
    uint8_t *formatted_data,
    size_t *formatted_data_len,
    size_t *bits)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    int ret                 = 0;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (sss_key_part == kSSS_KeyPart_Pair) {
        if (sss_cipher == kSSS_CipherType_RSA_CRT || sss_cipher == kSSS_CipherType_RSA) {
            ret = mbedtls_pk_parse_key(&pk, data, data_length, NULL, 0);
        }
    }
    else if (sss_key_part == kSSS_KeyPart_Public) {
        if (sss_cipher == kSSS_CipherType_RSA_CRT || sss_cipher == kSSS_CipherType_RSA) {
            ret = mbedtls_pk_parse_public_key(&pk, data, data_length);
        }
    }
    else if (sss_key_part == kSSS_KeyPart_Default) {
        if (sss_cipher != kSSS_CipherType_Binary) {
            /* Nothing to do. We are validating size later. */
        }
        else {
            if (data_length > 0x1FFF) {
                psa_status = PSA_ERROR_NOT_SUPPORTED;
                goto cleanup;
            }
            /* Nothing to do. Size can be anything for binary data. */
        }
        *bits      = data_length * 8;
        psa_status = sss_cipher_validate_key_size(sss_cipher, *bits);
        if (psa_status == PSA_SUCCESS) {
            if (*formatted_data_len < data_length) {
                psa_status = PSA_ERROR_BUFFER_TOO_SMALL;
            }
            else {
                memcpy(formatted_data, data, data_length);
                *formatted_data_len = data_length;
            }
        }
        goto cleanup;
    }

    if (ret != 0) {
        psa_status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    if (sss_cipher == kSSS_CipherType_RSA_CRT) {
        mbedtls_pk_type_t pk_type = pk.pk_info->type;
        if (pk_type != MBEDTLS_PK_RSA) {
            psa_status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }
        mbedtls_rsa_context *pk_rsa = mbedtls_pk_rsa(pk);
        *bits                       = pk_rsa->len * 8;
        psa_status                  = sss_cipher_validate_key_size(sss_cipher, *bits);
        if (psa_status == PSA_SUCCESS) {
            if (*formatted_data_len < data_length) {
                psa_status = PSA_ERROR_BUFFER_TOO_SMALL;
            }
            else {
                uint8_t temp[4096] = {0};
                size_t tLen        = sizeof(temp);
                if (sss_key_part == kSSS_KeyPart_Pair) {
                    ret = mbedtls_pk_write_key_der(&pk, temp, tLen);
                }
                else {
                    ret = mbedtls_pk_write_pubkey_der(&pk, temp, tLen);
                }
                if (ret < 0) {
                    psa_status = PSA_ERROR_NOT_SUPPORTED;
                    goto cleanup;
                }
                memcpy(formatted_data, &temp[tLen - ret], ret);
                // memcpy(formatted_data, data, data_length);
                *formatted_data_len = ret;
            }
        }
        // psa_status = PSA_SUCCESS;
    }
    else if (sss_cipher == kSSS_CipherType_EC_NIST_P || sss_cipher == kSSS_CipherType_EC_BRAINPOOL ||
             sss_cipher == kSSS_CipherType_EC_NIST_K || sss_cipher == kSSS_CipherType_EC_MONTGOMERY) {
        /* create formatted key */
        if (sss_key_part == kSSS_KeyPart_Pair) {
            *bits = PSA_BYTES_TO_BITS(data_length);
            /* PSA_BYTES_TO_BITS multiplies the value by 8
            * but sss accepts keyBitLength 521 instead of 528 (66 * 8)
            */
            if (*bits == PSA_BYTES_TO_BITS(KEY_SIZE_BYTE_SECP521R1)) {
                *bits = KEY_SIZE_BITS_SECP521R1;
            }
            mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_NONE;
            psa_status                  = cipher_type_to_mbedtls_type(sss_cipher, *bits, &grp_id);
            if (psa_status != PSA_SUCCESS) {
                goto cleanup;
            }
            psa_status = ec_pair_validate_input_size(sss_cipher, *bits, data_length);
            if (psa_status != PSA_SUCCESS) {
                goto cleanup;
            }
            psa_status = private_key_to_ec_pk_der(data, data_length, grp_id, formatted_data, formatted_data_len, bits);
            if (psa_status != PSA_SUCCESS) {
                goto cleanup;
            }
        }
        else if (sss_key_part == kSSS_KeyPart_Public) {
            *bits = PSA_BYTES_TO_BITS((data_length / 2));
            /* PSA_BYTES_TO_BITS multiplies the value by 8
            * but sss accepts keyBitLength 521 instead of 528 (66 * 8)
            */
            if (*bits == PSA_BYTES_TO_BITS(KEY_SIZE_BYTE_SECP521R1)) {
                *bits = KEY_SIZE_BITS_SECP521R1;
            }

            mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_NONE;

            psa_status = cipher_type_to_mbedtls_type(sss_cipher, *bits, &grp_id);
            if (psa_status != PSA_SUCCESS) {
                goto cleanup;
            }
            psa_status = ec_pub_validate_input_size(sss_cipher, *bits, data_length);
            if (psa_status != PSA_SUCCESS) {
                goto cleanup;
            }

            psa_status = ec_point_to_pubkey_der(data, data_length, grp_id, formatted_data, formatted_data_len, bits);
            if (psa_status != PSA_SUCCESS) {
                goto cleanup;
            }
        }
        psa_status = sss_cipher_validate_key_size(sss_cipher, *bits);
    }

cleanup:
    mbedtls_pk_free(&pk);
    return psa_status;
}

psa_status_t sss_check_if_object_exists(uint32_t key_id)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_object_t sss_object = {0};
    sss_status              = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    sss_status = sss_key_object_get_handle(&sss_object, key_id);
    if (sss_status != kStatus_SSS_Success) {
        psa_status = PSA_ERROR_DOES_NOT_EXIST;
    }
    else {
        psa_status = PSA_SUCCESS;
    }

exit:
    return psa_status;
}

psa_status_t sss_cipher_validate_key_size(const sss_cipher_type_t sss_cipher, size_t key_size)
{
    psa_status_t psa_status = PSA_SUCCESS;
    if (sss_cipher == kSSS_CipherType_RSA_CRT) {
        if ((key_size != 512) && (key_size != 1024) && (key_size != 2048) && (key_size != 3072) && (key_size != 4096)) {
            LOG_E("Key Size not supported");
            psa_status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
    else if (sss_cipher == kSSS_CipherType_EC_NIST_P) {
        if ((key_size != 192) && (key_size != 224) && (key_size != 256) && (key_size != 384) && (key_size != 521)) {
            LOG_E("Key Size not supported");
            psa_status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
    else if (sss_cipher == kSSS_CipherType_EC_NIST_K) {
        if ((key_size != 160) && (key_size != 192) && (key_size != 224) && (key_size != 256)) {
            LOG_E("Key Size not supported");
            psa_status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
    else if (sss_cipher == kSSS_CipherType_EC_BRAINPOOL) {
        if ((key_size != 256) && (key_size != 384) && (key_size != 512)) {
            LOG_E("Key Size not supported");
            psa_status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
    else if (sss_cipher == kSSS_CipherType_AES) {
        if ((key_size != 128) && (key_size != 192) && (key_size != 256)) {
            LOG_E("Key Size not supported");
            psa_status = PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (sss_cipher == kSSS_CipherType_HMAC) {
        if (key_size > (256 /* Max byte key supported */ * 8)) {
            LOG_E("Key Size not supported");
            psa_status = PSA_ERROR_NOT_SUPPORTED;
        }
    }

    return psa_status;
}

psa_status_t psa_key_type_to_sss_cipher(
    psa_key_type_t psa_key_type, sss_cipher_type_t *sss_cipher, sss_key_part_t *sss_key_part)
{
    psa_status_t psa_status = PSA_ERROR_NOT_SUPPORTED;

    if (psa_key_type == PSA_KEY_TYPE_RSA_PUBLIC_KEY) {
        *sss_cipher   = kSSS_CipherType_RSA_CRT;
        *sss_key_part = kSSS_KeyPart_Public;
        psa_status    = PSA_SUCCESS;
    }
    else if (psa_key_type == PSA_KEY_TYPE_RSA_KEY_PAIR) {
        *sss_cipher   = kSSS_CipherType_RSA_CRT;
        *sss_key_part = kSSS_KeyPart_Pair;
        psa_status    = PSA_SUCCESS;
    }
    else if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(psa_key_type)) {
        psa_ecc_family_t ecc_curve = PSA_KEY_TYPE_GET_CURVE(psa_key_type);
        psa_status                 = psa_ecc_curve_to_sss_cipher(ecc_curve, sss_cipher);
        if (psa_status != PSA_SUCCESS) {
            goto exit;
        }
        *sss_key_part = kSSS_KeyPart_Pair;
        psa_status    = PSA_SUCCESS;
    }
    else if (PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(psa_key_type)) {
        psa_ecc_family_t ecc_curve = PSA_KEY_TYPE_GET_CURVE(psa_key_type);
        psa_status                 = psa_ecc_curve_to_sss_cipher(ecc_curve, sss_cipher);
        if (psa_status != PSA_SUCCESS) {
            goto exit;
        }
        *sss_key_part = kSSS_KeyPart_Public;
        psa_status    = PSA_SUCCESS;
    }
    else if (psa_key_type == PSA_KEY_TYPE_AES) {
        *sss_cipher   = kSSS_CipherType_AES;
        *sss_key_part = kSSS_KeyPart_Default;
        psa_status    = PSA_SUCCESS;
    }
    else if (psa_key_type == PSA_KEY_TYPE_DES) {
        *sss_cipher   = kSSS_CipherType_DES;
        *sss_key_part = kSSS_KeyPart_Default;
        psa_status    = PSA_SUCCESS;
    }
    else if (psa_key_type == PSA_KEY_TYPE_HMAC) {
        *sss_cipher   = kSSS_CipherType_HMAC;
        *sss_key_part = kSSS_KeyPart_Default;
        psa_status    = PSA_SUCCESS;
    }
    else if (psa_key_type == PSA_KEY_TYPE_RAW_DATA) {
        *sss_cipher   = kSSS_CipherType_Binary;
        *sss_key_part = kSSS_KeyPart_Default;
        psa_status    = PSA_SUCCESS;
    }

exit:
    return psa_status;
}

psa_status_t generate_random_symmetric_key(uint8_t *key, size_t *bufferLen, const size_t keyLen)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status = kStatus_SSS_Fail;
    if (*bufferLen < keyLen) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    sss_rng_context_t rng_ctx;

    sss_status = sss_rng_context_init(&rng_ctx, &gPsaAltBootCtx.session);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    sss_status = sss_rng_get_random(&rng_ctx, key, keyLen);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    *bufferLen = keyLen;
    psa_status = PSA_SUCCESS;

exit:
    return psa_status;
}

psa_status_t psa_algorithm_to_sss_algorithm(const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm)
{
    psa_status_t psa_status = PSA_ERROR_NOT_SUPPORTED;

    if (PSA_ALG_IS_RANDOMIZED_ECDSA(psa_algorithm)) {
        psa_status = psa_algorithm_to_ecdsa_sign_algorithm(psa_algorithm, sss_algorithm);
    }
    /* RSA Sign algorithm - no padding - no hash not supported */
    else if (psa_algorithm == PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
        /* PKCS1_V1_5 padding with no hash.
           Check this first because this condition will be true as a part of next else if also */
        *sss_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH;
        psa_status     = PSA_SUCCESS;
    }
    else if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(psa_algorithm) || PSA_ALG_IS_RSA_PSS(psa_algorithm)) {
        psa_status = psa_algorithm_to_rsa_sign_algorithm(psa_algorithm, sss_algorithm);
    }
    else if (psa_algorithm == PSA_ALG_RSA_PKCS1V15_CRYPT) {
        *sss_algorithm = kAlgorithm_SSS_RSAES_PKCS1_V1_5;
        psa_status     = PSA_SUCCESS;
    }
    else if (PSA_ALG_IS_RSA_OAEP(psa_algorithm)) {
        psa_status = psa_algorithm_to_rsa_oaep_algorithm(psa_algorithm, sss_algorithm);
    }
    /* TODO: Update for symmetric operations */

    return psa_status;
}

static psa_status_t psa_algorithm_to_ecdsa_sign_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm)
{
    psa_status_t psa_status        = PSA_ERROR_GENERIC_ERROR;
    psa_algorithm_t hash_algorithm = psa_algorithm & PSA_ALG_HASH_MASK;
    switch (hash_algorithm) {
    /** SHA1 */
    case (PSA_ALG_SHA_1 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_ECDSA_SHA1;
        psa_status     = PSA_SUCCESS;
        break;
    /** SHA2-224 */
    case (PSA_ALG_SHA_224 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_ECDSA_SHA224;
        psa_status     = PSA_SUCCESS;
        break;
    /** SHA2-256 */
    case (PSA_ALG_SHA_256 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_ECDSA_SHA256;
        psa_status     = PSA_SUCCESS;
        break;
    /** SHA2-384 */
    case (PSA_ALG_SHA_384 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_ECDSA_SHA384;
        psa_status     = PSA_SUCCESS;
        break;
    /** SHA2-512 */
    case (PSA_ALG_SHA_512 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_ECDSA_SHA512;
        psa_status     = PSA_SUCCESS;
        break;
    default:
        psa_status = PSA_ERROR_NOT_SUPPORTED;
    }
    return psa_status;
}

static psa_status_t psa_algorithm_to_rsa_sign_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm)
{
    psa_status_t psa_status        = PSA_ERROR_GENERIC_ERROR;
    psa_algorithm_t hash_algorithm = psa_algorithm & PSA_ALG_HASH_MASK;
    if (!PSA_ALG_IS_RSA_PKCS1V15_SIGN(psa_algorithm) && !PSA_ALG_IS_RSA_PSS(psa_algorithm)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    switch (hash_algorithm) {
    /** SHA1 */
    case (PSA_ALG_SHA_1 & PSA_ALG_HASH_MASK):
        *sss_algorithm = PSA_ALG_IS_RSA_PKCS1V15_SIGN(psa_algorithm) ? kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1 :
                                                                       kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1;
        psa_status     = PSA_SUCCESS;
        break;
    /** SHA2-224 */
    case (PSA_ALG_SHA_224 & PSA_ALG_HASH_MASK):
        *sss_algorithm = PSA_ALG_IS_RSA_PKCS1V15_SIGN(psa_algorithm) ? kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224 :
                                                                       kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA224;
        psa_status     = PSA_SUCCESS;
        break;
    /** SHA2-256 */
    case (PSA_ALG_SHA_256 & PSA_ALG_HASH_MASK):
        *sss_algorithm = PSA_ALG_IS_RSA_PKCS1V15_SIGN(psa_algorithm) ? kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256 :
                                                                       kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256;
        psa_status     = PSA_SUCCESS;
        break;
    /** SHA2-384 */
    case (PSA_ALG_SHA_384 & PSA_ALG_HASH_MASK):
        *sss_algorithm = PSA_ALG_IS_RSA_PKCS1V15_SIGN(psa_algorithm) ? kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384 :
                                                                       kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384;
        psa_status     = PSA_SUCCESS;
        break;
    /** SHA2-512 */
    case (PSA_ALG_SHA_512 & PSA_ALG_HASH_MASK):
        *sss_algorithm = PSA_ALG_IS_RSA_PKCS1V15_SIGN(psa_algorithm) ? kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512 :
                                                                       kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512;
        psa_status     = PSA_SUCCESS;
        break;
    default:
        psa_status = PSA_ERROR_NOT_SUPPORTED;
    }
    return psa_status;
}

static psa_status_t psa_algorithm_to_rsa_oaep_algorithm(
    const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm)
{
    psa_status_t psa_status        = PSA_ERROR_GENERIC_ERROR;
    psa_algorithm_t hash_algorithm = psa_algorithm & PSA_ALG_HASH_MASK;
    switch (hash_algorithm) {
    /** SHA1 */
    case (PSA_ALG_SHA_1 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1;
        psa_status     = PSA_SUCCESS;
        break;
    /** SHA2-224 */
    case (PSA_ALG_SHA_224 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA224;
        /* Currently not supported by SE05X */
        psa_status = PSA_ERROR_NOT_SUPPORTED;
        break;
    /** SHA2-256 */
    case (PSA_ALG_SHA_256 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256;
        /* Currently not supported by SE05X */
        psa_status = PSA_ERROR_NOT_SUPPORTED;
        break;
    /** SHA2-384 */
    case (PSA_ALG_SHA_384 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA384;
        /* Currently not supported by SE05X */
        psa_status = PSA_ERROR_NOT_SUPPORTED;
        break;
    /** SHA2-512 */
    case (PSA_ALG_SHA_512 & PSA_ALG_HASH_MASK):
        *sss_algorithm = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA512;
        /* Currently not supported by SE05X */
        psa_status = PSA_ERROR_NOT_SUPPORTED;
        break;
    default:
        psa_status = PSA_ERROR_NOT_SUPPORTED;
    }
    return psa_status;
}

static psa_status_t psa_ecc_curve_to_sss_cipher(const psa_ecc_curve_t ecc_curve, sss_cipher_type_t *sss_cipher)
{
    psa_status_t psa_status = PSA_SUCCESS;
    switch (ecc_curve) {
    case PSA_ECC_FAMILY_SECP_R1:
        *sss_cipher = kSSS_CipherType_EC_NIST_P;
        break;
    case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
        *sss_cipher = kSSS_CipherType_EC_BRAINPOOL;
        break;
    case PSA_ECC_FAMILY_SECP_K1:
        *sss_cipher = kSSS_CipherType_EC_NIST_K;
        break;
    case PSA_ECC_FAMILY_MONTGOMERY:
        *sss_cipher = kSSS_CipherType_EC_MONTGOMERY;
        break;
    default:
        LOG_E("Curve not supported");
        psa_status = PSA_ERROR_NOT_SUPPORTED;
    }
    return psa_status;
}

/*
 This is a simple function to insert a TLV into a buffer.
 params:
    tag             - ASN.1 Tag
    component       - byte array to be inserted
    componentLen    - Size of component to be inserted
    key             - Buffer into which component will be inserted
    keyLen          - Size of the buffer (key)

 Note : This function inserts the component at the end of the buffer and updates the
        keyLen to where the component is inserted with tag. (Points to the tag)
*/
static int SetASNTLV(
    const uint8_t tag, const uint8_t *component, const size_t componentLen, uint8_t *key, size_t *keyLen)
{
    if (componentLen <= 0) {
        return 1;
    }

    if (*keyLen < componentLen) {
        return 1;
    }

    *keyLen = *keyLen - componentLen;
    memcpy(&key[*keyLen], component, componentLen);

    if (componentLen <= 127) {
        if (*keyLen < 1) {
            return 1;
        }
        *keyLen      = *keyLen - 1;
        key[*keyLen] = (uint8_t)componentLen;
    }
    else if (componentLen <= 255) {
        if (*keyLen < 2) {
            return 1;
        }
        *keyLen          = *keyLen - 2;
        key[*keyLen]     = 0x81;
        key[*keyLen + 1] = (uint8_t)componentLen;
    }
    else {
        if (*keyLen < 3) {
            return 1;
        }
        *keyLen          = *keyLen - 3;
        key[*keyLen]     = 0x82;
        key[*keyLen + 1] = (componentLen & 0x00FF00) >> 8;
        key[*keyLen + 2] = (componentLen & 0x00FF);
    }

    if (*keyLen < 1) {
        return 1;
    }
    *keyLen = *keyLen - 1;

    key[*keyLen] = tag;

    return 0;
}

static psa_status_t private_key_to_ec_pk_der(const uint8_t *prv_key,
    const size_t key_size,
    mbedtls_ecp_group_id grp_id,
    uint8_t *key_buffer,
    size_t *keyLen,
    size_t *bits)
{
    int result             = 0;
    uint8_t key[1024]      = {0};
    size_t bufferSize_copy = *keyLen;
    size_t parameterLen    = 0;
    uint8_t tag            = ASN_TAG_CRL_EXTENSIONS;
    uint8_t oid[20]        = {0};
    oid[0]                 = ASN_TAG_OBJ_IDF;
    size_t oidLen          = 1;

    /* Set EC Params manually. Parse key type and set EC_PARAM */
    if (grp_id == MBEDTLS_ECP_DP_SECP192R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP192R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_SECP224R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP224R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_SECP256R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP256R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_SECP384R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP384R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_SECP521R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP521R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    /* NISTK */
    else if (grp_id == MBEDTLS_ECP_DP_SECP192K1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP192K1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_SECP224K1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP224K1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_SECP256K1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP256K1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    /* BP */
    else if (grp_id == MBEDTLS_ECP_DP_BP256R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_BP256R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_BP384R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_BP384R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_BP512R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_BP512R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_CURVE25519) {
        return PSA_SUCCESS;
        // uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_BP512R1;
        // parameterLen     = sizeof(ec_oid) - 1;
        // oid[1]           = (uint8_t)parameterLen;
        // memcpy(&oid[2], ec_oid, parameterLen);
        // oidLen = oidLen + parameterLen + 1;
    }
    else {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    result = SetASNTLV(tag, oid, oidLen, key, keyLen);

    if (result != 0) {
        goto exit;
    }

    tag    = ASN_TAG_OCTETSTRING;
    result = SetASNTLV(tag, prv_key, key_size, key, keyLen);
    if (result != 0) {
        goto exit;
    }

    tag             = ASN_TAG_INT;
    uint8_t int_val = 0x01;
    result          = SetASNTLV(tag, &int_val, 1, key, keyLen);
    if (result != 0) {
        goto exit;
    }

    size_t totalLen = bufferSize_copy - *keyLen;

    if (totalLen <= 127) {
        if (*keyLen < 1) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        *keyLen      = *keyLen - 1;
        key[*keyLen] = (uint8_t)totalLen;
    }
    else if (totalLen <= 255) {
        if (*keyLen < 2) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        *keyLen          = *keyLen - 2;
        key[*keyLen]     = 0x81;
        key[*keyLen + 1] = (uint8_t)totalLen;
    }
    else {
        if (*keyLen < 3) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        *keyLen          = *keyLen - 3;
        key[*keyLen]     = 0x82;
        key[*keyLen + 1] = (totalLen & 0x00FF00) >> 8;
        key[*keyLen + 2] = (totalLen & 0x00FF);
    }

    if (*keyLen < 1) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    *keyLen = *keyLen - 1;

    key[*keyLen] = ASN_TAG_SEQUENCE;

    totalLen = bufferSize_copy - *keyLen;

    uint8_t temp[1024] = {0};
    size_t tLen        = sizeof(temp);
    int ret            = 0;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_key(&pk, &key[*keyLen], totalLen, NULL, 0);
    if (ret != 0) {
        result = 1;
        mbedtls_pk_free(&pk);
        goto exit;
    }
    ret = mbedtls_pk_write_key_der(&pk, temp, tLen);
    if (ret < 0) {
        result = 1;
        mbedtls_pk_free(&pk);
        goto exit;
    }

    mbedtls_pk_free(&pk);

    memcpy(&key_buffer[0], &temp[tLen - ret], ret);
    *keyLen = ret;

exit:
    if (result == 0) {
        return PSA_SUCCESS;
    }
    else {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

static psa_status_t ec_point_to_pubkey_der(const uint8_t *ec_point,
    const size_t param_size,
    mbedtls_ecp_group_id grp_id,
    uint8_t *key_buffer,
    size_t *keyLen,
    size_t *bits)
{
    int result             = 0;
    uint8_t key[1024]      = {0};
    size_t bufferSize_copy = *keyLen;
    size_t parameterLen    = 0;
    uint8_t tag            = ASN_TAG_BITSTRING;
    uint8_t oid[20]        = {0};
    oid[0]                 = ASN_TAG_OBJ_IDF;
    size_t oidLen          = 1;

    /* Set EC Params manually. Parse key type and set EC_PARAM */
    if (grp_id == MBEDTLS_ECP_DP_SECP192R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP192R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_SECP224R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP224R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_SECP256R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP256R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_SECP384R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP384R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_SECP521R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP521R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    /* NISTK */
    else if (grp_id == MBEDTLS_ECP_DP_SECP192K1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP192K1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_SECP224K1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP224K1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_SECP256K1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_SECP256K1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    /* BP */
    else if (grp_id == MBEDTLS_ECP_DP_BP256R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_BP256R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_BP384R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_BP384R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else if (grp_id == MBEDTLS_ECP_DP_BP512R1) {
        uint8_t ec_oid[] = MBEDTLS_OID_EC_GRP_BP512R1;
        parameterLen     = sizeof(ec_oid) - 1;
        oid[1]           = (uint8_t)parameterLen;
        memcpy(&oid[2], ec_oid, parameterLen);
        oidLen = oidLen + parameterLen + 1;
    }
    else {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t encoded_ec_point[150] = {0};
    memcpy(&encoded_ec_point[1], ec_point, param_size);

    result = SetASNTLV(tag, encoded_ec_point, param_size + 1, key, keyLen);
    if (result != 0) {
        goto exit;
    }

    uint8_t ecPubParams[50] = {0};
    size_t ecPubParams_size = sizeof(ecPubParams);
    tag                     = ASN_TAG_OBJ_IDF;

    result = SetASNTLV(tag, &oid[2], oid[1], ecPubParams, &ecPubParams_size);
    if (result != 0) {
        goto exit;
    }

    uint8_t id_ecPublicKey[] = ID_ECPUBLICKEY;
    result                   = SetASNTLV(tag, id_ecPublicKey, sizeof(id_ecPublicKey), ecPubParams, &ecPubParams_size);
    if (result != 0) {
        goto exit;
    }

    tag = ASN_TAG_SEQUENCE;

    result = SetASNTLV(tag, &ecPubParams[ecPubParams_size], sizeof(ecPubParams) - ecPubParams_size, key, keyLen);
    if (result != 0) {
        goto exit;
    }

    size_t totalLen = bufferSize_copy - *keyLen;

    if (totalLen <= 127) {
        if (*keyLen < 1) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        *keyLen      = *keyLen - 1;
        key[*keyLen] = (uint8_t)totalLen;
    }
    else if (totalLen <= 255) {
        if (*keyLen < 2) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        *keyLen          = *keyLen - 2;
        key[*keyLen]     = 0x81;
        key[*keyLen + 1] = (uint8_t)totalLen;
    }
    else {
        if (*keyLen < 3) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        *keyLen          = *keyLen - 3;
        key[*keyLen]     = 0x82;
        key[*keyLen + 1] = (totalLen & 0x00FF00) >> 8;
        key[*keyLen + 2] = (totalLen & 0x00FF);
    }

    if (*keyLen < 1) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    *keyLen = *keyLen - 1;

    key[*keyLen] = ASN_TAG_SEQUENCE;
    totalLen     = bufferSize_copy - *keyLen;

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int ret = mbedtls_pk_parse_public_key(&pk, &key[*keyLen], totalLen);
    if (ret != 0) {
        result = 1;
        mbedtls_pk_free(&pk);
        goto exit;
    }

    memcpy(&key_buffer[0], &key[*keyLen], totalLen);
    *keyLen = totalLen;
    mbedtls_pk_free(&pk);

exit:
    if (result == 0) {
        return PSA_SUCCESS;
    }
    else {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

static psa_status_t cipher_type_to_mbedtls_type(
    const sss_cipher_type_t sss_cipher, const size_t bits, mbedtls_ecp_group_id *grp_id)
{
    psa_status_t psa_status = PSA_SUCCESS;
    if (sss_cipher == kSSS_CipherType_EC_NIST_P) {
        switch (bits) {
        case KEY_SIZE_BITS_SECP192R1:
            *grp_id = MBEDTLS_ECP_DP_SECP192R1;
            break;
        case KEY_SIZE_BITS_SECP224R1:
            *grp_id = MBEDTLS_ECP_DP_SECP224R1;
            break;
        case KEY_SIZE_BITS_SECP256R1:
            *grp_id = MBEDTLS_ECP_DP_SECP256R1;
            break;
        case KEY_SIZE_BITS_SECP384R1:
            *grp_id = MBEDTLS_ECP_DP_SECP384R1;
            break;
        case KEY_SIZE_BITS_SECP521R1:
            *grp_id = MBEDTLS_ECP_DP_SECP521R1;
            break;
        default:
            psa_status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        }
    }
    else if (sss_cipher == kSSS_CipherType_EC_NIST_K) {
        switch (bits) {
        case KEY_SIZE_BITS_SECK160R1:
            // *grp_id = MBEDTLS_ECP_DP_SECP192R1;
            psa_status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        case KEY_SIZE_BITS_SECK192R1:
            *grp_id = MBEDTLS_ECP_DP_SECP192K1;
            break;
        case KEY_SIZE_BITS_SECK224R1:
            *grp_id = MBEDTLS_ECP_DP_SECP224K1;
            break;
        case KEY_SIZE_BITS_SECK256R1:
            *grp_id = MBEDTLS_ECP_DP_SECP256K1;
            break;
        default:
            psa_status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        }
    }
    else if (sss_cipher == kSSS_CipherType_EC_BRAINPOOL) {
        switch (bits) {
        case KEY_SIZE_BITS_BP256R1:
            *grp_id = MBEDTLS_ECP_DP_BP256R1;
            break;
        case KEY_SIZE_BITS_BP384R1:
            *grp_id = MBEDTLS_ECP_DP_BP384R1;
            break;
        case KEY_SIZE_BITS_BP512R1:
            *grp_id = MBEDTLS_ECP_DP_BP512R1;
            break;
        default:
            psa_status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        }
    }
    else if (sss_cipher == kSSS_CipherType_EC_MONTGOMERY) {
        switch (bits) {
        case KEY_SIZE_BITS_CURVE25519:
            *grp_id = MBEDTLS_ECP_DP_CURVE25519;
            break;
        default:
            psa_status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        }
    }

cleanup:
    return psa_status;
}

static psa_status_t ec_pair_validate_input_size(
    const sss_cipher_type_t sss_cipher, const size_t bits, const size_t data_length)
{
    psa_status_t psa_status = PSA_SUCCESS;
    if (sss_cipher == kSSS_CipherType_EC_NIST_P) {
        switch (bits) {
        case KEY_SIZE_BITS_SECP192R1:
            if (data_length != KEY_SIZE_BYTE_SECP192R1) {
                psa_status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case KEY_SIZE_BITS_SECP224R1:
            if (data_length != KEY_SIZE_BYTE_SECP224R1) {
                psa_status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case KEY_SIZE_BITS_SECP256R1:
            if (data_length != KEY_SIZE_BYTE_SECP256R1) {
                psa_status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case KEY_SIZE_BITS_SECP384R1:
            if (data_length != KEY_SIZE_BYTE_SECP384R1) {
                psa_status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case KEY_SIZE_BITS_SECP521R1:
            if (data_length != KEY_SIZE_BYTE_SECP521R1) {
                psa_status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        default:
            psa_status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }
    }
    else if (sss_cipher == kSSS_CipherType_EC_NIST_K) {
        switch (bits) {
        case KEY_SIZE_BITS_SECK160R1:
            // if(data_length != KEY_SIZE_BYTE_SECK160R1) {
            //     psa_status = PSA_ERROR_INVALID_ARGUMENT;
            // }
            psa_status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        case KEY_SIZE_BITS_SECK192R1:
            if (data_length != KEY_SIZE_BYTE_SECK192R1) {
                psa_status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case KEY_SIZE_BITS_SECK224R1:
            if (data_length != KEY_SIZE_BYTE_SECK224R1) {
                psa_status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case KEY_SIZE_BITS_SECK256R1:
            if (data_length != KEY_SIZE_BYTE_SECK256R1) {
                psa_status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        default:
            psa_status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }
    }
    else if (sss_cipher == kSSS_CipherType_EC_BRAINPOOL) {
        switch (bits) {
        case KEY_SIZE_BITS_BP256R1:
            if (data_length != KEY_SIZE_BYTE_BP256R1) {
                psa_status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case KEY_SIZE_BITS_BP384R1:
            if (data_length != KEY_SIZE_BYTE_BP384R1) {
                psa_status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case KEY_SIZE_BITS_BP512R1:
            if (data_length != KEY_SIZE_BYTE_BP512R1) {
                psa_status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        default:
            psa_status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }
    }
    else if (sss_cipher == kSSS_CipherType_EC_MONTGOMERY) {
        switch (bits) {
        case KEY_SIZE_BITS_CURVE25519:
            if (data_length != KEY_SIZE_BYTE_CURVE25519) {
                psa_status = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        default:
            psa_status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }
    }

cleanup:
    return psa_status;
}

static psa_status_t ec_pub_validate_input_size(
    const sss_cipher_type_t sss_cipher, const size_t bits, const size_t data_length)
{
    psa_status_t psa_status = PSA_SUCCESS;
    if (sss_cipher == kSSS_CipherType_EC_NIST_P) {
        switch (bits) {
        case KEY_SIZE_BITS_SECP192R1:
            if (data_length != ((KEY_SIZE_BYTE_SECP192R1 * 2) /* One byte for 0x04 */ + 1)) {
                psa_status = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        case KEY_SIZE_BITS_SECP224R1:
            if (data_length != ((KEY_SIZE_BYTE_SECP224R1 * 2) /* One byte for 0x04 */ + 1)) {
                psa_status = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        case KEY_SIZE_BITS_SECP256R1:
            if (data_length != ((KEY_SIZE_BYTE_SECP256R1 * 2) /* One byte for 0x04 */ + 1)) {
                psa_status = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        case KEY_SIZE_BITS_SECP384R1:
            if (data_length != ((KEY_SIZE_BYTE_SECP384R1 * 2) /* One byte for 0x04 */ + 1)) {
                psa_status = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        case KEY_SIZE_BITS_SECP521R1:
            if (data_length != ((KEY_SIZE_BYTE_SECP521R1 * 2) /* One byte for 0x04 */ + 1)) {
                psa_status = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        default:
            psa_status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        }
    }
    if (sss_cipher == kSSS_CipherType_EC_NIST_K) {
        switch (bits) {
        case KEY_SIZE_BITS_SECK160R1:
            // if(data_length != ((KEY_SIZE_BYTE_SECK160R1 * 2) /* One byte for 0x04 */ + 1)) {
            //     psa_status = PSA_ERROR_NOT_SUPPORTED;
            // }
            psa_status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        case KEY_SIZE_BITS_SECK192R1:
            if (data_length != ((KEY_SIZE_BYTE_SECK192R1 * 2) /* One byte for 0x04 */ + 1)) {
                psa_status = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        case KEY_SIZE_BITS_SECK224R1:
            if (data_length != ((KEY_SIZE_BYTE_SECK224R1 * 2) /* One byte for 0x04 */ + 1)) {
                psa_status = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        case KEY_SIZE_BITS_SECK256R1:
            if (data_length != ((KEY_SIZE_BYTE_SECK256R1 * 2) /* One byte for 0x04 */ + 1)) {
                psa_status = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        default:
            psa_status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        }
    }
    if (sss_cipher == kSSS_CipherType_EC_BRAINPOOL) {
        switch (bits) {
        case KEY_SIZE_BITS_BP256R1:
            if (data_length != ((KEY_SIZE_BYTE_BP256R1 * 2) /* One byte for 0x04 */ + 1)) {
                psa_status = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        case KEY_SIZE_BITS_BP384R1:
            if (data_length != ((KEY_SIZE_BYTE_BP384R1 * 2) /* One byte for 0x04 */ + 1)) {
                psa_status = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        case KEY_SIZE_BITS_BP512R1:
            if (data_length != ((KEY_SIZE_BYTE_BP512R1 * 2) /* One byte for 0x04 */ + 1)) {
                psa_status = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        default:
            psa_status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        }
    }

cleanup:
    return psa_status;
}

psa_status_t sss_validate_buffer_size(uint32_t key_id, size_t buffer_len)
{
    sss_status_t sss_status          = kStatus_SSS_Fail;
    smStatus_t status                = SM_NOT_OK;
    psa_status_t psa_status          = PSA_ERROR_GENERIC_ERROR;
    sss_object_t sss_object          = {0};
    sss_se05x_object_t *se05x_object = (sss_se05x_object_t *)(&sss_object);
    sss_se05x_key_store_t *se05x_ks  = (sss_se05x_key_store_t *)(&gPsaAltBootCtx.ks);
    uint16_t size                    = 0;

    sss_status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    sss_status = sss_key_object_get_handle(&sss_object, key_id);
    if (sss_status != kStatus_SSS_Success) {
        psa_status = PSA_ERROR_DOES_NOT_EXIST;
        goto exit;
    }

    status = Se05x_API_ReadSize(&se05x_ks->session->s_ctx, se05x_object->keyId, &size);
    if (status != SM_OK) {
        psa_status = PSA_ERROR_DOES_NOT_EXIST;
    }
    else if (buffer_len < size) {
        psa_status = PSA_ERROR_BUFFER_TOO_SMALL;
    }
    else {
        psa_status = PSA_SUCCESS;
    }

exit:
    return psa_status;
}

psa_status_t fill_export_data_buffer(
    const uint32_t key_id, const uint8_t *export_data, size_t *p_data_length, uint8_t *p_data, const size_t data_length)
{
    psa_status_t psa_status = PSA_ERROR_DOES_NOT_EXIST;
    sss_status_t sss_status = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    sss_status              = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    sss_status = sss_key_object_get_handle(&sss_object, key_id);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    if (sss_object.cipherType == kSSS_CipherType_RSA_CRT || sss_object.cipherType == kSSS_CipherType_RSA) {
        uint8_t tag            = ASN_TAG_INT;
        uint8_t buff[1024]     = {0};
        size_t buffLen         = sizeof(buff);
        size_t bufferSize_copy = buffLen;
        uint8_t rsaN[513]      = {0};
        uint8_t rsaE[10]       = {0};
        size_t rsaNLen         = sizeof(rsaN);
        size_t rsaELen         = sizeof(rsaE);
        sss_status             = sss_util_asn1_rsa_parse_public_nomalloc_complete_modulus(
            export_data, *p_data_length, rsaN, &rsaNLen, rsaE, &rsaELen);
        if (sss_status != kStatus_SSS_Success) {
            *p_data_length = 0;
            psa_status     = PSA_ERROR_DATA_CORRUPT;
            goto exit;
        }

        if (0 != SetASNTLV(tag, rsaE, rsaELen, buff, &buffLen)) {
            *p_data_length = 0;
            psa_status     = PSA_ERROR_DATA_CORRUPT;
            goto exit;
        }
        if (0 != SetASNTLV(tag, rsaN, rsaNLen, buff, &buffLen)) {
            *p_data_length = 0;
            psa_status     = PSA_ERROR_DATA_CORRUPT;
            goto exit;
        }
        size_t totalLen = bufferSize_copy - buffLen;

        if (totalLen <= 127) {
            if (buffLen < 1) {
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }
            buffLen       = buffLen - 1;
            buff[buffLen] = (uint8_t)totalLen;
        }
        else if (totalLen <= 255) {
            if (buffLen < 2) {
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }
            buffLen           = buffLen - 2;
            buff[buffLen]     = 0x81;
            buff[buffLen + 1] = (uint8_t)totalLen;
        }
        else {
            if (buffLen < 3) {
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }
            buffLen           = buffLen - 3;
            buff[buffLen]     = 0x82;
            buff[buffLen + 1] = (totalLen & 0x00FF00) >> 8;
            buff[buffLen + 2] = (totalLen & 0x00FF);
        }

        if (buffLen < 1) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        buffLen = buffLen - 1;

        buff[buffLen] = ASN_TAG_SEQUENCE;

        totalLen = bufferSize_copy - buffLen;
        if (data_length < totalLen) {
            *p_data_length = 0;
            psa_status     = PSA_ERROR_BUFFER_TOO_SMALL;
            goto exit;
        }

        memcpy(p_data, &buff[buffLen], totalLen);
        *p_data_length = totalLen;
        psa_status     = PSA_SUCCESS;
    }
    else if (sss_object.cipherType == kSSS_CipherType_EC_NIST_P || sss_object.cipherType == kSSS_CipherType_EC_NIST_K ||
             sss_object.cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        uint16_t pubKeyIndex = 0;
        size_t pubKeyLen     = 0;
        sss_status = sss_util_pkcs8_asn1_get_ec_public_key_index(export_data, *p_data_length, &pubKeyIndex, &pubKeyLen);
        if (sss_status != kStatus_SSS_Success) {
            *p_data_length = 0;
            psa_status     = PSA_ERROR_DATA_CORRUPT;
            goto exit;
        }
        if (data_length < pubKeyLen) {
            *p_data_length = 0;
            psa_status     = PSA_ERROR_BUFFER_TOO_SMALL;
            goto exit;
        }
        memcpy(p_data, &export_data[pubKeyIndex], pubKeyLen);
        *p_data_length = pubKeyLen;
        psa_status     = PSA_SUCCESS;
    }
    else {
        memcpy(p_data, export_data, *p_data_length);
        psa_status = PSA_SUCCESS;
    }

exit:
    return psa_status;
}

psa_status_t validate_sign_input_data(
    uint32_t key_id, const psa_algorithm_t psa_algorithm, const uint8_t *input, size_t data_len)
{
    psa_status_t psa_status          = PSA_ERROR_INVALID_ARGUMENT;
    sss_status_t sss_status          = kStatus_SSS_Fail;
    smStatus_t ret_val               = SM_NOT_OK;
    sss_object_t sss_object          = {0};
    sss_se05x_object_t *se05x_object = (sss_se05x_object_t *)(&sss_object);
    sss_se05x_key_store_t *se05x_ks  = (sss_se05x_key_store_t *)(&gPsaAltBootCtx.ks);
    uint16_t key_size_bytes          = 0;

    sss_status = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    sss_status = sss_key_object_get_handle(&sss_object, key_id);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    ret_val = Se05x_API_ReadSize(&se05x_ks->session->s_ctx, se05x_object->keyId, &key_size_bytes);
    if (ret_val != SM_OK) {
        psa_status = PSA_ERROR_HARDWARE_FAILURE;
        goto exit;
    }

    if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(psa_algorithm) || psa_algorithm == PSA_ALG_RSA_PKCS1V15_CRYPT) {
        psa_status = (key_size_bytes > (data_len + 11)) ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    else if (PSA_ALG_IS_RSA_PSS(psa_algorithm)) {
        psa_algorithm_t hash_algorithm = psa_algorithm & PSA_ALG_HASH_MASK;
        size_t hash_length;
        switch (hash_algorithm) {
        /** SHA1 */
        case (PSA_ALG_SHA_1 & PSA_ALG_HASH_MASK):
            hash_length = HASH_LENGTH_BYTE_SHA1;
            break;

        /** SHA2-224 */
        case (PSA_ALG_SHA_224 & PSA_ALG_HASH_MASK):
            hash_length = HASH_LENGTH_BYTE_SHA224;
            break;

        /** SHA2-256 */
        case (PSA_ALG_SHA_256 & PSA_ALG_HASH_MASK):
            hash_length = HASH_LENGTH_BYTE_SHA256;
            break;

        /** SHA2-384 */
        case (PSA_ALG_SHA_384 & PSA_ALG_HASH_MASK):
            hash_length = HASH_LENGTH_BYTE_SHA384;
            break;

        /** SHA2-512 */
        case (PSA_ALG_SHA_512 & PSA_ALG_HASH_MASK):
            hash_length = HASH_LENGTH_BYTE_SHA512;
            break;

        default:
            psa_status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
        psa_status = (key_size_bytes >= ((2 * hash_length) + 2)) ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    else {
        psa_status = PSA_SUCCESS;
    }

exit:
    return psa_status;
}

int EcSignatureToRandS(uint8_t *signature, size_t *sigLen)
{
    int result         = 1;
    uint8_t rands[128] = {0};
    int index          = 0;
    size_t i           = 0;
    size_t len         = 0;
    if (signature[index++] != 0x30) {
        goto exit;
    }
    if (signature[index++] != (*sigLen - 2)) {
        goto exit;
    }
    if (signature[index++] != 0x02) {
        goto exit;
    }

    /* Parse length, skip initial 0x00 byte if present */
    len = signature[index++];
    if (len & 0x01) {
        len--;
        index++;
    }

    /* Copy R component*/
    for (i = 0; i < len; i++) {
        rands[i] = signature[index++];
    }

    if (signature[index++] != 0x02) {
        goto exit;
    }

    /* Parse length, skip initial 0x00 byte if present */
    len = signature[index++];
    if (len & 0x01) {
        len--;
        index++;
    }

    /* Copy S component*/
    len = len + i;
    for (; i < len; i++) {
        rands[i] = signature[index++];
    }

    /* Copy to output buffer and update length */
    memcpy(&signature[0], &rands[0], i);
    *sigLen = i;

    result = 0;

exit:
    return result;
}

int EcRandSToSignature(const uint8_t *rands, const size_t rands_len, uint8_t *output, size_t *outputLen)
{
    int result             = 1;
    uint8_t signature[600] = {0};
    size_t signatureLen    = sizeof(signature);
    size_t componentLen    = (rands_len) / 2;
    uint8_t tag            = ASN_TAG_INT;

    result = SetASNTLV(tag, &rands[componentLen], componentLen, signature, &signatureLen);
    if (result != 0) {
        goto exit;
    }

    result = SetASNTLV(tag, &rands[0], componentLen, signature, &signatureLen);
    if (result != 0) {
        goto exit;
    }

    size_t totalLen = sizeof(signature) - signatureLen;

    if (totalLen <= 127) {
        if (signatureLen < 1) {
            result = 1;
            goto exit;
        }
        signatureLen            = signatureLen - 1;
        signature[signatureLen] = (uint8_t)totalLen;
    }
    else if (totalLen <= 255) {
        if (signatureLen < 2) {
            result = 1;
            goto exit;
        }
        signatureLen                = signatureLen - 2;
        signature[signatureLen]     = 0x81;
        signature[signatureLen + 1] = (uint8_t)totalLen;
    }
    else {
        if (signatureLen < 3) {
            result = 1;
            goto exit;
        }
        signatureLen                = signatureLen - 3;
        signature[signatureLen]     = 0x82;
        signature[signatureLen + 1] = (totalLen & 0x00FF00) >> 8;
        signature[signatureLen + 2] = (totalLen & 0x00FF);
    }

    if (signatureLen < 1) {
        return 1;
    }
    signatureLen = signatureLen - 1;

    signature[signatureLen] = ASN_TAG_SEQUENCE;

    totalLen = sizeof(signature) - signatureLen;
    memcpy(&output[0], &signature[signatureLen], totalLen);
    *outputLen = totalLen;

    result = 0;

exit:
    return result;
}

psa_status_t validate_algorithm_with_key_type(sss_algorithm_t sss_algorithm, const uint32_t key_slot)
{
    psa_status_t psa_status = PSA_ERROR_DOES_NOT_EXIST;
    sss_status_t sss_status = kStatus_SSS_Fail;
    sss_object_t sss_object = {0};
    sss_status              = sss_key_object_init(&sss_object, &gPsaAltBootCtx.ks);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    sss_status = sss_key_object_get_handle(&sss_object, key_slot);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    if (sss_object.cipherType == kSSS_CipherType_EC_NIST_P || sss_object.cipherType == kSSS_CipherType_EC_NIST_K ||
        sss_object.cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        if (sss_algorithm != kAlgorithm_SSS_ECDSA_SHA1 && sss_algorithm != kAlgorithm_SSS_ECDSA_SHA224 &&
            sss_algorithm != kAlgorithm_SSS_ECDSA_SHA256 && sss_algorithm != kAlgorithm_SSS_ECDSA_SHA384 &&
            sss_algorithm != kAlgorithm_SSS_ECDSA_SHA512) {
            psa_status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
        psa_status = PSA_SUCCESS;
    }
    else if (sss_object.cipherType == kSSS_CipherType_RSA_CRT || sss_object.cipherType == kSSS_CipherType_RSA) {
        if (SSS_ALGORITHM_IS_RSA(sss_algorithm)) {
            psa_status = PSA_SUCCESS;
        }
        else {
            psa_status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    }

exit:
    return psa_status;
}

psa_status_t ecdsa_algorithm_from_signature_length(
    psa_algorithm_t psa_algorithm, const size_t signature_length, sss_algorithm_t *sss_algorithm)
{
    psa_status_t psa_status = PSA_ERROR_NOT_SUPPORTED;
    if (!PSA_ALG_IS_RANDOMIZED_ECDSA(psa_algorithm)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    LOG_U32_I(signature_length);
    switch (signature_length) {
    case (HASH_LENGTH_BYTE_SHA1 * 2):
        *sss_algorithm = kAlgorithm_SSS_ECDSA_SHA1;
        psa_status     = PSA_SUCCESS;
        break;
    case (HASH_LENGTH_BYTE_SHA224 * 2):
        *sss_algorithm = kAlgorithm_SSS_ECDSA_SHA224;
        psa_status     = PSA_SUCCESS;
        break;
    case (HASH_LENGTH_BYTE_SHA256 * 2):
        *sss_algorithm = kAlgorithm_SSS_ECDSA_SHA256;
        psa_status     = PSA_SUCCESS;
        break;
    case (HASH_LENGTH_BYTE_SHA384 * 2):
        *sss_algorithm = kAlgorithm_SSS_ECDSA_SHA384;
        psa_status     = PSA_SUCCESS;
        break;
    case (HASH_LENGTH_BYTE_SHA512 * 2):
        *sss_algorithm = kAlgorithm_SSS_ECDSA_SHA512;
        psa_status     = PSA_SUCCESS;
        break;
    default:
        psa_status = PSA_ERROR_INVALID_SIGNATURE;
        LOG_E("Invalid ECDSA signature length");
        break;
    }

    return psa_status;
}

psa_status_t se05x_sign_check_input_len(size_t inLen, sss_algorithm_t sss_algorithm)
{
    psa_status_t retval = PSA_ERROR_INVALID_ARGUMENT;

    switch (sss_algorithm) {
    case kAlgorithm_SSS_SHA1:
    case kAlgorithm_SSS_ECDSA_SHA1:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1:
        retval = (inLen == 20) ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
        break;
    case kAlgorithm_SSS_SHA224:
    case kAlgorithm_SSS_ECDSA_SHA224:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA224:
        retval = (inLen == 28) ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
        break;
    case kAlgorithm_SSS_SHA256:
    case kAlgorithm_SSS_ECDSA_SHA256:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256:
        retval = (inLen == 32) ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
        break;
    case kAlgorithm_SSS_SHA384:
    case kAlgorithm_SSS_ECDSA_SHA384:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384:
        retval = (inLen == 48) ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
        break;
    case kAlgorithm_SSS_SHA512:
    case kAlgorithm_SSS_ECDSA_SHA512:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512:
        retval = (inLen == 64) ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
        break;
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH:
    case kAlgorithm_SSS_RSASSA_NO_PADDING:
        retval = PSA_SUCCESS;
        break;
    default:
        LOG_E("Unkown algorithm");
        retval = PSA_ERROR_INVALID_ARGUMENT;
    }
    return retval;
}

psa_status_t validate_domain_parameter(const psa_key_attributes_t *attributes)
{
    if (attributes->domain_parameters_size == 0) {
        return PSA_SUCCESS;
    }
    if (attributes->domain_parameters_size == 1) {
        uint8_t domain_parameters = 0;
        memcpy(&domain_parameters, attributes->domain_parameters, sizeof(domain_parameters));
        if (domain_parameters < 3) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        else {
            return PSA_SUCCESS;
        }
    }
    else if (attributes->domain_parameters_size == 3) {
        uint8_t domain_parameters[3] = {0};
        memcpy(&domain_parameters, attributes->domain_parameters, sizeof(domain_parameters));
        if ((domain_parameters[0] != 0x01) || (domain_parameters[1] != 0x00) || (domain_parameters[2] != 0x01)) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        else {
            return PSA_SUCCESS;
        }
    }
    else {
        return PSA_ERROR_NOT_SUPPORTED;
    }
}
