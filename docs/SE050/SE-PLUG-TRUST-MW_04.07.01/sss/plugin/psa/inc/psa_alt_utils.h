/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PSA_ALT_UTILS_H_
#define _PSA_ALT_UTILS_H_

#include <fsl_sss_api.h>

#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa_crypto_its.h"

/* NIST-P Curves */
#define KEY_SIZE_BITS_SECP192R1 192
#define KEY_SIZE_BITS_SECP224R1 224
#define KEY_SIZE_BITS_SECP256R1 256
#define KEY_SIZE_BITS_SECP384R1 384
#define KEY_SIZE_BITS_SECP521R1 521

#define KEY_SIZE_BYTE_SECP192R1 (KEY_SIZE_BITS_SECP192R1 / 8)
#define KEY_SIZE_BYTE_SECP224R1 (KEY_SIZE_BITS_SECP224R1 / 8)
#define KEY_SIZE_BYTE_SECP256R1 (KEY_SIZE_BITS_SECP256R1 / 8)
#define KEY_SIZE_BYTE_SECP384R1 (KEY_SIZE_BITS_SECP384R1 / 8)
#define KEY_SIZE_BYTE_SECP521R1 ((KEY_SIZE_BITS_SECP521R1 / 8) + 1)

/* Brainpool Curves */
#define KEY_SIZE_BITS_BP256R1 256
#define KEY_SIZE_BITS_BP384R1 384
#define KEY_SIZE_BITS_BP512R1 512

#define KEY_SIZE_BYTE_BP256R1 KEY_SIZE_BITS_BP256R1 / 8
#define KEY_SIZE_BYTE_BP384R1 KEY_SIZE_BITS_BP384R1 / 8
#define KEY_SIZE_BYTE_BP512R1 KEY_SIZE_BITS_BP512R1 / 8

/* Koblitz curves */
#define KEY_SIZE_BITS_SECK160R1 160
#define KEY_SIZE_BITS_SECK192R1 192
#define KEY_SIZE_BITS_SECK224R1 224
#define KEY_SIZE_BITS_SECK256R1 256

#define KEY_SIZE_BYTE_SECK160R1 KEY_SIZE_BITS_SECK160R1 / 8
#define KEY_SIZE_BYTE_SECK192R1 KEY_SIZE_BITS_SECK192R1 / 8
#define KEY_SIZE_BYTE_SECK224R1 KEY_SIZE_BITS_SECK224R1 / 8
#define KEY_SIZE_BYTE_SECK256R1 KEY_SIZE_BITS_SECK256R1 / 8

/* Montgomery curve */
/* Not supported for now */
#define KEY_SIZE_BITS_CURVE25519 256
#define KEY_SIZE_BYTE_CURVE25519 (KEY_SIZE_BITS_CURVE25519 / 8)

#define HASH_LENGTH_BYTE_SHA1 20
#define HASH_LENGTH_BYTE_SHA224 28
#define HASH_LENGTH_BYTE_SHA256 32
#define HASH_LENGTH_BYTE_SHA384 48
#define HASH_LENGTH_BYTE_SHA512 64

#define SSS_ALGORITHM_IS_RSA_PKCS1_V1_5_SIGN(algorithm)             \
    (((algorithm >= kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1) &&       \
         (algorithm <= kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512)) || \
        (algorithm == kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH))

#define SSS_ALGORITHM_IS_RSA_PKCS1_PSS_SIGN(algorithm)           \
    ((algorithm >= kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1) && \
        (algorithm <= kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512))

#define SSS_ALGORITHM_IS_RSA_PKCS1_OAEP_ENCRYPT(algorithm) \
    ((algorithm >= kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1) && (algorithm <= kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA512))

#define SSS_ALGORITHM_IS_RSA_PKCS1_V1_5_ENCRYPT(algorithm) ((algorithm == kAlgorithm_SSS_RSAES_PKCS1_V1_5))

#define SSS_ALGORITHM_IS_RSA(algorithm)                                                                         \
    (SSS_ALGORITHM_IS_RSA_PKCS1_V1_5_SIGN(algorithm) || SSS_ALGORITHM_IS_RSA_PKCS1_V1_5_ENCRYPT(algorithm) ||   \
        SSS_ALGORITHM_IS_RSA_PKCS1_PSS_SIGN(algorithm) || SSS_ALGORITHM_IS_RSA_PKCS1_OAEP_ENCRYPT(algorithm) || \
        (algorithm == kAlgorithm_SSS_RSASSA_NO_PADDING))

psa_status_t psa_key_type_to_sss_cipher(
    psa_key_type_t psa_key_type, sss_cipher_type_t *sss_cipher, sss_key_part_t *sss_key_part);

psa_status_t sss_cipher_validate_key_size(const sss_cipher_type_t sss_cipher, size_t key_size);

psa_status_t sss_check_if_object_exists(uint32_t key_id);

psa_status_t validate_import_data(const sss_cipher_type_t sss_cipher,
    const sss_key_part_t sss_key_part,
    const uint8_t *data,
    const size_t data_length,
    uint8_t *formatted_data,
    size_t *formatted_data_len,
    size_t *bits);

psa_status_t generate_random_symmetric_key(uint8_t *key, size_t *bufferLen, const size_t keyLen);

psa_status_t psa_algorithm_to_sss_algorithm(const psa_algorithm_t psa_algorithm, sss_algorithm_t *sss_algorithm);

psa_status_t sss_validate_buffer_size(uint32_t key_id, size_t buffer_len);

psa_status_t fill_export_data_buffer(const uint32_t key_id,
    const uint8_t *export_data,
    size_t *p_data_length,
    uint8_t *p_data,
    const size_t data_length);

psa_status_t validate_sign_input_data(
    uint32_t key_id, const psa_algorithm_t psa_algorithm, const uint8_t *input, size_t data_len);

int EcSignatureToRandS(uint8_t *signature, size_t *sigLen);

int EcRandSToSignature(const uint8_t *rands, const size_t rands_len, uint8_t *output, size_t *outputLen);

psa_status_t validate_algorithm_with_key_type(sss_algorithm_t sss_algorithm, const uint32_t key_slot);

psa_status_t ecdsa_algorithm_from_signature_length(
    psa_algorithm_t psa_algorithm, const size_t signature_length, sss_algorithm_t *sss_algorithm);

psa_status_t se05x_sign_check_input_len(size_t inLen, sss_algorithm_t sss_algorithm);

psa_status_t validate_domain_parameter(const psa_key_attributes_t *attributes);

#endif //_PSA_ALT_UTILS_H_
