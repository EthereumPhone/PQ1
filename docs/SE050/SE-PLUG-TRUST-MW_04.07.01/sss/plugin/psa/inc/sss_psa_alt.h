/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _SSS_PSA_ALT_H_
#define _SSS_PSA_ALT_H_

#include <fsl_sss_api.h>

/* Session Open from driver->p_init API */
sss_status_t sss_psa_alt_session_open(void);

sss_status_t sss_psa_alt_allocate_key(void);

sss_status_t sss_psa_alt_generate_key(
    uint32_t keyId, size_t keyBitLen, sss_key_part_t keyPart, sss_cipher_type_t cipherType);

sss_status_t sss_psa_alt_export_key(uint32_t keyId, uint8_t *data, size_t bufferLen, size_t *dataLen);

sss_status_t sss_psa_alt_destroy_key(uint32_t keyId);

sss_status_t sss_psa_alt_import_key(uint32_t keyId,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType);

sss_status_t sss_psa_alt_asymmetric_sign_digest(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    uint8_t *digest,
    size_t digestLen,
    uint8_t *signature,
    size_t *signatureLen);

sss_status_t sss_psa_alt_asymmetric_verify_digest(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    uint8_t *digest,
    size_t digestLen,
    uint8_t *signature,
    size_t signatureLen);

sss_status_t sss_psa_alt_asymmetric_encrypt(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    const uint8_t *input,
    size_t inputLen,
    uint8_t *output,
    size_t *outputLen);

sss_status_t sss_psa_alt_asymmetric_decrypt(const uint32_t keyId,
    sss_algorithm_t sss_algorithm,
    const uint8_t *input,
    size_t inputLen,
    uint8_t *output,
    size_t *outputLen);

#endif //_SSS_PSA_ALT_H_
