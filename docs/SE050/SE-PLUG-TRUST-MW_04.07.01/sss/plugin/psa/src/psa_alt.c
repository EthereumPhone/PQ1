/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "psa_alt.h"

#include <nxLog_App.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa_alt_utils.h"
#include "psa_crypto_storage.h"
#include "sss_psa_alt.h"
#include "psa/crypto_extra.h"

static void psa_uid_to_se_uid(psa_storage_uid_t uid, uint32_t *keyid);

psa_status_t psa_alt_driver_init(psa_drv_se_context_t *drv_context, void *persistent_data, psa_key_lifetime_t lifetime)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    LOG_I("Initializing driver");
    sss_status_t status = kStatus_SSS_Fail;
    status              = sss_psa_alt_session_open();
    if (status == kStatus_SSS_Success) {
        psa_status = PSA_SUCCESS;
    }
    return psa_status;
}

psa_status_t psa_alt_allocate_key(psa_drv_se_context_t *drv_context,
    void *persistent_data,
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_key_slot_number_t *key_slot)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    psa_key_id_t key_id     = psa_get_key_id(attributes);
    /* Return the keyID used by App. 
     * We will manage masking in implementation
     */
    *key_slot = (uint64_t)(key_id);
    /* Mask App keyID to the keyID actually to be used.
     * We only need to use OBJECT_ID mask here. 
     * ITS mask can be checked while creation/storing 
     * object file
     */
    key_id     = PSA_KEY_ID_TO_ALT_OBJECT_ID(key_id);
    psa_status = sss_check_if_object_exists(key_id);
    if (psa_status == PSA_ERROR_DOES_NOT_EXIST) {
        psa_status = PSA_SUCCESS;
    }
    else if (psa_status == PSA_SUCCESS) {
        // psa_status = PSA_ERROR_ALREADY_EXISTS;
    }
    return psa_status;
}

psa_status_t psa_alt_validate_slot_number(psa_drv_se_context_t *drv_context,
    void *persistent_data,
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_key_slot_number_t key_slot)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);
    // if ((key_slot & PSA_ALT_OBJECT_FILE_MASK) != PSA_ALT_OBJECT_START) {
    //     return PSA_ERROR_INVALID_ARGUMENT;
    // }
    psa_status = sss_check_if_object_exists(se_key_id);
    if (psa_status == PSA_ERROR_DOES_NOT_EXIST) {
        psa_status = PSA_SUCCESS;
    }
    else if (psa_status == PSA_SUCCESS) {
        psa_status = PSA_ERROR_ALREADY_EXISTS;
    }
    return psa_status;
}

psa_status_t psa_alt_import_key(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    size_t *bits)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);

    psa_status = sss_check_if_object_exists(se_key_id);
    if (psa_status == PSA_SUCCESS) {
        // return PSA_ERROR_ALREADY_EXISTS;
    }

    psa_key_type_t psa_key_type  = psa_get_key_type(attributes);
    size_t key_size              = psa_get_key_bits(attributes);
    sss_cipher_type_t sss_cipher = kSSS_CipherType_NONE;
    sss_key_part_t sss_key_part  = kSSS_KeyPart_NONE;

    psa_status = psa_key_type_to_sss_cipher(psa_key_type, &sss_cipher, &sss_key_part);
    if (psa_status != PSA_SUCCESS) {
        LOG_E("Incorrect attributes");
        return psa_status;
    }
    *bits = key_size;

    uint8_t formatted_data[8191] = {0};
    size_t formatted_data_len    = sizeof(formatted_data);
    psa_status =
        validate_import_data(sss_cipher, sss_key_part, data, data_length, formatted_data, &formatted_data_len, bits);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    if (key_size != 0 && key_size != *bits) {
        if (sss_key_part == kSSS_KeyPart_Default) {
            /* Only specific lengths are supported.
             * If some other value is passed, the argument is invalid
             */
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        else {
            /* Different bit sizes can be supported but we 
             * don't support the passed bit size 
             */
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }

    sss_status = sss_psa_alt_import_key(se_key_id, formatted_data, formatted_data_len, *bits, sss_key_part, sss_cipher);
    if (sss_status != kStatus_SSS_Success) {
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_generate_key(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    uint8_t *pubkey,
    size_t pubkey_size,
    size_t *pubkey_length)
{
    LOG_D("%s", __FUNCTION__);
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);

    // psa_algorithm_t psa_algorithm = psa_get_key_algorithm(attributes);

    psa_status = sss_check_if_object_exists(se_key_id);
    if (psa_status == PSA_SUCCESS) {
        return PSA_ERROR_ALREADY_EXISTS;
    }

    psa_key_type_t psa_key_type  = psa_get_key_type(attributes);
    size_t key_size              = psa_get_key_bits(attributes);
    sss_cipher_type_t sss_cipher = kSSS_CipherType_NONE;
    sss_key_part_t sss_key_part  = kSSS_KeyPart_NONE;
    uint8_t *key                 = NULL;
    size_t keyLen                = 0;

    psa_status = psa_key_type_to_sss_cipher(psa_key_type, &sss_cipher, &sss_key_part);
    if (psa_status != PSA_SUCCESS) {
        LOG_E("Incorrect attributes");
        return psa_status;
    }

    if (sss_key_part == kSSS_KeyPart_Public) {
        LOG_E("Cannot generate public key");
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (sss_cipher == kSSS_CipherType_Binary) {
        /* Generate random number here */
        if (key_size == 0 || (key_size % 8) != 0) {
            LOG_E("Incorrect attributes");
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        key    = (uint8_t *)SSS_MALLOC(sizeof(uint8_t) * (key_size));
        keyLen = key_size;
        goto generate_random;
    }

    psa_status = sss_cipher_validate_key_size(sss_cipher, key_size);
    if (psa_status != PSA_SUCCESS) {
        LOG_E("Unsupported key size");
        return psa_status;
    }

    if (sss_cipher == kSSS_CipherType_RSA_CRT) {
        psa_status = validate_domain_parameter(attributes);
        if (psa_status != PSA_SUCCESS) {
            return psa_status;
        }
    }

    if (sss_key_part != kSSS_KeyPart_Default) {
        sss_status = sss_psa_alt_generate_key(se_key_id, key_size, sss_key_part, sss_cipher);
        if (sss_status != kStatus_SSS_Success) {
            LOG_E("Key generation failed");
            return PSA_ERROR_HARDWARE_FAILURE;
        }
        else {
            return PSA_SUCCESS;
        }
    }
    else {
        key    = (uint8_t *)SSS_MALLOC(sizeof(uint8_t) * (key_size / 8));
        keyLen = key_size / 8;
        goto generate_random;
    }

generate_random:
    psa_status = generate_random_symmetric_key(key, &keyLen, key_size / 8);
    if (psa_status != PSA_SUCCESS) {
        if (key) {
            SSS_FREE(key);
        }
        return psa_status;
    }
    sss_status = sss_psa_alt_import_key(se_key_id, key, keyLen, keyLen * 8, sss_key_part, sss_cipher);
    if (key) {
        SSS_FREE(key);
    }
    if (sss_status != kStatus_SSS_Success) {
        LOG_E("Key generation failed");
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_destroy_key(
    psa_drv_se_context_t *drv_context, void *persistent_data, psa_key_slot_number_t key_slot)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);

    sss_status = sss_psa_alt_destroy_key(se_key_id);
    if (sss_status != kStatus_SSS_Success) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_export_key(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key,
    uint8_t *p_data,
    size_t data_size,
    size_t *p_data_length)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key);
    psa_status_t psa_status = sss_validate_buffer_size(se_key_id, data_size);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    uint8_t export_data[8191] = {0};
    size_t export_data_len    = sizeof(export_data);

    sss_status = sss_psa_alt_export_key(se_key_id, export_data, export_data_len, p_data_length);
    if (sss_status != kStatus_SSS_Success) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_status = fill_export_data_buffer(se_key_id, export_data, p_data_length, p_data, data_size);
    return psa_status;
}

psa_status_t psa_alt_asymmetric_sign_digest(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    const uint8_t *p_hash,
    size_t hash_length,
    uint8_t *p_signature,
    size_t signature_size,
    size_t *p_signature_length)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);

    psa_status = sss_check_if_object_exists(se_key_id);
    if (psa_status != PSA_SUCCESS) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(alg, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    psa_status = validate_sign_input_data(se_key_id, alg, p_hash, hash_length);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    psa_status = se05x_sign_check_input_len(hash_length, sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    // *p_signature_length = signature_size;

    uint8_t *pHash = (uint8_t *)SSS_MALLOC(sizeof(uint8_t) * hash_length);
    memset(pHash, 0, hash_length);
    memcpy(pHash, p_hash, hash_length);

    uint8_t signature[512] = {0};
    size_t sig_len         = sizeof(signature);

    sss_status = sss_psa_alt_asymmetric_sign_digest(se_key_id, sss_algorithm, pHash, hash_length, signature, &sig_len);

    if (pHash) {
        SSS_FREE(pHash);
    }

    if (sss_status != kStatus_SSS_Success) {
        *p_signature_length = 0;
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    if (PSA_ALG_IS_RANDOMIZED_ECDSA(alg)) {
        if (0 != EcSignatureToRandS(signature, &sig_len)) {
            *p_signature_length = 0;
            return PSA_ERROR_DATA_CORRUPT;
        }
    }
    if (signature_size < sig_len) {
        *p_signature_length = 0;
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(p_signature, signature, sig_len);
    *p_signature_length = sig_len;

    return PSA_SUCCESS;
}

psa_status_t psa_alt_asymmetric_verify_digest(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    const uint8_t *p_hash,
    size_t hash_length,
    const uint8_t *p_signature,
    size_t signature_length)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);

    psa_status = sss_check_if_object_exists(se_key_id);
    if (psa_status != PSA_SUCCESS) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }
    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(alg, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        if (PSA_ALG_IS_RANDOMIZED_ECDSA(alg)) {
            psa_status = ecdsa_algorithm_from_signature_length(alg, signature_length, &sss_algorithm);
            if (psa_status != PSA_SUCCESS) {
                return psa_status;
            }
        }
        else {
            return psa_status;
        }
    }

    psa_status = validate_algorithm_with_key_type(sss_algorithm, se_key_id);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    psa_status = se05x_sign_check_input_len(hash_length, sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    size_t sig_len      = signature_length + 0x10;
    uint8_t *pHash      = (uint8_t *)SSS_MALLOC(sizeof(uint8_t) * hash_length);
    uint8_t *pSignature = (uint8_t *)SSS_MALLOC(sizeof(uint8_t) * sig_len);

    memset(pHash, 0, hash_length);
    memcpy(pHash, p_hash, hash_length);

    memset(pSignature, 0, signature_length);
    if (PSA_ALG_IS_RANDOMIZED_ECDSA(alg)) {
        if (0 != EcRandSToSignature(p_signature, signature_length, pSignature, &sig_len)) {
            return PSA_ERROR_DATA_CORRUPT;
        }
    }
    else {
        memcpy(pSignature, p_signature, signature_length);
        sig_len = signature_length;
    }

    sss_status =
        sss_psa_alt_asymmetric_verify_digest(se_key_id, sss_algorithm, pHash, hash_length, pSignature, sig_len);

    if (pHash) {
        SSS_FREE(pHash);
    }

    if (pSignature) {
        SSS_FREE(pSignature);
    }

    if (sss_status != kStatus_SSS_Success) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_asymmetric_encrypt(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    const uint8_t *p_input,
    size_t input_length,
    const uint8_t *p_salt,
    size_t salt_length,
    uint8_t *p_output,
    size_t output_size,
    size_t *p_output_length)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);

    psa_status = sss_check_if_object_exists(se_key_id);
    if (psa_status != PSA_SUCCESS) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(alg, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    *p_output_length = output_size;

    sss_status =
        sss_psa_alt_asymmetric_encrypt(se_key_id, sss_algorithm, p_input, input_length, p_output, p_output_length);

    if (sss_status != kStatus_SSS_Success) {
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_asymmetric_decrypt(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    const uint8_t *p_input,
    size_t input_length,
    const uint8_t *p_salt,
    size_t salt_length,
    uint8_t *p_output,
    size_t output_size,
    size_t *p_output_length)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t se_key_id      = (uint32_t)PSA_KEY_ID_TO_ALT_OBJECT_ID(key_slot);

    psa_status = sss_check_if_object_exists(se_key_id);
    if (psa_status != PSA_SUCCESS) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    sss_algorithm_t sss_algorithm = kAlgorithm_None;
    psa_status                    = psa_algorithm_to_sss_algorithm(alg, &sss_algorithm);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    *p_output_length = output_size;

    sss_status =
        sss_psa_alt_asymmetric_decrypt(se_key_id, sss_algorithm, p_input, input_length, p_output, p_output_length);

    if (sss_status != kStatus_SSS_Success) {
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_alt_cipher_setup(psa_drv_se_context_t *drv_context,
    void *op_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t algorithm,
    psa_encrypt_or_decrypt_t direction)
{
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_alt_cipher_set_iv(void *op_context, const uint8_t *p_iv, size_t iv_length)
{
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_alt_cipher_update(void *op_context,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size,
    size_t *p_output_length)
{
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_alt_cipher_finish(void *op_context, uint8_t *p_output, size_t output_size, size_t *p_output_length)
{
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_alt_cipher_abort(void *op_context)
{
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_alt_cipher_ecb(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t algorithm,
    psa_encrypt_or_decrypt_t direction,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size)
{
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_alt_store_se_its_file(psa_storage_uid_t uid, uint8_t *data, size_t dataLen)
{
    psa_status_t psa_status      = PSA_ERROR_INSUFFICIENT_STORAGE;
    sss_status_t sss_status      = kStatus_SSS_Fail;
    sss_key_part_t keyPart       = kSSS_KeyPart_Default;
    sss_cipher_type_t cipherType = kSSS_CipherType_Binary;
    uint32_t file_id             = 0;

    // LOG_I("%s", __FUNCTION__);

    psa_uid_to_se_uid(uid, &file_id);

    sss_status = sss_psa_alt_import_key(file_id, data, dataLen, dataLen * 8, keyPart, cipherType);
    if (sss_status == kStatus_SSS_Success) {
        psa_status = PSA_SUCCESS;
    }

    return psa_status;
}

psa_status_t psa_alt_read_se_its_file(psa_storage_uid_t uid, uint8_t *data, size_t *dataLen)
{
    psa_status_t psa_status = PSA_ERROR_STORAGE_FAILURE;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t file_id        = 0;
    size_t bufferLen        = *dataLen;
    // LOG_I("%s", __FUNCTION__);

    psa_uid_to_se_uid(uid, &file_id);

    psa_status = sss_check_if_object_exists(file_id);
    if (psa_status != PSA_SUCCESS) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    sss_status = sss_psa_alt_export_key(file_id, data, bufferLen, dataLen);
    if (sss_status != kStatus_SSS_Success) {
        *dataLen   = 0;
        psa_status = PSA_ERROR_STORAGE_FAILURE;
    }
    else {
        psa_status = PSA_SUCCESS;
    }

    return psa_status;
}

psa_status_t psa_alt_remove_se_its_file(psa_storage_uid_t uid)
{
    psa_status_t psa_status = PSA_ERROR_STORAGE_FAILURE;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t file_id        = 0;

    // LOG_I("%s", __FUNCTION__);

    psa_uid_to_se_uid(uid, &file_id);

    psa_status = sss_check_if_object_exists(file_id);
    if (psa_status != PSA_SUCCESS) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    sss_status = sss_psa_alt_destroy_key(file_id);
    if (sss_status != kStatus_SSS_Success) {
        psa_status = PSA_ERROR_STORAGE_FAILURE;
    }
    else {
        psa_status = PSA_SUCCESS;
    }

    return psa_status;
}

static void psa_uid_to_se_uid(psa_storage_uid_t uid, uint32_t *keyid)
{
#if defined(PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS)
    if (uid == PSA_CRYPTO_ITS_TRANSACTION_UID) {
        // LOG_I("TRANSACTION");
        *keyid = PSA_ALT_TRANSACTION_FILE;
    }
    else
#endif
    {
        if ((uid & PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE) == PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE) {
            // LOG_I("LIFETIME");
            *keyid = PSA_ALT_LIFETIME_FILE;
        }
        else {
            // LOG_I("OBJECT");
            *keyid = PSA_KEY_ID_TO_ITS_KEY_ID(*keyid);
        }
    }
}
