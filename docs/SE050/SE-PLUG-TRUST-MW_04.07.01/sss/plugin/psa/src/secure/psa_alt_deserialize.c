/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <nxLog_App.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa_alt.h"
#include "psa_alt_utils.h"
#include "psa_crypto_storage.h"
#include "psa_crypto_core.h"
#include "psa_crypto_invasive.h"
#include "psa_crypto_slot_management.h"
#include "psa/crypto_extra.h"
#include "sss_psa_alt.h"

#include "psa_alt_serialize_struct.h"
#include "psa_alt_deserialize.h"

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_import_key_into_slot(
    psa_import_key_into_slot_struct_t *psa_import_key_into_slot_struct)
{
    const psa_key_attributes_t *attributes = psa_import_key_into_slot_struct->attributes;
    const uint8_t *data                    = psa_import_key_into_slot_struct->data;
    size_t data_length                     = psa_import_key_into_slot_struct->data_length;
    uint8_t *key_buffer                    = psa_import_key_into_slot_struct->key_buffer;
    size_t key_buffer_size                 = psa_import_key_into_slot_struct->key_buffer_size;
    size_t *key_buffer_length              = psa_import_key_into_slot_struct->key_buffer_length;
    size_t *bits                           = psa_import_key_into_slot_struct->bits;

    return psa_import_key_into_slot(
        attributes, data, data_length, key_buffer, key_buffer_size, key_buffer_length, bits);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_wipe_key_slot(
    psa_wipe_key_slot_struct_t *psa_wipe_key_slot_struct)
{
    psa_key_slot_t *slot = psa_wipe_key_slot_struct->slot;

    return psa_wipe_key_slot(slot);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_destroy_key(
    psa_destroy_key_struct_t *psa_destroy_key_struct)
{
    psa_key_handle_t handle = psa_destroy_key_struct->handle;

    return psa_destroy_key(handle);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_set_key_domain_parameters(
    psa_set_key_domain_parameters_struct_t *psa_set_key_domain_parameters_struct)
{
    psa_key_attributes_t *attributes = psa_set_key_domain_parameters_struct->attributes;
    psa_key_type_t type              = psa_set_key_domain_parameters_struct->type;
    const uint8_t *data              = psa_set_key_domain_parameters_struct->data;
    size_t data_length               = psa_set_key_domain_parameters_struct->data_length;

    return psa_set_key_domain_parameters(attributes, type, data, data_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_get_key_domain_parameters(
    psa_get_key_domain_parameters_struct_t *psa_get_key_domain_parameters_struct)
{
    const psa_key_attributes_t *attributes = psa_get_key_domain_parameters_struct->attributes;
    uint8_t *data                          = psa_get_key_domain_parameters_struct->data;
    size_t data_size                       = psa_get_key_domain_parameters_struct->data_size;
    size_t *data_length                    = psa_get_key_domain_parameters_struct->data_length;

    return psa_get_key_domain_parameters(attributes, data, data_size, data_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_get_key_attributes(
    psa_get_key_attributes_struct_t *psa_get_key_attributes_struct)
{
    psa_key_handle_t handle          = psa_get_key_attributes_struct->handle;
    psa_key_attributes_t *attributes = psa_get_key_attributes_struct->attributes;

    return psa_get_key_attributes(handle, attributes);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_get_key_slot_number(
    psa_get_key_slot_number_struct_t *psa_get_key_slot_number_struct)
{
    const psa_key_attributes_t *attributes = psa_get_key_slot_number_struct->attributes;
    psa_key_slot_number_t *slot_number     = psa_get_key_slot_number_struct->slot_number;

    return psa_get_key_slot_number(attributes, slot_number);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_export_key(psa_export_key_struct_t *psa_export_key_struct)
{
    psa_key_handle_t handle = psa_export_key_struct->handle;
    uint8_t *data           = psa_export_key_struct->data;
    size_t data_size        = psa_export_key_struct->data_size;
    size_t *data_length     = psa_export_key_struct->data_length;

    return psa_export_key(handle, data, data_size, data_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_export_public_key(
    psa_export_public_key_struct_t *psa_export_public_key_struct)
{
    psa_key_handle_t handle = psa_export_public_key_struct->handle;
    uint8_t *data           = psa_export_public_key_struct->data;
    size_t data_size        = psa_export_public_key_struct->data_size;
    size_t *data_length     = psa_export_public_key_struct->data_length;

    return psa_export_public_key(handle, data, data_size, data_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_import_key(psa_import_key_struct_t *psa_import_key_struct)
{
    const psa_key_attributes_t *attributes = psa_import_key_struct->attributes;
    const uint8_t *data                    = psa_import_key_struct->data;
    size_t data_length                     = psa_import_key_struct->data_length;
    psa_key_handle_t *handle               = psa_import_key_struct->handle;

    return psa_import_key(attributes, data, data_length, handle);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_mbedtls_psa_register_se_key(
    mbedtls_psa_register_se_key_struct_t *mbedtls_psa_register_se_key_struct)
{
    const psa_key_attributes_t *attributes = mbedtls_psa_register_se_key_struct->attributes;

    return mbedtls_psa_register_se_key(attributes);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_copy_key(psa_copy_key_struct_t *psa_copy_key_struct)
{
    psa_key_handle_t source_handle                   = psa_copy_key_struct->source_handle;
    const psa_key_attributes_t *specified_attributes = psa_copy_key_struct->specified_attributes;
    psa_key_handle_t *target_handle                  = psa_copy_key_struct->target_handle;

    return psa_copy_key(source_handle, specified_attributes, target_handle);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_hash_abort(psa_hash_abort_struct_t *psa_hash_abort_struct)
{
    psa_hash_operation_t *operation = psa_hash_abort_struct->operation;

    return psa_hash_abort(operation);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_hash_setup(psa_hash_setup_struct_t *psa_hash_setup_struct)
{
    psa_hash_operation_t *operation = psa_hash_setup_struct->operation;
    psa_algorithm_t alg             = psa_hash_setup_struct->alg;

    return psa_hash_setup(operation, alg);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_hash_update(
    psa_hash_update_struct_t *psa_hash_update_struct)
{
    psa_hash_operation_t *operation = psa_hash_update_struct->operation;
    const uint8_t *input            = psa_hash_update_struct->input;
    size_t input_length             = psa_hash_update_struct->input_length;

    return psa_hash_update(operation, input, input_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_hash_finish(
    psa_hash_finish_struct_t *psa_hash_finish_struct)
{
    psa_hash_operation_t *operation = psa_hash_finish_struct->operation;
    uint8_t *hash                   = psa_hash_finish_struct->hash;
    size_t hash_size                = psa_hash_finish_struct->hash_size;
    size_t *hash_length             = psa_hash_finish_struct->hash_length;

    return psa_hash_finish(operation, hash, hash_size, hash_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_hash_verify(
    psa_hash_verify_struct_t *psa_hash_verify_struct)
{
    psa_hash_operation_t *operation = psa_hash_verify_struct->operation;
    const uint8_t *hash             = psa_hash_verify_struct->hash;
    size_t hash_length              = psa_hash_verify_struct->hash_length;

    return psa_hash_verify(operation, hash, hash_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_hash_clone(psa_hash_clone_struct_t *psa_hash_clone_struct)
{
    const psa_hash_operation_t *source_operation = psa_hash_clone_struct->source_operation;
    psa_hash_operation_t *target_operation       = psa_hash_clone_struct->target_operation;

    return psa_hash_clone(source_operation, target_operation);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_mac_abort(psa_mac_abort_struct_t *psa_mac_abort_struct)
{
    psa_mac_operation_t *operation = psa_mac_abort_struct->operation;

    return psa_mac_abort(operation);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_mac_sign_setup(
    psa_mac_sign_setup_struct_t *psa_mac_sign_setup_struct)
{
    psa_mac_operation_t *operation = psa_mac_sign_setup_struct->operation;
    psa_key_handle_t handle        = psa_mac_sign_setup_struct->handle;
    psa_algorithm_t alg            = psa_mac_sign_setup_struct->alg;

    return psa_mac_sign_setup(operation, handle, alg);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_mac_verify_setup(
    psa_mac_verify_setup_struct_t *psa_mac_verify_setup_struct)
{
    psa_mac_operation_t *operation = psa_mac_verify_setup_struct->operation;
    psa_key_handle_t handle        = psa_mac_verify_setup_struct->handle;
    psa_algorithm_t alg            = psa_mac_verify_setup_struct->alg;

    return psa_mac_verify_setup(operation, handle, alg);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_mac_update(psa_mac_update_struct_t *psa_mac_update_struct)
{
    psa_mac_operation_t *operation = psa_mac_update_struct->operation;
    const uint8_t *input           = psa_mac_update_struct->input;
    size_t input_length            = psa_mac_update_struct->input_length;

    return psa_mac_update(operation, input, input_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_mac_sign_finish(
    psa_mac_sign_finish_struct_t *psa_mac_sign_finish_struct)
{
    psa_mac_operation_t *operation = psa_mac_sign_finish_struct->operation;
    uint8_t *mac                   = psa_mac_sign_finish_struct->mac;
    size_t mac_size                = psa_mac_sign_finish_struct->mac_size;
    size_t *mac_length             = psa_mac_sign_finish_struct->mac_length;

    return psa_mac_sign_finish(operation, mac, mac_size, mac_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_mac_verify_finish(
    psa_mac_verify_finish_struct_t *psa_mac_verify_finish_struct)
{
    psa_mac_operation_t *operation = psa_mac_verify_finish_struct->operation;
    const uint8_t *mac             = psa_mac_verify_finish_struct->mac;
    size_t mac_length              = psa_mac_verify_finish_struct->mac_length;

    return psa_mac_verify_finish(operation, mac, mac_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_sign_hash(psa_sign_hash_struct_t *psa_sign_hash_struct)
{
    psa_key_handle_t handle  = psa_sign_hash_struct->handle;
    psa_algorithm_t alg      = psa_sign_hash_struct->alg;
    const uint8_t *hash      = psa_sign_hash_struct->hash;
    size_t hash_length       = psa_sign_hash_struct->hash_length;
    uint8_t *signature       = psa_sign_hash_struct->signature;
    size_t signature_size    = psa_sign_hash_struct->signature_size;
    size_t *signature_length = psa_sign_hash_struct->signature_length;

    return psa_sign_hash(handle, alg, hash, hash_length, signature, signature_size, signature_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_verify_hash(
    psa_verify_hash_struct_t *psa_verify_hash_struct)
{
    psa_key_handle_t handle  = psa_verify_hash_struct->handle;
    psa_algorithm_t alg      = psa_verify_hash_struct->alg;
    const uint8_t *hash      = psa_verify_hash_struct->hash;
    size_t hash_length       = psa_verify_hash_struct->hash_length;
    const uint8_t *signature = psa_verify_hash_struct->signature;
    size_t signature_length  = psa_verify_hash_struct->signature_length;

    return psa_verify_hash(handle, alg, hash, hash_length, signature, signature_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_asymmetric_encrypt(
    psa_asymmetric_encrypt_struct_t *psa_asymmetric_encrypt_struct)
{
    psa_key_handle_t handle = psa_asymmetric_encrypt_struct->handle;
    psa_algorithm_t alg     = psa_asymmetric_encrypt_struct->alg;
    const uint8_t *input    = psa_asymmetric_encrypt_struct->input;
    size_t input_length     = psa_asymmetric_encrypt_struct->input_length;
    const uint8_t *salt     = psa_asymmetric_encrypt_struct->salt;
    size_t salt_length      = psa_asymmetric_encrypt_struct->salt_length;
    uint8_t *output         = psa_asymmetric_encrypt_struct->output;
    size_t output_size      = psa_asymmetric_encrypt_struct->output_size;
    size_t *output_length   = psa_asymmetric_encrypt_struct->output_length;

    return psa_asymmetric_encrypt(
        handle, alg, input, input_length, salt, salt_length, output, output_size, output_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_asymmetric_decrypt(
    psa_asymmetric_decrypt_struct_t *psa_asymmetric_decrypt_struct)
{
    psa_key_handle_t handle = psa_asymmetric_decrypt_struct->handle;
    psa_algorithm_t alg     = psa_asymmetric_decrypt_struct->alg;
    const uint8_t *input    = psa_asymmetric_decrypt_struct->input;
    size_t input_length     = psa_asymmetric_decrypt_struct->input_length;
    const uint8_t *salt     = psa_asymmetric_decrypt_struct->salt;
    size_t salt_length      = psa_asymmetric_decrypt_struct->salt_length;
    uint8_t *output         = psa_asymmetric_decrypt_struct->output;
    size_t output_size      = psa_asymmetric_decrypt_struct->output_size;
    size_t *output_length   = psa_asymmetric_decrypt_struct->output_length;

    return psa_asymmetric_decrypt(
        handle, alg, input, input_length, salt, salt_length, output, output_size, output_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_cipher_encrypt_setup(
    psa_cipher_encrypt_setup_struct_t *psa_cipher_encrypt_setup_struct)
{
    psa_cipher_operation_t *operation = psa_cipher_encrypt_setup_struct->operation;
    psa_key_handle_t handle           = psa_cipher_encrypt_setup_struct->handle;
    psa_algorithm_t alg               = psa_cipher_encrypt_setup_struct->alg;

    return psa_cipher_encrypt_setup(operation, handle, alg);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_cipher_decrypt_setup(
    psa_cipher_decrypt_setup_struct_t *psa_cipher_decrypt_setup_struct)
{
    psa_cipher_operation_t *operation = psa_cipher_decrypt_setup_struct->operation;
    psa_key_handle_t handle           = psa_cipher_decrypt_setup_struct->handle;
    psa_algorithm_t alg               = psa_cipher_decrypt_setup_struct->alg;

    return psa_cipher_decrypt_setup(operation, handle, alg);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_cipher_generate_iv(
    psa_cipher_generate_iv_struct_t *psa_cipher_generate_iv_struct)
{
    psa_cipher_operation_t *operation = psa_cipher_generate_iv_struct->operation;
    uint8_t *iv                       = psa_cipher_generate_iv_struct->iv;
    size_t iv_size                    = psa_cipher_generate_iv_struct->iv_size;
    size_t *iv_length                 = psa_cipher_generate_iv_struct->iv_length;

    return psa_cipher_generate_iv(operation, iv, iv_size, iv_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_cipher_set_iv(
    psa_cipher_set_iv_struct_t *psa_cipher_set_iv_struct)
{
    psa_cipher_operation_t *operation = psa_cipher_set_iv_struct->operation;
    const uint8_t *iv                 = psa_cipher_set_iv_struct->iv;
    size_t iv_length                  = psa_cipher_set_iv_struct->iv_length;

    return psa_cipher_set_iv(operation, iv, iv_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_cipher_update(
    psa_cipher_update_struct_t *psa_cipher_update_struct)
{
    psa_cipher_operation_t *operation = psa_cipher_update_struct->operation;
    const uint8_t *input              = psa_cipher_update_struct->input;
    size_t input_length               = psa_cipher_update_struct->input_length;
    uint8_t *output                   = psa_cipher_update_struct->output;
    size_t output_size                = psa_cipher_update_struct->output_size;
    size_t *output_length             = psa_cipher_update_struct->output_length;

    return psa_cipher_update(operation, input, input_length, output, output_size, output_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_cipher_finish(
    psa_cipher_finish_struct_t *psa_cipher_finish_struct)
{
    psa_cipher_operation_t *operation = psa_cipher_finish_struct->operation;
    uint8_t *output                   = psa_cipher_finish_struct->output;
    size_t output_size                = psa_cipher_finish_struct->output_size;
    size_t *output_length             = psa_cipher_finish_struct->output_length;

    return psa_cipher_finish(operation, output, output_size, output_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_cipher_abort(
    psa_cipher_abort_struct_t *psa_cipher_abort_struct)
{
    psa_cipher_operation_t *operation = psa_cipher_abort_struct->operation;

    return psa_cipher_abort(operation);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_aead_encrypt(
    psa_aead_encrypt_struct_t *psa_aead_encrypt_struct)
{
    psa_key_handle_t handle        = psa_aead_encrypt_struct->handle;
    psa_algorithm_t alg            = psa_aead_encrypt_struct->alg;
    const uint8_t *nonce           = psa_aead_encrypt_struct->nonce;
    size_t nonce_length            = psa_aead_encrypt_struct->nonce_length;
    const uint8_t *additional_data = psa_aead_encrypt_struct->additional_data;
    size_t additional_data_length  = psa_aead_encrypt_struct->additional_data_length;
    const uint8_t *plaintext       = psa_aead_encrypt_struct->plaintext;
    size_t plaintext_length        = psa_aead_encrypt_struct->plaintext_length;
    uint8_t *ciphertext            = psa_aead_encrypt_struct->ciphertext;
    size_t ciphertext_size         = psa_aead_encrypt_struct->ciphertext_size;
    size_t *ciphertext_length      = psa_aead_encrypt_struct->ciphertext_length;

    return psa_aead_encrypt(handle,
        alg,
        nonce,
        nonce_length,
        additional_data,
        additional_data_length,
        plaintext,
        plaintext_length,
        ciphertext,
        ciphertext_size,
        ciphertext_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_aead_decrypt(
    psa_aead_decrypt_struct_t *psa_aead_decrypt_struct)
{
    psa_key_handle_t handle        = psa_aead_decrypt_struct->handle;
    psa_algorithm_t alg            = psa_aead_decrypt_struct->alg;
    const uint8_t *nonce           = psa_aead_decrypt_struct->nonce;
    size_t nonce_length            = psa_aead_decrypt_struct->nonce_length;
    const uint8_t *additional_data = psa_aead_decrypt_struct->additional_data;
    size_t additional_data_length  = psa_aead_decrypt_struct->additional_data_length;
    const uint8_t *ciphertext      = psa_aead_decrypt_struct->ciphertext;
    size_t ciphertext_length       = psa_aead_decrypt_struct->ciphertext_length;
    uint8_t *plaintext             = psa_aead_decrypt_struct->plaintext;
    size_t plaintext_size          = psa_aead_decrypt_struct->plaintext_size;
    size_t *plaintext_length       = psa_aead_decrypt_struct->plaintext_length;

    return psa_aead_decrypt(handle,
        alg,
        nonce,
        nonce_length,
        additional_data,
        additional_data_length,
        ciphertext,
        ciphertext_length,
        plaintext,
        plaintext_size,
        plaintext_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_key_derivation_abort(
    psa_key_derivation_abort_struct_t *psa_key_derivation_abort_struct)
{
    psa_key_derivation_operation_t *operation = psa_key_derivation_abort_struct->operation;

    return psa_key_derivation_abort(operation);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_key_derivation_get_capacity(
    psa_key_derivation_get_capacity_struct_t *psa_key_derivation_get_capacity_struct)
{
    const psa_key_derivation_operation_t *operation = psa_key_derivation_get_capacity_struct->operation;
    size_t *capacity                                = psa_key_derivation_get_capacity_struct->capacity;

    return psa_key_derivation_get_capacity(operation, capacity);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_key_derivation_set_capacity(
    psa_key_derivation_set_capacity_struct_t *psa_key_derivation_set_capacity_struct)
{
    psa_key_derivation_operation_t *operation = psa_key_derivation_set_capacity_struct->operation;
    size_t capacity                           = psa_key_derivation_set_capacity_struct->capacity;

    return psa_key_derivation_set_capacity(operation, capacity);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_key_derivation_output_bytes(
    psa_key_derivation_output_bytes_struct_t *psa_key_derivation_output_bytes_struct)
{
    psa_key_derivation_operation_t *operation = psa_key_derivation_output_bytes_struct->operation;
    uint8_t *output                           = psa_key_derivation_output_bytes_struct->output;
    size_t output_length                      = psa_key_derivation_output_bytes_struct->output_length;

    return psa_key_derivation_output_bytes(operation, output, output_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_key_derivation_output_key(
    psa_key_derivation_output_key_struct_t *psa_key_derivation_output_key_struct)
{
    const psa_key_attributes_t *attributes    = psa_key_derivation_output_key_struct->attributes;
    psa_key_derivation_operation_t *operation = psa_key_derivation_output_key_struct->operation;
    psa_key_handle_t *handle                  = psa_key_derivation_output_key_struct->handle;

    return psa_key_derivation_output_key(attributes, operation, handle);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_key_derivation_setup(
    psa_key_derivation_setup_struct_t *psa_key_derivation_setup_struct)
{
    psa_key_derivation_operation_t *operation = psa_key_derivation_setup_struct->operation;
    psa_algorithm_t alg                       = psa_key_derivation_setup_struct->alg;

    return psa_key_derivation_setup(operation, alg);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_key_derivation_input_bytes(
    psa_key_derivation_input_bytes_struct_t *psa_key_derivation_input_bytes_struct)
{
    psa_key_derivation_operation_t *operation = psa_key_derivation_input_bytes_struct->operation;
    psa_key_derivation_step_t step            = psa_key_derivation_input_bytes_struct->step;
    const uint8_t *data                       = psa_key_derivation_input_bytes_struct->data;
    size_t data_length                        = psa_key_derivation_input_bytes_struct->data_length;

    return psa_key_derivation_input_bytes(operation, step, data, data_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_key_derivation_input_key(
    psa_key_derivation_input_key_struct_t *psa_key_derivation_input_key_struct)
{
    psa_key_derivation_operation_t *operation = psa_key_derivation_input_key_struct->operation;
    psa_key_derivation_step_t step            = psa_key_derivation_input_key_struct->step;
    psa_key_handle_t handle                   = psa_key_derivation_input_key_struct->handle;

    return psa_key_derivation_input_key(operation, step, handle);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_key_derivation_key_agreement(
    psa_key_derivation_key_agreement_struct_t *psa_key_derivation_key_agreement_struct)
{
    psa_key_derivation_operation_t *operation = psa_key_derivation_key_agreement_struct->operation;
    psa_key_derivation_step_t step            = psa_key_derivation_key_agreement_struct->step;
    psa_key_handle_t private_key              = psa_key_derivation_key_agreement_struct->private_key;
    const uint8_t *peer_key                   = psa_key_derivation_key_agreement_struct->peer_key;
    size_t peer_key_length                    = psa_key_derivation_key_agreement_struct->peer_key_length;

    return psa_key_derivation_key_agreement(operation, step, private_key, peer_key, peer_key_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_raw_key_agreement(
    psa_raw_key_agreement_struct_t *psa_raw_key_agreement_struct)
{
    psa_algorithm_t alg          = psa_raw_key_agreement_struct->alg;
    psa_key_handle_t private_key = psa_raw_key_agreement_struct->private_key;
    const uint8_t *peer_key      = psa_raw_key_agreement_struct->peer_key;
    size_t peer_key_length       = psa_raw_key_agreement_struct->peer_key_length;
    uint8_t *output              = psa_raw_key_agreement_struct->output;
    size_t output_size           = psa_raw_key_agreement_struct->output_size;
    size_t *output_length        = psa_raw_key_agreement_struct->output_length;

    return psa_raw_key_agreement(alg, private_key, peer_key, peer_key_length, output, output_size, output_length);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_generate_random(
    psa_generate_random_struct_t *psa_generate_random_struct)
{
    uint8_t *output    = psa_generate_random_struct->output;
    size_t output_size = psa_generate_random_struct->output_size;

    return psa_generate_random(output, output_size);
}

#if defined(MBEDTLS_PSA_INJECT_ENTROPY)
__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_mbedtls_psa_inject_entropy(
    mbedtls_psa_inject_entropy_struct_t *mbedtls_psa_inject_entropy_struct)
{
    const uint8_t *seed = mbedtls_psa_inject_entropy_struct->seed;
    size_t seed_size    = mbedtls_psa_inject_entropy_struct->seed_size;

    return mbedtls_psa_inject_entropy(seed, seed_size);
}
#endif

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_generate_key(
    psa_generate_key_struct_t *psa_generate_key_struct)
{
    const psa_key_attributes_t *attributes = psa_generate_key_struct->attributes;
    psa_key_handle_t *handle               = psa_generate_key_struct->handle;

    return psa_generate_key(attributes, handle);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_mbedtls_psa_crypto_configure_entropy_sources(
    mbedtls_psa_crypto_configure_entropy_sources_struct_t *mbedtls_psa_crypto_configure_entropy_sources_struct)
{
    void (*entropy_init)(mbedtls_entropy_context * ctx) =
        mbedtls_psa_crypto_configure_entropy_sources_struct->entropy_init;
    void (*entropy_free)(mbedtls_entropy_context * ctx) =
        mbedtls_psa_crypto_configure_entropy_sources_struct->entropy_free;

    return mbedtls_psa_crypto_configure_entropy_sources(entropy_init, entropy_free);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_crypto_init(void)
{
    return psa_crypto_init();
}

/* PSA CRYPTO SLOT MANAGEMENT */

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_close_key(psa_close_key_struct_t *psa_close_key_struct)
{
    psa_key_handle_t handle = psa_close_key_struct->handle;

    return psa_close_key(handle);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_open_key(psa_open_key_struct_t *psa_open_key_struct)
{
    mbedtls_svc_key_id_t id  = psa_open_key_struct->id;
    psa_key_handle_t *handle = psa_open_key_struct->handle;

    return psa_open_key(id, handle);
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_get_empty_key_slot(
    psa_get_empty_key_slot_struct_t *psa_get_empty_key_slot_struct)
{
    psa_key_handle_t *handle = psa_get_empty_key_slot_struct->handle;
    psa_key_slot_t **p_slot  = psa_get_empty_key_slot_struct->p_slot;

    return psa_get_empty_key_slot(handle, p_slot);
}

__attribute__((cmse_nonsecure_entry)) void veneer_psa_wipe_all_key_slots(void)
{
    return psa_wipe_all_key_slots();
}

__attribute__((cmse_nonsecure_entry)) psa_status_t veneer_psa_initialize_key_slots(void)
{
    return psa_initialize_key_slots();
}
