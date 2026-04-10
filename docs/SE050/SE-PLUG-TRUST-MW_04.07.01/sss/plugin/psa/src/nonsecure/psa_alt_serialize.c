/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * THIS FILE MUST BE USED WHEN BUILDING FOR NON-SECURE ZONE.
 * IT WILL CREATE STRUCTURES OF INPUT VARIABLES AND PASS TO PSA_ALT_DESERIALIZE.C
 * THE ACTUAL IMPLEMENTATION WILL BE IN PSA_ALT_DESERIALIZE.C
 * PSA_ALT_DESERIALIZE.C WILL BE RUNNING IN SECURE ZONE WHILE THIS FILE WILL BE 
 * IN NON-SECURE ZONE
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
#include "sss_psa_alt.h"

#include "psa_alt_serialize_struct.h"
#include "psa_alt_deserialize.h"

psa_status_t psa_import_key_into_slot(const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length,
    size_t *bits)
{
    psa_import_key_into_slot_struct_t psa_import_key_into_slot_struct = {
        .attributes        = attributes,
        .data              = data,
        .data_length       = data_length,
        .key_buffer        = key_buffer,
        .key_buffer_size   = key_buffer_size,
        .key_buffer_length = key_buffer_length,
        .bits              = bits,
    };
    return veneer_psa_import_key_into_slot(&psa_import_key_into_slot_struct);
}

psa_status_t psa_wipe_key_slot(psa_key_slot_t *slot)
{
    psa_wipe_key_slot_struct_t psa_wipe_key_slot_struct = {
        .slot = slot,
    };
    return veneer_psa_wipe_key_slot(&psa_wipe_key_slot_struct);
}

psa_status_t psa_destroy_key(psa_key_handle_t handle)
{
    psa_destroy_key_struct_t psa_destroy_key_struct = {
        .handle = handle,
    };
    return veneer_psa_destroy_key(&psa_destroy_key_struct);
}

psa_status_t psa_set_key_domain_parameters(
    psa_key_attributes_t *attributes, psa_key_type_t type, const uint8_t *data, size_t data_length)
{
    psa_set_key_domain_parameters_struct_t psa_set_key_domain_parameters_struct = {
        .attributes  = attributes,
        .type        = type,
        .data        = data,
        .data_length = data_length,
    };
    return veneer_psa_set_key_domain_parameters(&psa_set_key_domain_parameters_struct);
}

psa_status_t psa_get_key_domain_parameters(
    const psa_key_attributes_t *attributes, uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_get_key_domain_parameters_struct_t psa_get_key_domain_parameters_struct = {
        .attributes  = attributes,
        .data        = data,
        .data_size   = data_size,
        .data_length = data_length,
    };
    return veneer_psa_get_key_domain_parameters(&psa_get_key_domain_parameters_struct);
}

psa_status_t psa_get_key_attributes(psa_key_handle_t handle, psa_key_attributes_t *attributes)
{
    psa_get_key_attributes_struct_t psa_get_key_attributes_struct = {
        .handle     = handle,
        .attributes = attributes,
    };
    return veneer_psa_get_key_attributes(&psa_get_key_attributes_struct);
}

psa_status_t psa_get_key_slot_number(const psa_key_attributes_t *attributes, psa_key_slot_number_t *slot_number)
{
    psa_get_key_slot_number_struct_t psa_get_key_slot_number_struct = {
        .attributes  = attributes,
        .slot_number = slot_number,
    };
    return veneer_psa_get_key_slot_number(&psa_get_key_slot_number_struct);
}

psa_status_t psa_export_key(psa_key_handle_t handle, uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_export_key_struct_t psa_export_key_struct = {
        .handle      = handle,
        .data        = data,
        .data_size   = data_size,
        .data_length = data_length,
    };
    return veneer_psa_export_key(&psa_export_key_struct);
}

psa_status_t psa_export_public_key(psa_key_handle_t handle, uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_export_public_key_struct_t psa_export_public_key_struct = {
        .handle      = handle,
        .data        = data,
        .data_size   = data_size,
        .data_length = data_length,
    };
    return veneer_psa_export_public_key(&psa_export_public_key_struct);
}

psa_status_t psa_import_key(
    const psa_key_attributes_t *attributes, const uint8_t *data, size_t data_length, psa_key_handle_t *handle)
{
    psa_import_key_struct_t psa_import_key_struct = {
        .attributes  = attributes,
        .data        = data,
        .data_length = data_length,
        .handle      = handle,
    };
    return veneer_psa_import_key(&psa_import_key_struct);
}

psa_status_t mbedtls_psa_register_se_key(const psa_key_attributes_t *attributes)
{
    mbedtls_psa_register_se_key_struct_t mbedtls_psa_register_se_key_struct = {
        .attributes = attributes,
    };
    return veneer_mbedtls_psa_register_se_key(&mbedtls_psa_register_se_key_struct);
}

psa_status_t psa_copy_key(
    psa_key_handle_t source_handle, const psa_key_attributes_t *specified_attributes, psa_key_handle_t *target_handle)
{
    psa_copy_key_struct_t psa_copy_key_struct = {
        .source_handle        = source_handle,
        .specified_attributes = specified_attributes,
        .target_handle        = target_handle,
    };
    return veneer_psa_copy_key(&psa_copy_key_struct);
}

psa_status_t psa_hash_abort(psa_hash_operation_t *operation)
{
    psa_hash_abort_struct_t psa_hash_abort_struct = {
        .operation = operation,
    };
    return veneer_psa_hash_abort(&psa_hash_abort_struct);
}

psa_status_t psa_hash_setup(psa_hash_operation_t *operation, psa_algorithm_t alg)
{
    psa_hash_setup_struct_t psa_hash_setup_struct = {
        .operation = operation,
        .alg       = alg,
    };
    return veneer_psa_hash_setup(&psa_hash_setup_struct);
}

psa_status_t psa_hash_update(psa_hash_operation_t *operation, const uint8_t *input, size_t input_length)
{
    psa_hash_update_struct_t psa_hash_update_struct = {
        .operation    = operation,
        .input        = input,
        .input_length = input_length,
    };
    return veneer_psa_hash_update(&psa_hash_update_struct);
}

psa_status_t psa_hash_finish(psa_hash_operation_t *operation, uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    psa_hash_finish_struct_t psa_hash_finish_struct = {
        .operation   = operation,
        .hash        = hash,
        .hash_size   = hash_size,
        .hash_length = hash_length,
    };
    return veneer_psa_hash_finish(&psa_hash_finish_struct);
}

psa_status_t psa_hash_verify(psa_hash_operation_t *operation, const uint8_t *hash, size_t hash_length)
{
    psa_hash_verify_struct_t psa_hash_verify_struct = {
        .operation   = operation,
        .hash        = hash,
        .hash_length = hash_length,
    };
    return veneer_psa_hash_verify(&psa_hash_verify_struct);
}

psa_status_t psa_hash_clone(const psa_hash_operation_t *source_operation, psa_hash_operation_t *target_operation)
{
    psa_hash_clone_struct_t psa_hash_clone_struct = {
        .source_operation = source_operation,
        .target_operation = target_operation,
    };
    return veneer_psa_hash_clone(&psa_hash_clone_struct);
}

psa_status_t psa_mac_abort(psa_mac_operation_t *operation)
{
    psa_mac_abort_struct_t psa_mac_abort_struct = {
        .operation = operation,
    };
    return veneer_psa_mac_abort(&psa_mac_abort_struct);
}

psa_status_t psa_mac_sign_setup(psa_mac_operation_t *operation, psa_key_handle_t handle, psa_algorithm_t alg)
{
    psa_mac_sign_setup_struct_t psa_mac_sign_setup_struct = {
        .operation = operation,
        .handle    = handle,
        .alg       = alg,
    };
    return veneer_psa_mac_sign_setup(&psa_mac_sign_setup_struct);
}

psa_status_t psa_mac_verify_setup(psa_mac_operation_t *operation, psa_key_handle_t handle, psa_algorithm_t alg)
{
    psa_mac_verify_setup_struct_t psa_mac_verify_setup_struct = {
        .operation = operation,
        .handle    = handle,
        .alg       = alg,
    };
    return veneer_psa_mac_verify_setup(&psa_mac_verify_setup_struct);
}

psa_status_t psa_mac_update(psa_mac_operation_t *operation, const uint8_t *input, size_t input_length)
{
    psa_mac_update_struct_t psa_mac_update_struct = {
        .operation    = operation,
        .input        = input,
        .input_length = input_length,
    };
    return veneer_psa_mac_update(&psa_mac_update_struct);
}

psa_status_t psa_mac_sign_finish(psa_mac_operation_t *operation, uint8_t *mac, size_t mac_size, size_t *mac_length)
{
    psa_mac_sign_finish_struct_t psa_mac_sign_finish_struct = {
        .operation  = operation,
        .mac        = mac,
        .mac_size   = mac_size,
        .mac_length = mac_length,
    };
    return veneer_psa_mac_sign_finish(&psa_mac_sign_finish_struct);
}

psa_status_t psa_mac_verify_finish(psa_mac_operation_t *operation, const uint8_t *mac, size_t mac_length)
{
    psa_mac_verify_finish_struct_t psa_mac_verify_finish_struct = {
        .operation  = operation,
        .mac        = mac,
        .mac_length = mac_length,
    };
    return veneer_psa_mac_verify_finish(&psa_mac_verify_finish_struct);
}

psa_status_t psa_sign_hash(psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length)
{
    psa_sign_hash_struct_t psa_sign_hash_struct = {
        .handle           = handle,
        .alg              = alg,
        .hash             = hash,
        .hash_length      = hash_length,
        .signature        = signature,
        .signature_size   = signature_size,
        .signature_length = signature_length,
    };
    return veneer_psa_sign_hash(&psa_sign_hash_struct);
}

psa_status_t psa_verify_hash(psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length)
{
    psa_verify_hash_struct_t psa_verify_hash_struct = {
        .handle           = handle,
        .alg              = alg,
        .hash             = hash,
        .hash_length      = hash_length,
        .signature        = signature,
        .signature_length = signature_length,
    };
    return veneer_psa_verify_hash(&psa_verify_hash_struct);
}

psa_status_t psa_asymmetric_encrypt(psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    const uint8_t *salt,
    size_t salt_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    psa_asymmetric_encrypt_struct_t psa_asymmetric_encrypt_struct = {
        .handle        = handle,
        .alg           = alg,
        .input         = input,
        .input_length  = input_length,
        .salt          = salt,
        .salt_length   = salt_length,
        .output        = output,
        .output_size   = output_size,
        .output_length = output_length,
    };
    return veneer_psa_asymmetric_encrypt(&psa_asymmetric_encrypt_struct);
}

psa_status_t psa_asymmetric_decrypt(psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    const uint8_t *salt,
    size_t salt_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    psa_asymmetric_decrypt_struct_t psa_asymmetric_decrypt_struct = {
        .handle        = handle,
        .alg           = alg,
        .input         = input,
        .input_length  = input_length,
        .salt          = salt,
        .salt_length   = salt_length,
        .output        = output,
        .output_size   = output_size,
        .output_length = output_length,
    };
    return veneer_psa_asymmetric_decrypt(&psa_asymmetric_decrypt_struct);
}

psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t *operation, psa_key_handle_t handle, psa_algorithm_t alg)
{
    psa_cipher_encrypt_setup_struct_t psa_cipher_encrypt_setup_struct = {
        .operation = operation,
        .handle    = handle,
        .alg       = alg,
    };
    return veneer_psa_cipher_encrypt_setup(&psa_cipher_encrypt_setup_struct);
}

psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t *operation, psa_key_handle_t handle, psa_algorithm_t alg)
{
    psa_cipher_decrypt_setup_struct_t psa_cipher_decrypt_setup_struct = {
        .operation = operation,
        .handle    = handle,
        .alg       = alg,
    };
    return veneer_psa_cipher_decrypt_setup(&psa_cipher_decrypt_setup_struct);
}

psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t *operation, uint8_t *iv, size_t iv_size, size_t *iv_length)
{
    psa_cipher_generate_iv_struct_t psa_cipher_generate_iv_struct = {
        .operation = operation,
        .iv        = iv,
        .iv_size   = iv_size,
        .iv_length = iv_length,
    };
    return veneer_psa_cipher_generate_iv(&psa_cipher_generate_iv_struct);
}

psa_status_t psa_cipher_set_iv(psa_cipher_operation_t *operation, const uint8_t *iv, size_t iv_length)
{
    psa_cipher_set_iv_struct_t psa_cipher_set_iv_struct = {
        .operation = operation,
        .iv        = iv,
        .iv_length = iv_length,
    };
    return veneer_psa_cipher_set_iv(&psa_cipher_set_iv_struct);
}

psa_status_t psa_cipher_update(psa_cipher_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    psa_cipher_update_struct_t psa_cipher_update_struct = {
        .operation     = operation,
        .input         = input,
        .input_length  = input_length,
        .output        = output,
        .output_size   = output_size,
        .output_length = output_length,
    };
    return veneer_psa_cipher_update(&psa_cipher_update_struct);
}

psa_status_t psa_cipher_finish(
    psa_cipher_operation_t *operation, uint8_t *output, size_t output_size, size_t *output_length)
{
    psa_cipher_finish_struct_t psa_cipher_finish_struct = {
        .operation     = operation,
        .output        = output,
        .output_size   = output_size,
        .output_length = output_length,
    };
    return veneer_psa_cipher_finish(&psa_cipher_finish_struct);
}

psa_status_t psa_cipher_abort(psa_cipher_operation_t *operation)
{
    psa_cipher_abort_struct_t psa_cipher_abort_struct = {
        .operation = operation,
    };
    return veneer_psa_cipher_abort(&psa_cipher_abort_struct);
}

psa_status_t psa_aead_encrypt(psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length)
{
    psa_aead_encrypt_struct_t psa_aead_encrypt_struct = {
        .handle                 = handle,
        .alg                    = alg,
        .nonce                  = nonce,
        .nonce_length           = nonce_length,
        .additional_data        = additional_data,
        .additional_data_length = additional_data_length,
        .plaintext              = plaintext,
        .plaintext_length       = plaintext_length,
        .ciphertext             = ciphertext,
        .ciphertext_size        = ciphertext_size,
        .ciphertext_length      = ciphertext_length,
    };
    return veneer_psa_aead_encrypt(&psa_aead_encrypt_struct);
}

psa_status_t psa_aead_decrypt(psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length)
{
    psa_aead_decrypt_struct_t psa_aead_decrypt_struct = {
        .handle                 = handle,
        .alg                    = alg,
        .nonce                  = nonce,
        .nonce_length           = nonce_length,
        .additional_data        = additional_data,
        .additional_data_length = additional_data_length,
        .ciphertext             = ciphertext,
        .ciphertext_length      = ciphertext_length,
        .plaintext              = plaintext,
        .plaintext_size         = plaintext_size,
        .plaintext_length       = plaintext_length,
    };
    return veneer_psa_aead_decrypt(&psa_aead_decrypt_struct);
}

psa_status_t psa_key_derivation_abort(psa_key_derivation_operation_t *operation)
{
    psa_key_derivation_abort_struct_t psa_key_derivation_abort_struct = {
        .operation = operation,
    };
    return veneer_psa_key_derivation_abort(&psa_key_derivation_abort_struct);
}

psa_status_t psa_key_derivation_get_capacity(const psa_key_derivation_operation_t *operation, size_t *capacity)
{
    psa_key_derivation_get_capacity_struct_t psa_key_derivation_get_capacity_struct = {
        .operation = operation,
        .capacity  = capacity,
    };
    return veneer_psa_key_derivation_get_capacity(&psa_key_derivation_get_capacity_struct);
}

psa_status_t psa_key_derivation_set_capacity(psa_key_derivation_operation_t *operation, size_t capacity)
{
    psa_key_derivation_set_capacity_struct_t psa_key_derivation_set_capacity_struct = {
        .operation = operation,
        .capacity  = capacity,
    };
    return veneer_psa_key_derivation_set_capacity(&psa_key_derivation_set_capacity_struct);
}

psa_status_t psa_key_derivation_output_bytes(
    psa_key_derivation_operation_t *operation, uint8_t *output, size_t output_length)
{
    psa_key_derivation_output_bytes_struct_t psa_key_derivation_output_bytes_struct = {
        .operation     = operation,
        .output        = output,
        .output_length = output_length,
    };
    return veneer_psa_key_derivation_output_bytes(&psa_key_derivation_output_bytes_struct);
}

psa_status_t psa_key_derivation_output_key(
    const psa_key_attributes_t *attributes, psa_key_derivation_operation_t *operation, psa_key_handle_t *handle)
{
    psa_key_derivation_output_key_struct_t psa_key_derivation_output_key_struct = {
        .attributes = attributes,
        .operation  = operation,
        .handle     = handle,
    };
    return veneer_psa_key_derivation_output_key(&psa_key_derivation_output_key_struct);
}

psa_status_t psa_key_derivation_setup(psa_key_derivation_operation_t *operation, psa_algorithm_t alg)
{
    psa_key_derivation_setup_struct_t psa_key_derivation_setup_struct = {
        .operation = operation,
        .alg       = alg,
    };
    return veneer_psa_key_derivation_setup(&psa_key_derivation_setup_struct);
}

psa_status_t psa_key_derivation_input_bytes(
    psa_key_derivation_operation_t *operation, psa_key_derivation_step_t step, const uint8_t *data, size_t data_length)
{
    psa_key_derivation_input_bytes_struct_t psa_key_derivation_input_bytes_struct = {
        .operation   = operation,
        .step        = step,
        .data        = data,
        .data_length = data_length,
    };
    return veneer_psa_key_derivation_input_bytes(&psa_key_derivation_input_bytes_struct);
}

psa_status_t psa_key_derivation_input_key(
    psa_key_derivation_operation_t *operation, psa_key_derivation_step_t step, psa_key_handle_t handle)
{
    psa_key_derivation_input_key_struct_t psa_key_derivation_input_key_struct = {
        .operation = operation,
        .step      = step,
        .handle    = handle,
    };
    return veneer_psa_key_derivation_input_key(&psa_key_derivation_input_key_struct);
}

psa_status_t psa_key_derivation_key_agreement(psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    psa_key_handle_t private_key,
    const uint8_t *peer_key,
    size_t peer_key_length)
{
    psa_key_derivation_key_agreement_struct_t psa_key_derivation_key_agreement_struct = {
        .operation       = operation,
        .step            = step,
        .private_key     = private_key,
        .peer_key        = peer_key,
        .peer_key_length = peer_key_length,
    };
    return veneer_psa_key_derivation_key_agreement(&psa_key_derivation_key_agreement_struct);
}

psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
    psa_key_handle_t private_key,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    psa_raw_key_agreement_struct_t psa_raw_key_agreement_struct = {
        .alg             = alg,
        .private_key     = private_key,
        .peer_key        = peer_key,
        .peer_key_length = peer_key_length,
        .output          = output,
        .output_size     = output_size,
        .output_length   = output_length,
    };
    return veneer_psa_raw_key_agreement(&psa_raw_key_agreement_struct);
}

psa_status_t psa_generate_random(uint8_t *output, size_t output_size)
{
    psa_generate_random_struct_t psa_generate_random_struct = {
        .output      = output,
        .output_size = output_size,
    };
    return veneer_psa_generate_random(&psa_generate_random_struct);
}

#if defined(MBEDTLS_PSA_INJECT_ENTROPY)
psa_status_t mbedtls_psa_inject_entropy(const uint8_t *seed, size_t seed_size)
{
    mbedtls_psa_inject_entropy_struct_t mbedtls_psa_inject_entropy_struct = {
        .seed      = seed,
        .seed_size = seed_size,
    };
    return veneer_mbedtls_psa_inject_entropy(&mbedtls_psa_inject_entropy_struct);
}
#endif

psa_status_t psa_generate_key(const psa_key_attributes_t *attributes, psa_key_handle_t *handle)
{
    psa_generate_key_struct_t psa_generate_key_struct = {
        .attributes = attributes,
        .handle     = handle,
    };
    return veneer_psa_generate_key(&psa_generate_key_struct);
}

psa_status_t mbedtls_psa_crypto_configure_entropy_sources(
    void (*entropy_init)(mbedtls_entropy_context *ctx), void (*entropy_free)(mbedtls_entropy_context *ctx))
{
    mbedtls_psa_crypto_configure_entropy_sources_struct_t mbedtls_psa_crypto_configure_entropy_sources_struct = {
        .entropy_init = entropy_init,
        .entropy_free = entropy_free,
    };
    return veneer_mbedtls_psa_crypto_configure_entropy_sources(&mbedtls_psa_crypto_configure_entropy_sources_struct);
}

psa_status_t psa_crypto_init(void)
{
    return veneer_psa_crypto_init();
}

/* PSA CRYPTO SLOT MANAGEMENT */

psa_status_t psa_close_key(psa_key_handle_t handle)
{
    psa_close_key_struct_t psa_close_key_struct = {
        .handle = handle,
    };
    return veneer_psa_close_key(&psa_close_key_struct);
}

psa_status_t psa_open_key(mbedtls_svc_key_id_t id, psa_key_handle_t *handle)
{
    psa_open_key_struct_t psa_open_key_struct = {
        .id     = id,
        .handle = handle,
    };
    return veneer_psa_open_key(&psa_open_key_struct);
}

psa_status_t psa_get_empty_key_slot(psa_key_handle_t *handle, psa_key_slot_t **p_slot)
{
    psa_get_empty_key_slot_struct_t psa_get_empty_key_slot_struct = {
        .handle = handle,
        .p_slot = p_slot,
    };
    return veneer_psa_get_empty_key_slot(&psa_get_empty_key_slot_struct);
}

void psa_wipe_all_key_slots(void)
{
    return veneer_psa_wipe_all_key_slots();
}

psa_status_t psa_initialize_key_slots(void)
{
    return veneer_psa_initialize_key_slots();
}
