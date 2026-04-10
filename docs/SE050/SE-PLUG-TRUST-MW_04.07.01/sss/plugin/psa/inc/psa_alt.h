/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PSA_ALT_H_
#define _PSA_ALT_H_

#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa_crypto_its.h"
#include "psa_crypto_se.h"

/************************************************************************
 * Definitions
 ************************************************************************/

/* PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE = 0xfffffe00 */

/* Driver keystore file is defined as File Permissions (32-bit) 
 * (PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE (32-bit) + lifetime) 
 */

#define PSA_ALT_SE05X_LOCATION 50
#define PSA_ALT_SE05X_LIFETIME (PSA_ALT_SE05X_LOCATION << 8)
#define PSA_ALT_SE05X_ITS_UID (PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE + PSA_ALT_SE05X_LOCATION)
#define PSA_ALT_LIFETIME_FILE 0x1FFFFFFF

/* Transaction file : PSA_CRYPTO_ITS_TRANSACTION_UID = 0xffffff74 */
#define PSA_ALT_TRANSACTION_FILE 0x1FFFFFFE

/** Use of Internal KeyIDs
 *  0x2xxxxxxx -> Object files
 *  0x3xxxxxxx -> Secure Objects
 *  
 *  KeyID and slotID can be used inter-changeably by the app.
 *  App can specify whether to store object file in SE or flash.
 *  
 *  Slot number (Application keyID) ranges
 *  0x00000001 - 0x0FFFFFFF -> Require Flash storage for object files.
 *  0x10000000 - 0x1FFFFFFF -> Require SE storage for object files.
 *  
 *  If bit 28 of the keyID sent by app is 1, we will use SE to store 
 *  object files. Otherwise, we will use flash to store object files.
 *  Most significant nibble is still masked out - effective keyID is 
 *  28-bit.
 */

/**  
 *  Note - Since we have effective keyID of 28-bits, we can use 
 *  4 most significant bits as flags if required.
 *  
 *  PSA library also internally checks the keyID. According to PSA, 
 *  the application keyID range is from 0x00000001 - 0x3fffffff. 
 *  So, if application passes a keyID greater that 0x3fffffff, it fails.
 *  There is an option for vendor keyID which can be in range 
 *  0x40000000 - 0x7fffffff. But this is only used in psa_open_key. 
 *  While creating a new key, vendor keyID is not checked.
 *  
 *  So, we can use only 2 flags, for bit-28 and bit-29.
 */

#define PSA_ALT_OBJECT_FILE_START 0x20000000
#define PSA_ALT_OBJECT_FILE_MASK 0xF0000000
#define PSA_ALT_OBJECT_FILE_END 0x2FFFFFFF
#define PSA_ALT_OBJECT_START 0x30000000
#define PSA_ALT_OBJECT_END 0x3FFFFFFF

#define PSA_ALT_ITS_SE_FLAG ((0x1) << 28)
#define PSA_ALT_ITS_SE_MASK PSA_ALT_ITS_SE_FLAG

#define PSA_KEY_ID_TO_ALT_OBJECT_ID(id) ((id & (~PSA_ALT_OBJECT_FILE_MASK)) | PSA_ALT_OBJECT_START)
#define PSA_KEY_ID_TO_ITS_KEY_ID(id) ((id & (~PSA_ALT_OBJECT_FILE_MASK)) | PSA_ALT_OBJECT_FILE_START)

#define PSA_KEY_ID_NEEDS_ITS_FLASH(id) (!((uint32_t)(id & PSA_ALT_ITS_SE_MASK)))
#define PSA_KEY_ID_NEEDS_ITS_SE(id) (((uint32_t)(id & PSA_ALT_ITS_SE_MASK)))

/** The driver initialization function.
 *
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_driver_init(psa_drv_se_context_t *drv_context, void *persistent_data, psa_key_lifetime_t lifetime);

/** psa_drv_se_key_management_t APIs */

/** Function that allocates a slot for a key.
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_allocate_key(psa_drv_se_context_t *drv_context,
    void *persistent_data,
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_key_slot_number_t *key_slot);

/** Function that checks the validity of a slot for a key.
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_validate_slot_number(psa_drv_se_context_t *drv_context,
    void *persistent_data,
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_key_slot_number_t key_slot);

/** Function that performs a key import operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_import_key(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    size_t *bits);

/** Function that performs a generation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_generate_key(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    uint8_t *pubkey,
    size_t pubkey_size,
    size_t *pubkey_length);

/** Function that performs a key destroy operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_destroy_key(
    psa_drv_se_context_t *drv_context, void *persistent_data, psa_key_slot_number_t key_slot);

/** Function that performs a key export operation
 *  Function that performs a public key export operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_export_key(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key,
    uint8_t *p_data,
    size_t data_size,
    size_t *p_data_length);

/** psa_drv_se_mac_t APIs */
/** psa_drv_se_cipher_t APIs */

/** A function that provides the cipher setup function for a
 *  secure element driver
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_cipher_setup(psa_drv_se_context_t *drv_context,
    void *op_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t algorithm,
    psa_encrypt_or_decrypt_t direction);

/** A function that sets the initialization vector (if
 *  necessary) for an secure element cipher operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_cipher_set_iv(void *op_context, const uint8_t *p_iv, size_t iv_length);

/** A function that continues a previously started secure element cipher
 *  operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_cipher_update(void *op_context,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size,
    size_t *p_output_length);

/** A function that completes a previously started secure element cipher
 *  operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_cipher_finish(void *op_context, uint8_t *p_output, size_t output_size, size_t *p_output_length);

/** A function that aborts a previously started secure element cipher
 *  operation
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_cipher_abort(void *op_context);

/** A function that performs the ECB block mode for secure element
 *  cipher operations
 *  Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_cipher_ecb(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t algorithm,
    psa_encrypt_or_decrypt_t direction,
    const uint8_t *p_input,
    size_t input_size,
    uint8_t *p_output,
    size_t output_size);

/** psa_drv_se_aead_t APIs */
/** psa_drv_se_asymmetric_t APIs */

/**
 * A function that signs a hash or short message with a private key in
 * a secure element
 * Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */

psa_status_t psa_alt_asymmetric_sign_digest(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    const uint8_t *p_hash,
    size_t hash_length,
    uint8_t *p_signature,
    size_t signature_size,
    size_t *p_signature_length);

/**
 * A function that verifies the signature a hash or short message using
 * an asymmetric public key in a secure element
 * Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_asymmetric_verify_digest(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    const uint8_t *p_hash,
    size_t hash_length,
    const uint8_t *p_signature,
    size_t signature_length);

/**
 * A function that encrypts a short message with an asymmetric public
 * key in a secure element
 * Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_asymmetric_encrypt(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    const uint8_t *p_input,
    size_t input_length,
    const uint8_t *p_salt,
    size_t salt_length,
    uint8_t *p_output,
    size_t output_size,
    size_t *p_output_length);

/**
 * A function that decrypts a short message with an asymmetric private
 * key in a secure element.
 * Refer to mbed-crypto\include\psa\crypto_se_driver.h
 */
psa_status_t psa_alt_asymmetric_decrypt(psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    psa_algorithm_t alg,
    const uint8_t *p_input,
    size_t input_length,
    const uint8_t *p_salt,
    size_t salt_length,
    uint8_t *p_output,
    size_t output_size,
    size_t *p_output_length);

/** psa_drv_se_key_derivation_t APIs */

psa_status_t psa_alt_store_se_its_file(psa_storage_uid_t uid, uint8_t *data, size_t dataLen);

psa_status_t psa_alt_read_se_its_file(psa_storage_uid_t uid, uint8_t *data, size_t *dataLen);

psa_status_t psa_alt_remove_se_its_file(psa_storage_uid_t uid);

psa_status_t psa_alt_store_flash_its_file(psa_storage_uid_t uid, uint8_t *data, size_t dataLen);

psa_status_t psa_alt_read_flash_its_file(psa_storage_uid_t uid, uint8_t *data, size_t *dataLen);

psa_status_t psa_alt_remove_flash_its_file(psa_storage_uid_t uid);
#endif //_PSA_ALT_H_
