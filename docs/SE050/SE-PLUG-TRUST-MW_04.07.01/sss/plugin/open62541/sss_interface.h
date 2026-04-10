/* Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fsl_sss_api.h>
#include <fsl_sss_se05x_types.h>
#include <stdio.h>

#if PCWindows
#define USE_SSS_DLL 0
#endif

#if USE_SSS_DLL
typedef sss_status_t (*pFunc_sss_key_store_context_init)(sss_key_store_t *keyStore, sss_session_t *session);

typedef sss_status_t (*pFunc_sss_key_store_allocate)(sss_key_store_t *keyStore, uint32_t keyStoreId);

typedef void (*pFunc_sss_key_store_context_free)(sss_key_store_t *keyStore);

typedef sss_status_t (*pFunc_sss_key_object_init)(sss_object_t *keyObject, sss_key_store_t *keyStore);

typedef void (*pFunc_sss_key_object_free)(sss_object_t *keyObject);

typedef sss_status_t (*pFunc_sss_key_object_allocate_handle)(sss_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options);

typedef sss_status_t (*pFunc_sss_key_object_get_handle)(sss_object_t *keyObject, uint32_t keyId);

typedef sss_status_t (*pFunc_sss_asymmetric_context_init)(sss_asymmetric_t *context,
    sss_session_t *session,
    sss_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

typedef void (*pFunc_sss_asymmetric_context_free)(sss_asymmetric_t *context);

typedef sss_status_t (*pFunc_sss_asymmetric_sign)(
    sss_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen);

typedef sss_status_t (*pFunc_sss_asymmetric_decrypt)(
    sss_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

typedef sss_status_t (*pFunc_sss_asymmetric_encrypt)(
    sss_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

typedef sss_status_t (*pFunc_sss_key_store_get_key)(
    sss_key_store_t *keyStore, sss_object_t *keyObject, uint8_t *data, size_t *dataLen, size_t *pKeyBitLen);

#endif

int sss_interface_init();
void sss_interface_deinit(sss_session_t *session);
int sss_interface_rsa_decrypt_data(
    unsigned char *input, unsigned int inlen, unsigned char *output, unsigned int *outLen);
int sss_interface_rsa_encrypt_data(
    unsigned char *input, unsigned int inlen, unsigned char *output, unsigned int *outLen);
int sss_interface_rsa_sign_data(unsigned char *input, unsigned int inlen, unsigned char *output, unsigned int *outLen);
int sss_interface_rsa_get_key_size();
int sss_interface_read_certificate(unsigned char **cert_buf, size_t *cert_buf_len);
int sss_interface_is_ref_key(unsigned char *pem_key, unsigned int pem_key_len);
