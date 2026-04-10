/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef FSL_SSS_BASE_APIS_HPP_H
#define FSL_SSS_BASE_APIS_HPP_H

extern "C" {
#include <fsl_sss_api.h>
} // extern "C"
namespace sss {

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

class I_keyobj; /* forward declaration for keystore */

class I_keystore; /* forward declaration for keyobj */

class I_session {
   public:
    virtual void *getCtx() = 0;
    virtual sss_status_t create(
        sss_type_t subsystem, uint32_t application_id, sss_connection_type_t connection_type, void *connectionData) = 0;

    virtual sss_status_t open(
        sss_type_t subsystem, uint32_t application_id, sss_connection_type_t connection_type, void *connectionData) = 0;

    virtual sss_status_t prop_get_u32(uint32_t property, uint32_t *pValue) = 0;

    virtual sss_status_t prop_get_au8(uint32_t property, uint8_t *pValue, size_t *pValueLen) = 0;

    virtual void close() = 0;

    virtual void dodelete() = 0;

}; /* I_session */

class I_keyobj {
   public:
    virtual void *getCtx()                          = 0;
    virtual sss_status_t init(I_keystore *keyStore) = 0;

    virtual sss_status_t allocate_handle(uint32_t keyId,
        sss_key_part_t keyPart,
        sss_cipher_type_t cipherType,
        size_t keyByteLenMax,
        uint32_t options) = 0;

    virtual sss_status_t get_handle(uint32_t keyId) = 0;

    virtual sss_status_t set_user(uint32_t user, uint32_t options) = 0;

    virtual sss_status_t set_purpose(sss_mode_t purpose, uint32_t options) = 0;

    virtual sss_status_t set_access(uint32_t access, uint32_t options) = 0;

    virtual sss_status_t set_eccgfp_group(sss_eccgfp_group_t *group) = 0;

    virtual sss_status_t get_user(uint32_t *user) = 0;

    virtual sss_status_t get_purpose(sss_mode_t *purpose) = 0;

    virtual sss_status_t get_access(uint32_t *access) = 0;

    virtual void free() = 0;

}; /* I_keyobj */

class I_keyderive {
   public:
    virtual void *getCtx() = 0;
    virtual sss_status_t context_init(
        I_session *session, I_keyobj *keyObject, sss_algorithm_t algorithm, sss_mode_t mode) = 0;

    virtual sss_status_t go(const uint8_t *saltData,
        size_t saltLen,
        const uint8_t *info,
        size_t infoLen,
        I_keyobj *derivedKeyObject,
        uint16_t deriveDataLen,
        uint8_t *hkdfOutput,
        size_t *hkdfOutputLen) = 0;

    virtual sss_status_t dh(I_keyobj *otherPartyKeyObject, I_keyobj *derivedKeyObject) = 0;

    virtual void context_free() = 0;

}; /* I_keyderive */

class I_keystore {
   public:
    virtual void *getCtx()                                = 0;
    virtual sss_status_t context_init(I_session *session) = 0;

    virtual sss_status_t allocate(uint32_t keyStoreId) = 0;

    virtual sss_status_t save() = 0;

    virtual sss_status_t load() = 0;

    virtual sss_status_t set_key(I_keyobj *keyObject,
        const uint8_t *data,
        size_t dataLen,
        size_t keyBitLen,
        void *options,
        size_t optionsLen) = 0;

    virtual sss_status_t generate_key(I_keyobj *keyObject, size_t keyBitLen, void *options) = 0;

    virtual sss_status_t get_key(I_keyobj *keyObject, uint8_t *data, size_t *dataLen, size_t *pKeyBitLen) = 0;

    virtual sss_status_t open_key(I_keyobj *keyObject) = 0;

    virtual sss_status_t freeze_key(I_keyobj *keyObject) = 0;

    virtual sss_status_t erase_key(I_keyobj *keyObject) = 0;

    virtual void context_free() = 0;

}; /* I_keystore */

class I_asym {
   public:
    virtual void *getCtx() = 0;
    virtual sss_status_t context_init(
        I_session *session, I_keyobj *keyObject, sss_algorithm_t algorithm, sss_mode_t mode) = 0;

    virtual sss_status_t encrypt(const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen) = 0;

    virtual sss_status_t decrypt(const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen) = 0;

    virtual sss_status_t sign_digest(uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen) = 0;

    virtual sss_status_t verify_digest(uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen) = 0;

    virtual void context_free() = 0;

}; /* I_asym */

class I_symm {
   public:
    virtual void *getCtx() = 0;
    virtual sss_status_t context_init(
        I_session *session, I_keyobj *keyObject, sss_algorithm_t algorithm, sss_mode_t mode) = 0;

    virtual sss_status_t one_go(
        uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen) = 0;

    virtual sss_status_t init(uint8_t *iv, size_t ivLen) = 0;

    virtual sss_status_t update(const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen) = 0;

    virtual sss_status_t finish(const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen) = 0;

    virtual sss_status_t crypt_ctr(const uint8_t *srcData,
        uint8_t *destData,
        size_t size,
        uint8_t *initialCounter,
        uint8_t *lastEncryptedCounter,
        size_t *szLeft) = 0;

    virtual void context_free() = 0;

}; /* I_symm */

class I_aead {
   public:
    virtual void *getCtx() = 0;
    virtual sss_status_t context_init(
        I_session *session, I_keyobj *keyObject, sss_algorithm_t algorithm, sss_mode_t mode) = 0;

    virtual sss_status_t one_go(const uint8_t *srcData,
        uint8_t *destData,
        size_t size,
        uint8_t *nonce,
        size_t nonceLen,
        const uint8_t *aad,
        size_t aadLen,
        uint8_t *tag,
        size_t *tagLen) = 0;

    virtual sss_status_t init(uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen) = 0;

    virtual sss_status_t update_aad(const uint8_t *aadData, size_t aadDataLen) = 0;

    virtual sss_status_t update(const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen) = 0;

    virtual sss_status_t finish(
        const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen, uint8_t *tag, size_t *tagLen) = 0;

    virtual void context_free() = 0;

}; /* I_aead */

class I_mac {
   public:
    virtual void *getCtx() = 0;
    virtual sss_status_t context_init(
        I_session *session, I_keyobj *keyObject, sss_algorithm_t algorithm, sss_mode_t mode) = 0;

    virtual sss_status_t one_go(const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen) = 0;

    virtual sss_status_t init() = 0;

    virtual sss_status_t update(const uint8_t *message, size_t messageLen) = 0;

    virtual sss_status_t finish(uint8_t *mac, size_t *macLen) = 0;

    virtual void context_free() = 0;

}; /* I_mac */

class I_md {
   public:
    virtual void *getCtx()                                                                            = 0;
    virtual sss_status_t context_init(I_session *session, sss_algorithm_t algorithm, sss_mode_t mode) = 0;

    virtual sss_status_t one_go(const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen) = 0;

    virtual sss_status_t init() = 0;

    virtual sss_status_t update(const uint8_t *message, size_t messageLen) = 0;

    virtual sss_status_t finish(uint8_t *digest, size_t *digestLen) = 0;

    virtual void context_free() = 0;

}; /* I_md */

class I_rng {
   public:
    virtual void *getCtx()                                = 0;
    virtual sss_status_t context_init(I_session *session) = 0;

    virtual sss_status_t get_random(uint8_t *random_data, size_t dataLen) = 0;

    virtual sss_status_t context_free() = 0;

}; /* I_rng */

} // namespace sss
#endif /* FSL_SSS_BASE_APIS_HPP_H */
