/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef FSL_SSS_SE05X_APIS_HPP_H
#define FSL_SSS_SE05X_APIS_HPP_H

#include <fsl_sss_se05x_apis.h>

#include <fsl_sss_base_apis.hpp>

#if SSS_HAVE_APPLET_SE05X_IOT

namespace sss {
/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

class SESSION_SE05X : public I_session {
   protected:
    sss_se05x_session_t ctx;

   public:
    void *getCtx();
    virtual sss_status_t create(
        sss_type_t subsystem, uint32_t application_id, sss_connection_type_t connection_type, void *connectionData);

    virtual sss_status_t open(
        sss_type_t subsystem, uint32_t application_id, sss_connection_type_t connection_type, void *connectionData);

    virtual sss_status_t prop_get_u32(uint32_t property, uint32_t *pValue);

    virtual sss_status_t prop_get_au8(uint32_t property, uint8_t *pValue, size_t *pValueLen);

    virtual void close();

    virtual void dodelete();

}; /* SESSION_SE05X */

class KEYOBJ_SE05X : public I_keyobj {
   protected:
    sss_se05x_object_t ctx;

   public:
    void *getCtx();
    virtual sss_status_t init(I_keystore *keyStore);

    virtual sss_status_t allocate_handle(
        uint32_t keyId, sss_key_part_t keyPart, sss_cipher_type_t cipherType, size_t keyByteLenMax, uint32_t options);

    virtual sss_status_t get_handle(uint32_t keyId);

    virtual sss_status_t set_user(uint32_t user, uint32_t options);

    virtual sss_status_t set_purpose(sss_mode_t purpose, uint32_t options);

    virtual sss_status_t set_access(uint32_t access, uint32_t options);

    virtual sss_status_t set_eccgfp_group(sss_eccgfp_group_t *group);

    virtual sss_status_t get_user(uint32_t *user);

    virtual sss_status_t get_purpose(sss_mode_t *purpose);

    virtual sss_status_t get_access(uint32_t *access);

    virtual void free();

}; /* KEYOBJ_SE05X */

class KEYDERIVE_SE05X : public I_keyderive {
   protected:
    sss_se05x_derive_key_t ctx;

   public:
    void *getCtx();
    virtual sss_status_t context_init(
        I_session *session, I_keyobj *keyObject, sss_algorithm_t algorithm, sss_mode_t mode);

    virtual sss_status_t go(const uint8_t *saltData,
        size_t saltLen,
        const uint8_t *info,
        size_t infoLen,
        I_keyobj *derivedKeyObject,
        uint16_t deriveDataLen,
        uint8_t *hkdfOutput,
        size_t *hkdfOutputLen);

    virtual sss_status_t dh(I_keyobj *otherPartyKeyObject, I_keyobj *derivedKeyObject);

    virtual void context_free();

}; /* KEYDERIVE_SE05X */

class KEYSTORE_SE05X : public I_keystore {
   protected:
    sss_se05x_key_store_t ctx;

   public:
    void *getCtx();
    virtual sss_status_t context_init(I_session *session);

    virtual sss_status_t allocate(uint32_t keyStoreId);

    virtual sss_status_t save();

    virtual sss_status_t load();

    virtual sss_status_t set_key(
        I_keyobj *keyObject, const uint8_t *data, size_t dataLen, size_t keyBitLen, void *options, size_t optionsLen);

    virtual sss_status_t generate_key(I_keyobj *keyObject, size_t keyBitLen, void *options);

    virtual sss_status_t get_key(I_keyobj *keyObject, uint8_t *data, size_t *dataLen, size_t *pKeyBitLen);

    virtual sss_status_t open_key(I_keyobj *keyObject);

    virtual sss_status_t freeze_key(I_keyobj *keyObject);

    virtual sss_status_t erase_key(I_keyobj *keyObject);

    virtual void context_free();

}; /* KEYSTORE_SE05X */

class ASYM_SE05X : public I_asym {
   protected:
    sss_se05x_asymmetric_t ctx;

   public:
    void *getCtx();
    virtual sss_status_t context_init(
        I_session *session, I_keyobj *keyObject, sss_algorithm_t algorithm, sss_mode_t mode);

    virtual sss_status_t encrypt(const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

    virtual sss_status_t decrypt(const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

    virtual sss_status_t sign_digest(uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen);

    virtual sss_status_t verify_digest(uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen);

    virtual void context_free();

}; /* ASYM_SE05X */

class SYMM_SE05X : public I_symm {
   protected:
    sss_se05x_symmetric_t ctx;

   public:
    void *getCtx();
    virtual sss_status_t context_init(
        I_session *session, I_keyobj *keyObject, sss_algorithm_t algorithm, sss_mode_t mode);

    virtual sss_status_t one_go(uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen);

    virtual sss_status_t one_go_v2(
        uint8_t *iv, size_t ivLen, const uint8_t *srcData, const size_t srcLen, uint8_t *destData, size_t *pDataLen);

    virtual sss_status_t init(uint8_t *iv, size_t ivLen);

    virtual sss_status_t update(const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

    virtual sss_status_t finish(const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

    virtual sss_status_t crypt_ctr(const uint8_t *srcData,
        uint8_t *destData,
        size_t size,
        uint8_t *initialCounter,
        uint8_t *lastEncryptedCounter,
        size_t *szLeft);

    virtual void context_free();

}; /* SYMM_SE05X */

class AEAD_SE05X : public I_aead {
   protected:
    sss_se05x_aead_t ctx;

   public:
    void *getCtx();
    virtual sss_status_t context_init(
        I_session *session, I_keyobj *keyObject, sss_algorithm_t algorithm, sss_mode_t mode);

    virtual sss_status_t one_go(const uint8_t *srcData,
        uint8_t *destData,
        size_t size,
        uint8_t *nonce,
        size_t nonceLen,
        const uint8_t *aad,
        size_t aadLen,
        uint8_t *tag,
        size_t *tagLen);

    virtual sss_status_t init(uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen);

    virtual sss_status_t update_aad(const uint8_t *aadData, size_t aadDataLen);

    virtual sss_status_t update(const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

    virtual sss_status_t finish(
        const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen, uint8_t *tag, size_t *tagLen);

    virtual void context_free();

}; /* AEAD_SE05X */

class MAC_SE05X : public I_mac {
   protected:
    sss_se05x_mac_t ctx;

   public:
    void *getCtx();
    virtual sss_status_t context_init(
        I_session *session, I_keyobj *keyObject, sss_algorithm_t algorithm, sss_mode_t mode);

    virtual sss_status_t one_go(const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen);

    virtual sss_status_t init();

    virtual sss_status_t update(const uint8_t *message, size_t messageLen);

    virtual sss_status_t finish(uint8_t *mac, size_t *macLen);

    virtual void context_free();

}; /* MAC_SE05X */

class MD_SE05X : public I_md {
   protected:
    sss_se05x_digest_t ctx;

   public:
    void *getCtx();
    virtual sss_status_t context_init(I_session *session, sss_algorithm_t algorithm, sss_mode_t mode);

    virtual sss_status_t one_go(const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen);

    virtual sss_status_t init();

    virtual sss_status_t update(const uint8_t *message, size_t messageLen);

    virtual sss_status_t finish(uint8_t *digest, size_t *digestLen);

    virtual void context_free();

}; /* MD_SE05X */

class RNG_SE05X : public I_rng {
   protected:
    sss_se05x_rng_context_t ctx;

   public:
    void *getCtx();
    virtual sss_status_t context_init(I_session *session);

    virtual sss_status_t get_random(uint8_t *random_data, size_t dataLen);

    virtual sss_status_t context_free();

}; /* RNG_SE05X */

} // namespace sss

#endif /* SSS_HAVE_APPLET_SE05X_IOT */

#endif /* FSL_SSS_SE05X_APIS_HPP_H */
