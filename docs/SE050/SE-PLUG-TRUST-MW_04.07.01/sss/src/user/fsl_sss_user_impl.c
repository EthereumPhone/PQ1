/*
 * Copyright 2018,2020,2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <nxEnsure.h>
#include <nxLog_sss.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if SSS_HAVE_HOSTCRYPTO_USER
#include <fsl_sss_types.h>

#include "fsl_sss_user_apis.h"

#include <time.h>
#include "crypto/aes_cmac.h"
#include "crypto/aes_cmac_multistep.h"

#define MAC_BLOCK_SIZE 16
#define AES_BLOCK_SIZE 16

sss_status_t sss_user_impl_session_open(sss_user_impl_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(session != NULL);
    ENSURE_OR_GO_CLEANUP(connection_type == kSSS_ConnectionType_Plain);
    memset(session, 0, sizeof(*session));
    session->subsystem = subsystem;
    retval             = kStatus_SSS_Success;
cleanup:
    return retval;
}

sss_status_t sss_user_impl_key_object_init(sss_user_impl_object_t *keyObject, sss_user_impl_key_store_t *keyStore)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyObject);
    ENSURE_OR_GO_CLEANUP(keyStore);
    SSS_ASSERT(sizeof(sss_user_impl_object_t) <= sizeof(sss_object_t));
    SSS_ASSERT(sizeof(sss_user_impl_key_store_t) <= sizeof(sss_key_store_t));
    memset(keyObject, 0, sizeof(*keyObject));
    keyObject->keyStore = keyStore;
    retval              = kStatus_SSS_Success;
cleanup:
    return retval;
}

sss_status_t sss_user_impl_key_object_allocate_handle(sss_user_impl_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyObject);
    ENSURE_OR_GO_CLEANUP(keyId != 0);
    ENSURE_OR_GO_CLEANUP(keyId != 0xFFFFFFFFu);

    keyObject->keyId      = keyId;
    keyObject->objectType = keyPart;
    keyObject->cipherType = cipherType;

    if (options != kKeyObject_Mode_Persistent && options != kKeyObject_Mode_Transient) {
        LOG_E("sss_user_impl_key_object_allocate_handle option invalid 0x%X", options);
        retval = kStatus_SSS_Fail;
        goto cleanup;
    }

    if (keyByteLenMax != 0) {
        // keyObject->contents = malloc(keyByteLenMax);
        keyObject->contents = SSS_MALLOC(keyByteLenMax);
        ENSURE_OR_GO_CLEANUP(keyObject->contents);
        memset(keyObject->contents, 0, keyByteLenMax);
        keyObject->contents_size = keyByteLenMax;
        retval                   = kStatus_SSS_Success;
    }

cleanup:
    return retval;
}

sss_status_t sss_user_impl_key_store_context_init(sss_user_impl_key_store_t *keyStore, sss_user_impl_session_t *session)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyStore);
    ENSURE_OR_GO_CLEANUP(session);

    memset(keyStore, 0, sizeof(*keyStore));
    keyStore->session = session;
    retval            = kStatus_SSS_Success;
cleanup:
    return retval;
}

sss_status_t sss_user_impl_key_store_allocate(sss_user_impl_key_store_t *keyStore, uint32_t keyStoreId)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_CLEANUP(keyStore);
    ENSURE_OR_GO_CLEANUP(keyStore->session);
    retval = kStatus_SSS_Success;
cleanup:
    return retval;
}

sss_status_t sss_user_impl_key_store_set_key(sss_user_impl_key_store_t *keyStore,
    sss_user_impl_object_t *keyObject,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(data != NULL)
    ENSURE_OR_GO_EXIT(keyObject != NULL)
    ENSURE_OR_GO_EXIT(keyObject->contents != NULL)
    ENSURE_OR_GO_EXIT(dataLen <= keyObject->contents_size);

    if (dataLen <= sizeof(keyObject->key)) {
        memcpy(keyObject->key, data, dataLen);
    }

    memcpy(keyObject->contents, data, dataLen);
    keyObject->contents_size = dataLen;

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_user_impl_key_store_get_key(sss_user_impl_key_store_t *keyStore,
    sss_user_impl_object_t *keyObject,
    uint8_t *data,
    size_t *dataLen,
    size_t *pKeyBitLen)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(*dataLen >= keyObject->contents_size);
    memcpy(data, keyObject->contents, keyObject->contents_size);
    *dataLen = keyObject->contents_size;
    if (pKeyBitLen != NULL) {
        *pKeyBitLen = keyObject->contents_size * 8;
    }
    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_user_impl_cipher_one_go(sss_user_impl_symmetric_t *context,
    uint8_t *iv,
    size_t ivLen,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t dataLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    int i;
    uint8_t indata[AES_BLOCK_SIZE] = {0};
    ENSURE_OR_GO_EXIT(context);
    if (context->algorithm != kAlgorithm_SSS_AES_ECB)
        ENSURE_OR_GO_EXIT(iv);
    if (context->algorithm == kAlgorithm_SSS_AES_ECB)
        dataLen = 16;
    ENSURE_OR_GO_EXIT(srcData);
    ENSURE_OR_GO_EXIT(destData);
    ENSURE_OR_GO_EXIT(dataLen % AES_BLOCK_SIZE == 0);

    if (context->mode == kMode_SSS_Encrypt) {
        while (dataLen > 0) {
            memcpy(indata, srcData, AES_BLOCK_SIZE);
            if (context->algorithm != kAlgorithm_SSS_AES_ECB) {
                // XOR the current vector with the block before encrypting
                for (i = 0; i < AES_BLOCK_SIZE; i++) {
                    indata[i] ^= iv[i];
                }
            }

            // Encrypt the block
            AES_user_encrypt(context->pAesctx, indata, destData);
            if (context->algorithm != kAlgorithm_SSS_AES_ECB)
                memcpy(iv, destData, AES_BLOCK_SIZE);

            srcData += AES_BLOCK_SIZE;
            destData += AES_BLOCK_SIZE;
            dataLen -= AES_BLOCK_SIZE;
        }
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        while (dataLen > 0) {
            memcpy(indata, srcData, AES_BLOCK_SIZE);
            // Decrypt the block
            AES_user_decrypt(context->pAesctx, indata, destData);

            // XOR the output with the current vector to fully decrypt
            for (i = 0; i < AES_BLOCK_SIZE; i++) {
                destData[i] ^= iv[i];
            }
            memcpy(iv, indata, AES_BLOCK_SIZE);

            srcData += AES_BLOCK_SIZE;
            destData += AES_BLOCK_SIZE;
            dataLen -= AES_BLOCK_SIZE;
        }
    }
    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_user_impl_mac_context_init(sss_user_impl_mac_t *context,
    sss_user_impl_session_t *session,
    sss_user_impl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;
    SSS_ASSERT(sizeof(sss_user_impl_mac_t) < sizeof(sss_mac_t));
    ENSURE_OR_GO_EXIT(context);
    ENSURE_OR_GO_EXIT(keyObject);
    memset(context, 0, sizeof(*context));
    context->keyObject  = keyObject;
    context->pAesmacctx = AES_ctx_alloc(keyObject->key, sizeof(keyObject->key));
    ENSURE_OR_GO_EXIT(context->pAesmacctx);
    retval = kStatus_SSS_Success;

exit:
    return retval;
}
sss_status_t sss_user_impl_mac_init(sss_user_impl_mac_t *context)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(context);
    memset(context->calc_mac, 0, sizeof(*context->calc_mac));
    memset(context->cache_data, 0, sizeof(*context->cache_data));
    context->cache_dataLen = 0;
    retval                 = kStatus_SSS_Success;

exit:
    return retval;
}

sss_status_t sss_user_impl_mac_update(sss_user_impl_mac_t *context, const uint8_t *message, size_t messageLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(context);
    SSS_ASSERT(sizeof(sss_user_impl_mac_t) < sizeof(sss_mac_t));
    //ENSURE_OR_GO_EXIT(messageLen < sizeof(input));
    size_t n, i;
    uint8_t mac[MAC_BLOCK_SIZE] = {0};
    /*Use this input buffer as message is const*/
    /*Below algo changes buffer for padding*/
    uint8_t input[MAC_BLOCK_SIZE] = {0};

    LOG_AU8_D(message, messageLen);
    /* check if any data in cache, that's greater than a block */
    if ((context->cache_dataLen > 0) && (messageLen > (MAC_BLOCK_SIZE - context->cache_dataLen))) {
        memcpy(&context->cache_data[context->cache_dataLen], message, MAC_BLOCK_SIZE - context->cache_dataLen);
        //memcpy(input, message, MAC_BLOCK_SIZE);
        aes_cmac_update(
            context->pAesmacctx, context->cache_data, context->calc_mac, MAC_BLOCK_SIZE, context->keyObject->key, mac);
        memcpy(context->calc_mac, mac, MAC_BLOCK_SIZE);

        message += MAC_BLOCK_SIZE - context->cache_dataLen;
        messageLen -= MAC_BLOCK_SIZE - context->cache_dataLen;
        context->cache_dataLen = 0;
    }
    LOG_AU8_D(context->calc_mac, MAC_BLOCK_SIZE);

    n = (messageLen + MAC_BLOCK_SIZE - 1) / MAC_BLOCK_SIZE;
    for (i = 1; i < n; i++) {
        memcpy(input, message, MAC_BLOCK_SIZE);
        LOG_AU8_D(context->calc_mac, MAC_BLOCK_SIZE);
        aes_cmac_update(context->pAesmacctx, input, context->calc_mac, MAC_BLOCK_SIZE, context->keyObject->key, mac);
        memcpy(context->calc_mac, mac, MAC_BLOCK_SIZE);
        messageLen -= MAC_BLOCK_SIZE;
        message += MAC_BLOCK_SIZE;
    }

    /* Copy left over data that wasn't aligned to a block */
    if (messageLen > 0) {
        LOG_D("messageLen=%d MAC_BLOCK_SIZE=%d", messageLen, MAC_BLOCK_SIZE);
        //ENSURE_OR_GO_EXIT(messageLen < MAC_BLOCK_SIZE);
        memcpy(context->cache_data, message, messageLen);
        context->cache_dataLen += messageLen;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}
sss_status_t sss_user_impl_mac_finish(sss_user_impl_mac_t *context, uint8_t *mac, size_t *macLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(context);
    ENSURE_OR_GO_EXIT(mac);
    ENSURE_OR_GO_EXIT(macLen);
    uint8_t input[MAC_BLOCK_SIZE] = {0};
    size_t inputLen               = 0;

    memcpy(input, context->cache_data, context->cache_dataLen);
    inputLen = context->cache_dataLen;

    aes_cmac_finish(context->pAesmacctx, input, context->calc_mac, inputLen, context->keyObject->key, mac);
    *macLen = MAC_BLOCK_SIZE;
    status  = kStatus_SSS_Success;
exit:
    return status;
}
sss_status_t sss_user_impl_mac_one_go(
    sss_user_impl_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(context);
    uint8_t input[1024] = {0};
    //ENSURE_OR_GO_CLEANUP(messageLen == AES_BLOCKSIZE);
    memcpy(input, message, messageLen);
    aes_cmac(/*context->pAesmacctx,*/ input, messageLen, context->keyObject->key, mac);
    *macLen = AES_BLOCKSIZE;
    status  = kStatus_SSS_Success;

exit:
    return status;
}
void sss_user_impl_mac_context_free(sss_user_impl_mac_t *context)
{
    if (context != NULL) {
        if (context->pAesmacctx != NULL) {
            memset(context->pAesmacctx, 3, sizeof(*context->pAesmacctx));
            // free(context->pAesmacctx);
            SSS_FREE(context->pAesmacctx);
        }
        memset(context->calc_mac, 0, MAC_BLOCK_SIZE);
        memset(context->cache_data, 0, MAC_BLOCK_SIZE);
    }
    return;
}

sss_status_t sss_user_impl_rng_context_free(sss_user_impl_rng_context_t *context)
{
    return kStatus_SSS_Success;
}
sss_status_t sss_user_impl_rng_context_init(sss_user_impl_rng_context_t *context, sss_user_impl_session_t *session)
{
    sss_status_t status = kStatus_SSS_Fail;
    SSS_ASSERT(sizeof(sss_user_impl_rng_context_t) <= sizeof(sss_rng_context_t));
    srand((unsigned int)time(NULL));
    status = kStatus_SSS_Success;
    return status;
}

sss_status_t sss_user_impl_rng_get_random(sss_user_impl_rng_context_t *context, uint8_t *random_data, size_t dataLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(context);
    for (size_t i = 0; i < dataLen; i++) {
        random_data[i] = (uint8_t)rand();
    }
    status = kStatus_SSS_Success;
exit:
    return status;
}

void sss_user_impl_symmetric_context_free(sss_user_impl_symmetric_t *context)
{
    LOG_D("SYM_FREE");
    if (NULL != context->pAesctx) {
        // free(context->pAesctx);
        SSS_FREE(context->pAesctx);
        context->pAesctx = NULL;
    }
}

sss_status_t sss_user_impl_symmetric_context_init(sss_user_impl_symmetric_t *context,
    sss_user_impl_session_t *session,
    sss_user_impl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t status = kStatus_SSS_Fail;
    LOG_D("SYM_NEW");
    ENSURE_OR_GO_EXIT(context);
    ENSURE_OR_GO_EXIT(session);
    ENSURE_OR_GO_EXIT(keyObject);
    SSS_ASSERT(sizeof(sss_user_impl_symmetric_t) <= sizeof(sss_symmetric_t));
    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;
    context->pAesctx   = AES_ctx_alloc(keyObject->key, sizeof(keyObject->key));
    ENSURE_OR_GO_EXIT(context->pAesctx);
    status = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t sss_user_impl_key_store_generate_key(
    sss_user_impl_key_store_t *keyStore, sss_user_impl_object_t *keyObject, size_t keyBitLen, void *options)
{
    LOG_W("sss_user_impl_key_store_generate_key not implemented!!!");
    return kStatus_SSS_Fail;
}

void sss_user_impl_key_object_free(sss_user_impl_object_t *keyObject)
{
    if (keyObject != NULL) {
        if (keyObject->contents != NULL) {
            // free(keyObject->contents);
            SSS_FREE(keyObject->contents);
            keyObject->contents      = NULL;
            keyObject->contents_size = 0;
            memset(keyObject, 0, sizeof(*keyObject));
        }
    }
    return;
}

sss_status_t sss_user_impl_derive_key_context_init(sss_user_impl_derive_key_t *context,
    sss_user_impl_session_t *session,
    sss_user_impl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    LOG_W("sss_user_impl_derive_key_context_init not implemented!!!");
    return kStatus_SSS_Fail;
}

sss_status_t sss_user_impl_derive_key_go(sss_user_impl_derive_key_t *context,
    const uint8_t *saltData,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    sss_user_impl_object_t *derivedKeyObject,
    uint16_t deriveDataLen,
    uint8_t *hkdfOutput,
    size_t *hkdfOutputLen)
{
    LOG_W("sss_user_impl_derive_key_go not implemented!!!");
    return kStatus_SSS_Fail;
}

sss_status_t sss_user_impl_derive_key_dh(sss_user_impl_derive_key_t *context,
    sss_user_impl_object_t *otherPartyKeyObject,
    sss_user_impl_object_t *derivedKeyObject)
{
    LOG_W("sss_user_impl_derive_key_dh not implemented!!!");
    return kStatus_SSS_Fail;
}

void sss_user_impl_derive_key_context_free(sss_user_impl_derive_key_t *context)
{
    LOG_W("sss_user_impl_derive_key_context_free not implemented!!!");
    return;
}

sss_status_t sss_user_impl_asymmetric_context_init(sss_user_impl_asymmetric_t *context,
    sss_user_impl_session_t *session,
    sss_user_impl_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    LOG_W("sss_user_impl_asymmetric_context_init not implemented!!!");
    return kStatus_SSS_Fail;
}

sss_status_t sss_user_impl_asymmetric_sign_digest(
    sss_user_impl_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
    LOG_W("sss_user_impl_asymmetric_sign_digest not implemented!!!");
    return kStatus_SSS_Fail;
}

void sss_user_impl_asymmetric_context_free(sss_user_impl_asymmetric_t *context)
{
    LOG_W("sss_user_impl_asymmetric_context_free not implemented!!!");
}

sss_status_t sss_user_impl_digest_context_init(
    sss_user_impl_digest_t *context, sss_user_impl_session_t *session, sss_algorithm_t algorithm, sss_mode_t mode)
{
    LOG_W("sss_user_impl_digest_context_init not implemented!!!");
    return kStatus_SSS_Fail;
}
sss_status_t sss_user_impl_digest_one_go(
    sss_user_impl_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen)
{
    LOG_W("sss_user_impl_digest_one_go not implemented!!!");
    return kStatus_SSS_Fail;
}

void sss_user_impl_digest_context_free(sss_user_impl_digest_t *context)
{
    LOG_W("sss_user_impl_digest_context_free not implemented!!!");
    return;
}

void sss_user_impl_key_store_context_free(sss_user_impl_key_store_t *keyStore)
{
    if (keyStore != NULL) {
        memset(keyStore, 0, sizeof(*keyStore));
    }
}

void sss_user_impl_session_close(sss_user_impl_session_t *session)
{
    if (session != NULL) {
        memset(session, 0, sizeof(*session));
    }
}
#endif /* SSS_HAVE_HOSTCRYPTO_USER */
