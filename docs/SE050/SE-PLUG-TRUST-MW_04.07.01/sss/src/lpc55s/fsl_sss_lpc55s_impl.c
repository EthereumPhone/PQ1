/*
 *
 * Copyright 2018,2020 NXP
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

#if defined(SECURE_WORLD)
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include <board.h>
#include <fsl_puf.h>
#include <fsl_hashcrypt.h>
#include "ex_scp03_puf.h"
#include "fsl_sss_lpc55s_apis.h"
#include "fsl_sss_mbedtls_apis.h"

#define CIPHER_BLOCK_SIZE 16
#define PUF_INTRINSIC_KEY_SIZE 16
#define PUF_KEY_CODE_SIZE PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)

static status_t puf_generate_last_block(hashcrypt_handle_t *p_m_handle,
    uint8_t *subkey_k1,
    uint8_t *subkey_k2,
    const uint8_t *srcData,
    uint32_t srcDataLen,
    uint8_t *lastBlock);
static status_t puf_generate_subkeys(
    const uint8_t kc[PUF_KEY_CODE_SIZE], hashcrypt_handle_t *p_m_handle, uint8_t *subkey_k1, uint8_t *subkey_k2);

static bool is_lpc_context = false;

sss_status_t sss_lpc55s_impl_session_open(sss_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData)
{
    uint8_t ac[PUF_ACTIVATION_CODE_SIZE] = ACTIVATION_CODE_TESTING_LOCAL;
    /* Start PUF by loading generated activation code */

    if (kStatus_Success != PUF_Start(PUF, ac, PUF_ACTIVATION_CODE_SIZE)) {
        LOG_E("PUF_Start failed");
        goto init_mbedtls;
    }

init_mbedtls:
    return sss_mbedtls_session_open(
        (sss_mbedtls_session_t *)session, subsystem, application_id, connection_type, connectionData);
}

void sss_lpc55s_impl_session_close(sss_session_t *session)
{
    return sss_mbedtls_session_close((sss_mbedtls_session_t *)session);
}

sss_status_t sss_lpc55s_impl_mac_context_init(
    sss_mac_t *context, sss_session_t *session, sss_object_t *keyObject, sss_algorithm_t algorithm, sss_mode_t mode)
{
    sss_status_t status = kStatus_SSS_Fail;
    SSS_ASSERT(sizeof(sss_lpc55s_impl_mac_t) < sizeof(sss_mac_t));
    uint8_t key_data[PUF_KEY_CODE_SIZE] = {0};
    uint8_t *kc;
    size_t kc_size                     = PUF_KEY_CODE_SIZE;
    size_t kc_size_bits                = kc_size * 8;
    sss_lpc55s_impl_mac_t *lpc_context = (sss_lpc55s_impl_mac_t *)context;
    hashcrypt_handle_t *p_hashcrypt_handle;

    status = sss_key_store_get_key(keyObject->keyStore, keyObject, key_data, &kc_size, &kc_size_bits);
    if ((status != kStatus_SSS_Success) || (kc_size != PUF_KEY_CODE_SIZE)) {
        return sss_mbedtls_mac_context_init((sss_mbedtls_mac_t *)context,
            (sss_mbedtls_session_t *)session,
            (sss_mbedtls_object_t *)keyObject,
            algorithm,
            mode);
    }

    /* If code reaches here, key_data MUST contain a key code (kc_size = PUF_KEY_CODE_SIZE) */
    status_t result = PUF_GetHwKey(PUF, key_data, PUF_KEY_CODE_SIZE, kPUF_KeySlot0, rand());
    if (result != kStatus_Success) {
        return kStatus_SSS_Fail;
    }

    kc = (uint8_t *)SSS_MALLOC(PUF_KEY_CODE_SIZE);
    memset(kc, 0, PUF_KEY_CODE_SIZE);

    p_hashcrypt_handle = (hashcrypt_handle_t *)SSS_MALLOC(sizeof(hashcrypt_handle_t));
    memset(p_hashcrypt_handle, 0, sizeof(hashcrypt_handle_t));

    ENSURE_OR_GO_CLEANUP(context);
    ENSURE_OR_GO_CLEANUP(keyObject);
    memset(lpc_context, 0, sizeof(*lpc_context));

    memcpy(kc, key_data, PUF_KEY_CODE_SIZE);

    p_hashcrypt_handle->keyType = kHASHCRYPT_SecretKey;

    lpc_context->p_hashcrypt_handle = p_hashcrypt_handle;
    lpc_context->keyCode            = kc;

    // LOG_MAU8_W("KeyCode", kc, PUF_KEY_CODE_SIZE);
    lpc_context->keyObject       = keyObject;
    lpc_context->algorithm       = algorithm;
    lpc_context->mode            = mode;
    lpc_context->hashCryptHandle = 1;
    status                       = kStatus_SSS_Success;
    is_lpc_context               = true;
    goto exit;

cleanup:
    memset(lpc_context, 0, sizeof(*lpc_context));
    if (kc) {
        SSS_FREE(kc);
    }
    if (p_hashcrypt_handle) {
        SSS_FREE(p_hashcrypt_handle);
    }
exit:
    return status;
}

sss_status_t sss_lpc55s_impl_mac_one_go(
    sss_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen)
{
    sss_lpc55s_impl_mac_t *lpc_context = (sss_lpc55s_impl_mac_t *)context;
    if (!is_lpc_context) {
        return sss_mbedtls_mac_one_go((sss_mbedtls_mac_t *)context, message, messageLen, mac, macLen);
    }

    sss_status_t status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(lpc_context);

    status_t result                        = kStatus_Fail;
    uint8_t subkey_k1[16]                  = {0};
    uint8_t subkey_k2[16]                  = {0};
    uint8_t lastBlock[CIPHER_BLOCK_SIZE]   = {0};
    hashcrypt_handle_t *p_hashcrypt_handle = lpc_context->p_hashcrypt_handle;
    p_hashcrypt_handle->keyType            = kHASHCRYPT_SecretKey;

    result = puf_generate_subkeys(lpc_context->keyCode, p_hashcrypt_handle, subkey_k1, subkey_k2);
    ENSURE_OR_GO_EXIT(result == kStatus_Success);

    result = puf_generate_last_block(p_hashcrypt_handle, subkey_k1, subkey_k2, message, messageLen, lastBlock);
    ENSURE_OR_GO_EXIT(result == kStatus_Success);

    result = HASHCRYPT_AES_EncryptEcb(HASHCRYPT, p_hashcrypt_handle, lastBlock, mac, CIPHER_BLOCK_SIZE);
    ENSURE_OR_GO_EXIT(result == kStatus_Success);

    *macLen = CIPHER_BLOCK_SIZE;
    status  = kStatus_SSS_Success;

exit:
    sss_lpc55s_impl_mac_context_free(context);
    return status;
}

void sss_lpc55s_impl_mac_context_free(sss_mac_t *context)
{
    sss_lpc55s_impl_mac_t *lpc_context = (sss_lpc55s_impl_mac_t *)context;
    if (!lpc_context) {
        return;
    }
    if (!is_lpc_context /*lpc_context->hashCryptHandle*/) {
        return sss_mbedtls_mac_context_free((sss_mbedtls_mac_t *)context);
    }

    if (lpc_context->keyCode) {
        SSS_FREE(lpc_context->keyCode);
    }
    if (lpc_context->p_hashcrypt_handle) {
        SSS_FREE(lpc_context->p_hashcrypt_handle);
    }
    memset(lpc_context, 0, sizeof(*lpc_context));
    lpc_context->hashCryptHandle = 0;

    is_lpc_context = false;

    return;
}

static status_t puf_generate_last_block(hashcrypt_handle_t *p_m_handle,
    uint8_t *subkey_k1,
    uint8_t *subkey_k2,
    const uint8_t *srcData,
    uint32_t srcDataLen,
    uint8_t *lastBlock)
{
    status_t result       = kStatus_Fail;
    uint8_t iv[16]        = {0};
    uint8_t destData[256] = {0};
    size_t destDataLen    = sizeof(destData);

    // uint8_t lastBlock[CIPHER_BLOCK_SIZE] = { 0 };
    if (srcDataLen < CIPHER_BLOCK_SIZE) {
        memcpy(lastBlock, srcData, srcDataLen);
        lastBlock[srcDataLen] = 0x80;
        for (int i = 0; i < CIPHER_BLOCK_SIZE; i++) {
            lastBlock[i] = lastBlock[i] ^ subkey_k1[i];
        }
        result = kStatus_Success;
    }
    else if (srcDataLen == CIPHER_BLOCK_SIZE) {
        // subkey to use = subkey k1
        memcpy(lastBlock, srcData, CIPHER_BLOCK_SIZE);
        for (int i = 0; i < CIPHER_BLOCK_SIZE; i++) {
            lastBlock[i] = lastBlock[i] ^ subkey_k1[i];
        }
        // cipher_one_go_ecb(lastBlock)
        result = kStatus_Success;
    }
    else if (srcDataLen % CIPHER_BLOCK_SIZE == 0) {
        // subkey to use = subkey k1
        uint8_t number_of_blocks = (srcDataLen / CIPHER_BLOCK_SIZE) - 1;
        destDataLen              = number_of_blocks * CIPHER_BLOCK_SIZE;
        memcpy(lastBlock, &srcData[destDataLen], CIPHER_BLOCK_SIZE);

        result = HASHCRYPT_AES_EncryptCbc(HASHCRYPT, p_m_handle, srcData, destData, destDataLen, iv);
        ENSURE_OR_GO_CLEANUP(result == kStatus_Success);
        for (int i = 0; i < CIPHER_BLOCK_SIZE; i++) {
            lastBlock[i] = lastBlock[i] ^ destData[destDataLen - CIPHER_BLOCK_SIZE + i] ^ subkey_k1[i];
        }
    }
    else {
        uint8_t number_of_blocks = (srcDataLen / CIPHER_BLOCK_SIZE);
        destDataLen              = number_of_blocks * CIPHER_BLOCK_SIZE;
        memcpy(lastBlock, &srcData[destDataLen], (srcDataLen % CIPHER_BLOCK_SIZE));
        lastBlock[srcDataLen % CIPHER_BLOCK_SIZE] = 0x80;
        result = HASHCRYPT_AES_EncryptCbc(HASHCRYPT, p_m_handle, srcData, destData, destDataLen, iv);
        ENSURE_OR_GO_CLEANUP(result == kStatus_Success);
        for (int i = 0; i < CIPHER_BLOCK_SIZE; i++) {
            lastBlock[i] = lastBlock[i] ^ destData[destDataLen - CIPHER_BLOCK_SIZE + i] ^ subkey_k2[i];
        }
    }

cleanup:
    return result;
}

static status_t puf_generate_subkeys(
    const uint8_t kc[PUF_KEY_CODE_SIZE], hashcrypt_handle_t *p_m_handle, uint8_t *subkey_k1, uint8_t *subkey_k2)
{
    uint8_t const_rb[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87};
    size_t const_rb_size = sizeof(const_rb);
    uint8_t srcData[16]  = {0};
    uint8_t L[16]        = {
        0,
    };
    size_t LLen      = sizeof(L);
    bool msb_is_zero = true;

    /* If this function is called kc must contain a keyCode */
    status_t result = PUF_GetHwKey(PUF, kc, PUF_KEY_CODE_SIZE, kPUF_KeySlot0, rand());
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);

    /* Decrypt ciphertext with key now inserted into PUF Index 0 */
    result = HASHCRYPT_AES_SetKey(HASHCRYPT, p_m_handle, NULL, PUF_INTRINSIC_KEY_SIZE);
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);

    result = HASHCRYPT_AES_EncryptEcb(HASHCRYPT, p_m_handle, srcData, L, LLen);
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);

    /**
     *  Constants: const_Zero is 0x00000000000000000000000000000000 
     *             const_Rb   is 0x00000000000000000000000000000087 
     *  Variables: L          for output of AES-128 applied to 0^128
     *                                                              
     *  Step 1.  L := AES-128(K, const_Zero);                       
     *  Step 2.  if MSB(L) is equal to 0                            
     *           then    K1 := L << 1;                              
     *           else    K1 := (L << 1) XOR const_Rb;               
     *  Step 3.  if MSB(K1) is equal to 0                           
     *           then    K2 := K1 << 1;                             
     *           else    K2 := (K1 << 1) XOR const_Rb;              
     *  Step 4.  return K1, K2;                                     
     */

    /* Create Subkey K1 from L */
    if ((L[0] & 0x80) == 0x80) {
        msb_is_zero = false;
    }

    for (size_t i = 0; i < LLen - 1; i++) {
        L[i] = L[i] << 1;
        if ((L[i + 1] & 0x80) == 0x80) {
            L[i] = L[i] | 0x01;
        }
    }
    L[LLen - 1] = L[LLen - 1] << 1;

    memcpy(subkey_k1, L, LLen);

    if (!msb_is_zero) {
        for (size_t i = 0; i < const_rb_size; i++) {
            subkey_k1[i] = subkey_k1[i] ^ const_rb[i];
        }
    }

    /* Create Subkey K2 from Subkey K1 */
    msb_is_zero = true;
    memcpy(subkey_k2, subkey_k1, CIPHER_BLOCK_SIZE);

    if ((subkey_k1[0] & 0x80) == 0x80) {
        msb_is_zero = false;
    }

    for (size_t i = 0; i < CIPHER_BLOCK_SIZE - 1; i++) {
        subkey_k2[i] = subkey_k2[i] << 1;
        if ((subkey_k2[i + 1] & 0x80) == 0x80) {
            subkey_k2[i] = subkey_k2[i] | 0x01;
        }
    }

    subkey_k2[CIPHER_BLOCK_SIZE - 1] = subkey_k2[CIPHER_BLOCK_SIZE - 1] << 1;

    if (!msb_is_zero) {
        for (size_t i = 0; i < const_rb_size; i++) {
            subkey_k2[i] = subkey_k2[i] ^ const_rb[i];
        }
    }

    // LOG_MAU8_W("Subkey K1", subkey_k1, CIPHER_BLOCK_SIZE);
    // LOG_MAU8_W("Subkey K2", subkey_k2, CIPHER_BLOCK_SIZE);

cleanup:
    return result;
}

#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */

#endif /* SECURE_WORLD */
