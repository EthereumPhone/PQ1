/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include <fsl_sss_se05x_apis.h>
#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_hashcrypt.h>
#include <nxLog_App.h>
#include <nxEnsure.h>

#include "se05x_bind.h"
#include "memory.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define SCP03_MAX_AUTH_KEY_SIZE 52

/*******************************************************************************
 * Global variables
 ******************************************************************************/

/*******************************************************************************
 * Functions
 ******************************************************************************/

sss_status_t puf_insert_scp03_keys(
    uint8_t *enc_key, uint8_t *mac_key, uint8_t *dek_key, uint8_t *enc_kc, uint8_t *mac_kc, uint8_t *dek_kc)
{
    status_t result = kStatus_Fail;

    /* PUF SRAM Configuration*/
    puf_config_t conf;
    PUF_GetDefaultConfig(&conf);

    /* Insert the SCP03 keys into Index 0 and store the returned KC to the right arrays */
    result = PUF_SetUserKey(PUF,
        kPUF_KeyIndex_00,
        enc_key,
        PUF_INTRINSIC_KEY_SIZE,
        enc_kc,
        PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);
    result = PUF_SetUserKey(PUF,
        kPUF_KeyIndex_00,
        mac_key,
        PUF_INTRINSIC_KEY_SIZE,
        mac_kc,
        PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);
    result = PUF_SetUserKey(PUF,
        kPUF_KeyIndex_00,
        dek_key,
        PUF_INTRINSIC_KEY_SIZE,
        dek_kc,
        PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);

    // LOG_MAU8_I("KeyCode_ENC", keyCodeENC_01, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    // LOG_MAU8_I("KeyCode_MAC", keyCodeMAC_01, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    // LOG_MAU8_I("KeyCode_DEK", keyCodeDEK_01, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));

    return kStatus_SSS_Success;

cleanup:
    return kStatus_SSS_Fail;
}

sss_status_t rotate_platformscp_keys(uint8_t *enc, uint8_t *mac, uint8_t *dek, ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    uint8_t keyVersion  = pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->keyVerNo;
    tlvHeader_t hdr     = {{GP_CLA_BYTE, GP_INS_PUTKEY, keyVersion, GP_P2_MULTIPLEKEYS}};
    smStatus_t st       = SM_NOT_OK;
    uint8_t response[64];
    size_t responseLen = sizeof(response);
    uint8_t cmdBuf[128];
    uint8_t len = 0;
    uint8_t keyChkValues[16];
    uint8_t keyChkValLen = 0;

    /* Prepare the packet for SCP03 keys Provision */
    cmdBuf[len] = keyVersion; //keyVersion to replace
    len += 1;
    keyChkValues[keyChkValLen] = keyVersion;
    keyChkValLen += 1;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;

    /* Prepare the packet for ENC Key */
    status = createKeyData(enc, &cmdBuf[len], pCtx, MAKE_TEST_ID(__LINE__));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    memcpy(&keyChkValues[keyChkValLen], &cmdBuf[len + 3 + AES_KEY_LEN_nBYTE + 1], CRYPTO_KEY_CHECK_LEN);
    len += (3 + AES_KEY_LEN_nBYTE + 1 + CRYPTO_KEY_CHECK_LEN);
    keyChkValLen += CRYPTO_KEY_CHECK_LEN;

    /* Prepare the packet for MAC Key */
    status = createKeyData(mac, &cmdBuf[len], pCtx, MAKE_TEST_ID(__LINE__));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    memcpy(&keyChkValues[keyChkValLen], &cmdBuf[len + 3 + AES_KEY_LEN_nBYTE + 1], CRYPTO_KEY_CHECK_LEN);
    len += (3 + AES_KEY_LEN_nBYTE + 1 + CRYPTO_KEY_CHECK_LEN);
    keyChkValLen += CRYPTO_KEY_CHECK_LEN;

    /* Prepare the packet for DEK Key */
    status = createKeyData(dek, &cmdBuf[len], pCtx, MAKE_TEST_ID(__LINE__));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    memcpy(&keyChkValues[keyChkValLen], &cmdBuf[len + 3 + AES_KEY_LEN_nBYTE + 1], CRYPTO_KEY_CHECK_LEN);
    len += (3 + AES_KEY_LEN_nBYTE + 1 + CRYPTO_KEY_CHECK_LEN);
    keyChkValLen += CRYPTO_KEY_CHECK_LEN;

    /* Reset status to fail */
    status = kStatus_SSS_Fail;
    st     = DoAPDUTxRx_s_Case4(&pSession->s_ctx, &hdr, cmdBuf, len, response, &responseLen);
    ENSURE_OR_GO_CLEANUP(st == SM_OK);

    // reconstruct Return Value
    st = (response[responseLen - 2] << 8) + response[responseLen - 1];
    ENSURE_OR_GO_CLEANUP(st == SM_OK);
    if ((memcmp(response, keyChkValues, keyChkValLen) == 0)) {
        LOG_I("Key Rotation was successful!");
    }
    else {
        LOG_E("!!! Key Rotation Failed!!!!");
        goto cleanup;
    }
    status = kStatus_SSS_Success;

cleanup:
    return status;
}

sss_status_t createKeyData(uint8_t *key, uint8_t *targetStore, ex_sss_boot_ctx_t *pCtx, uint32_t Id)
{
    uint8_t keyCheckValues[AES_KEY_LEN_nBYTE] = {0};
    sss_status_t status                       = kStatus_SSS_Fail;

    /* For Each Key add Key Type Length of Key data and key length*/

    targetStore[0]                     = PUT_KEYS_KEY_TYPE_CODING_AES; //Key Type
    targetStore[1]                     = AES_KEY_LEN_nBYTE + 1;        // Length of the 'AES key data'
    targetStore[2]                     = AES_KEY_LEN_nBYTE;            // Length of 'AES key'
    targetStore[3 + AES_KEY_LEN_nBYTE] = CRYPTO_KEY_CHECK_LEN;         //Lenth of KCV

    /* Encrypt Key and generate key check values */
    status = genKCVandEncryptKey(&targetStore[3], keyCheckValues, key, pCtx, Id);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Copy the Key Check values */
    memcpy(&targetStore[3 + AES_KEY_LEN_nBYTE + 1], &keyCheckValues[0], CRYPTO_KEY_CHECK_LEN);

cleanup:
    return status;
}

sss_status_t genKCVandEncryptKey(
    uint8_t *encryptedkey, uint8_t *keyCheckVal, uint8_t *plainKey, ex_sss_boot_ctx_t *pCtx, uint32_t keyId)
{
    sss_algorithm_t algorithm              = kAlgorithm_SSS_AES_ECB;
    sss_mode_t mode                        = kMode_SSS_Encrypt;
    sss_status_t status                    = kStatus_SSS_Fail;
    uint8_t keyCheckValLen                 = 0;
    uint8_t refOneArray[AES_KEY_LEN_nBYTE] = {0};
    sss_symmetric_t symm;
    sss_object_t keyObj;
    uint8_t DekEnckey[256];
    size_t DekEnckeyLen    = sizeof(DekEnckey);
    size_t DekEnckeyBitLen = 1024;

    /* Initialize the key Object */
    status = sss_key_object_init(&keyObj, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Allocate the key Object handle */
    status = sss_key_object_allocate_handle(
        &keyObj, keyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, 16, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Set the key */
    status =
        sss_key_store_set_key(&pCtx->host_ks, &keyObj, plainKey, AES_KEY_LEN_nBYTE, (AES_KEY_LEN_nBYTE)*8, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Init EBC Encrypt Symmetric Algorithm */
    status = sss_symmetric_context_init(&symm, &pCtx->host_session, &keyObj, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    memset(refOneArray, 1, sizeof(refOneArray));

    /* Generate key check values*/
    status = sss_cipher_one_go(&symm, NULL, 0, refOneArray, keyCheckVal, keyCheckValLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Encyrpt the sensitive data */
    status = sss_key_store_get_key(&pCtx->host_ks,
        &pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->Dek,
        DekEnckey,
        &DekEnckeyLen,
        &DekEnckeyBitLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /** Encrypt using DEK key present in PUF */
    status = kStatus_SSS_Fail;
    hashcrypt_handle_t m_handle;
    const uint8_t *kc = &DekEnckey[0];

    /* Note - kc MUST be a correct keyCode */
    status_t result =
        PUF_GetHwKey(PUF, kc, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE), kPUF_KeySlot0, rand());
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);

    m_handle.keyType = kHASHCRYPT_SecretKey;
    result           = HASHCRYPT_AES_SetKey(HASHCRYPT, &m_handle, NULL, PUF_INTRINSIC_KEY_SIZE);
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);
    result = HASHCRYPT_AES_EncryptEcb(HASHCRYPT, &m_handle, plainKey, encryptedkey, PUF_INTRINSIC_KEY_SIZE);
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);

    status = kStatus_SSS_Success;

cleanup:
    return status;
}

sss_status_t s_platform_prepare_host(sss_session_t *pHostSession,
    sss_key_store_t *pHostKs,
    SE_Connect_Ctx_t *se05x_open_ctx,
    uint8_t *ENC_KEY,
    uint8_t *MAC_KEY,
    uint8_t *DEK_KEY,
    size_t key_length)
{
    sss_status_t status = kStatus_SSS_Fail;

    NXSCP03_StaticCtx_t *pStatic_ctx = se05x_open_ctx->auth.ctx.scp03.pStatic_ctx;
    NXSCP03_DynCtx_t *pDyn_ctx       = se05x_open_ctx->auth.ctx.scp03.pDyn_ctx;

    pStatic_ctx->keyVerNo = PF_KEY_VERSION_NO;

    /* Init Allocate ENC Static Key */
    status = s_alloc_Scp03key_Host(&pStatic_ctx->Enc, pHostKs, __LINE__);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Set ENC Static Key */
    status = sss_key_store_set_key(pHostKs, &pStatic_ctx->Enc, ENC_KEY, key_length, key_length * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate MAC Static Key */
    status = s_alloc_Scp03key_Host(&pStatic_ctx->Mac, pHostKs, __LINE__);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Set MAC Static Key */
    status = sss_key_store_set_key(pHostKs, &pStatic_ctx->Mac, MAC_KEY, key_length, key_length * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate DEK Static Key */
    status = s_alloc_Scp03key_Host(&pStatic_ctx->Dek, pHostKs, __LINE__);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Set DEK Static Key */
    status = sss_key_store_set_key(pHostKs, &pStatic_ctx->Dek, DEK_KEY, key_length, key_length * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate ENC Session Key */
    status = s_alloc_Scp03key_Host(&pDyn_ctx->Enc, pHostKs, __LINE__);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate MAC Session Key */
    status = s_alloc_Scp03key_Host(&pDyn_ctx->Mac, pHostKs, __LINE__);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Init Allocate DEK Session Key */
    status = s_alloc_Scp03key_Host(&pDyn_ctx->Rmac, pHostKs, __LINE__);

    return status;
}

sss_status_t s_alloc_Scp03key_Host(sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId)
{
    sss_status_t status = kStatus_SSS_Fail;
    status              = sss_key_object_init(keyObject, pKs);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    status = sss_key_object_allocate_handle(keyObject,
        keyId,
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        SCP03_MAX_AUTH_KEY_SIZE,
        kKeyObject_Mode_Transient);
    return status;
}

sss_status_t sbl_nvm_init()
{
    int status = memory_init();
    return status == 0 ? kStatus_SSS_Success : kStatus_SSS_Fail;
}

sss_status_t sbl_nvm_write(sbl_nvm_t *ctx)
{
    memory_erase(BL_DATA_START, BL_DATA_SIZE);
    return memory_write(BL_DATA_START, (void *)ctx, sizeof(sbl_nvm_t));
    return kStatus_SSS_Success;
}

sss_status_t sbl_nvm_read(sbl_nvm_t *ctx)
{
    memory_read(BL_DATA_START, (void *)ctx, sizeof(sbl_nvm_t));
    if (ctx->marker != BL_DATA_MARKER) {
        return kStatus_SSS_Fail;
    }
    return kStatus_SSS_Success;
}