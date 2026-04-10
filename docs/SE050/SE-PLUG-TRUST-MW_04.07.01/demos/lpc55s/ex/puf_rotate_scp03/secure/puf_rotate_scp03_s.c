/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <ex_sss_scp03_keys.h>
#include <ex_scp03_puf.h>
#include <fsl_hashcrypt.h>
#include <fsl_puf.h>
#include <fsl_sss_se05x_apis.h>
#include <nxLog_App.h>
#include <puf_rotate_scp03_s.h>
#include <string.h>
#include <nxEnsure.h>

#include "ex_sss_auth.h"
#include "smCom.h"

/*******************************************************************************
 * Defines
 ******************************************************************************/
#define NON_SECURE_START 0x00070000
#define SCP03_MAX_AUTH_KEY_SIZE 52

/* typedef for non-secure callback functions */
typedef void (*funcptr_ns)(void) __attribute__((cmse_nonsecure_call));

static ex_sss_boot_ctx_t gex_sss_tp_keys_boot_ctx;
#define EX_SSS_BOOT_PCONTEXT (&gex_sss_tp_keys_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0
#ifdef EX_SSS_BOOT_PCONTEXT
#define PCONTEXT EX_SSS_BOOT_PCONTEXT
#endif

/* This application wants only ISD selection as the keys are for ISD */
/* So applet selection has been skipped */
#define EX_SSS_BOOT_SKIP_SELECT_APPLET 1

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/* Insert PUF keys into Index 0 */
static sss_status_t puf_insert_scp03_keys();

/* Open session with applet selected */
static sss_status_t select_applet(ex_sss_boot_ctx_t *pCtx);

/* Open session with applet deselected to change SCP03 keys */
static sss_status_t deselect_applet(ex_sss_boot_ctx_t *pCtx);

/* Test applet by optaining some random data */
static sss_status_t test_random(ex_sss_boot_ctx_t *pCtx);

/* Functions to rotate PlatfSCP03 keys */
static sss_status_t rotate_platformscp_keys(uint8_t *enc, uint8_t *mac, uint8_t *dek, ex_sss_boot_ctx_t *pCtx);
static sss_status_t createKeyData(uint8_t *key, uint8_t *targetStore, ex_sss_boot_ctx_t *pCtx, uint32_t Id);
static sss_status_t genKCVandEncryptKey(
    uint8_t *encryptedkey, uint8_t *keyCheckVal, uint8_t *plainKey, ex_sss_boot_ctx_t *pCtx, uint32_t keyId);

/* Platform SCP03 prepare host */
static sss_status_t s_platform_prepare_host(sss_session_t *pHostSession,
    sss_key_store_t *pHostKs,
    SE_Connect_Ctx_t *se05x_open_ctx,
    uint8_t *ENC_KEY,
    uint8_t *MAC_KEY,
    uint8_t *DEK_KEY,
    size_t key_length);

/* Platform SCP03 Allocate key object */
static sss_status_t s_alloc_Scp03key_Host(sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId);
static sss_status_t getHostAesKeys(ex_sss_boot_ctx_t *pCtx, uint8_t *key, size_t keyLen);

/*******************************************************************************
 * Global variables
 ******************************************************************************/

/*******************************************************************************
 * Functions
 ******************************************************************************/
sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;

    /* Store DEK KeyCode first */
    uint8_t dek_kc[] = EX_SSS_AUTH_SE05X_KEY_DEK;
    status           = sss_key_store_set_key(&pCtx->host_ks,
        &pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->Dek,
        dek_kc,
        sizeof(dek_kc),
        sizeof(dek_kc) * 8,
        NULL,
        0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    puf_config_t conf;
    PUF_GetDefaultConfig(&conf);

    /** New key material
      * These will be the static platform SCP03 keys
      * which will be provisioned on the SE and in PUF
      */
    uint8_t PROV_KEY_ENC[PUF_INTRINSIC_KEY_SIZE] = {0};
    uint8_t PROV_KEY_MAC[PUF_INTRINSIC_KEY_SIZE] = {0};
    uint8_t PROV_KEY_DEK[PUF_INTRINSIC_KEY_SIZE] = {0};

    status = getHostAesKeys(pCtx, PROV_KEY_ENC, PUF_INTRINSIC_KEY_SIZE);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    // LOG_MAU8_W("Random ENC Key", PROV_KEY_ENC, PUF_INTRINSIC_KEY_SIZE);

    status = getHostAesKeys(pCtx, PROV_KEY_MAC, PUF_INTRINSIC_KEY_SIZE);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    // LOG_MAU8_W("Random MAC Key", PROV_KEY_MAC, PUF_INTRINSIC_KEY_SIZE);

    status = getHostAesKeys(pCtx, PROV_KEY_DEK, PUF_INTRINSIC_KEY_SIZE);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    // LOG_MAU8_W("Random DEK Key", PROV_KEY_DEK, PUF_INTRINSIC_KEY_SIZE);

    /** Select the applet and perform some operations.
      * This operation uses the PUF keyCodes provisioned in the 
      * boot context to open a platform SCP session.
      */
    status = select_applet(pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    /** Test RNG */
    status = test_random(pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Random test 1 was successful, with default SCP03 keys!");

    /** Deselect the applet to prepare for SCP03 Key rotation */
    status = deselect_applet(pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /** Rotate Platform SCP03 keys to new keys.
      * Same must be provisioned in PUF and respective
      * keyCodes must be updated in boot context so that 
      * next applet select can use these keyCodes to open 
      * platform SCP session
      */
    status = rotate_platformscp_keys(PROV_KEY_ENC, PROV_KEY_MAC, PROV_KEY_DEK, pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /** Insert the new keyCodes into PUF Index 0 (HW keys index) */
    status = puf_insert_scp03_keys(PROV_KEY_ENC, PROV_KEY_MAC, PROV_KEY_DEK);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /** Prepare the boot context with the new SCP03 keyCodes */
    status = s_platform_prepare_host(&pCtx->host_session,
        &pCtx->host_ks,
        &pCtx->se05x_open_ctx,
        keyCodeENC_01,
        keyCodeMAC_01,
        keyCodeDEK_01,
        PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /** Select the applet again (this time using new keyCodes) */
    status = select_applet(pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Applet is now using PUF keys!");
    /** Test RNG */
    status = test_random(pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Random test 2 was successful, with new PUF keys!");

    /** Switch back to the default SCP03 keys */
    status = deselect_applet(pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = rotate_platformscp_keys(_OLD_KEY_ENC, _OLD_KEY_MAC, _OLD_KEY_DEK, pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Rotation back to default keys was successful!");

    /* Example done, switch to NS side */
    /* Set non-secure main stack (MSP_NS) */
    __TZ_set_MSP_NS(*((uint32_t *)(NON_SECURE_START)));

    /* Set non-secure vector table */
    SCB_NS->VTOR = NON_SECURE_START;

    /* Get non-secure reset handler */
    funcptr_ns ResetHandler_ns = (funcptr_ns)(*((uint32_t *)((NON_SECURE_START) + 4U)));

    /* Call non-secure application */
    LOG_I("Entering normal world.\r\n");
    /* Jump to normal world */
    ResetHandler_ns();
    while (1) {
        /* This point should never be reached */
    }

cleanup:
    return status;
}

static sss_status_t getHostAesKeys(ex_sss_boot_ctx_t *pCtx, uint8_t *key, size_t keyLen)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    sss_rng_context_t sss_rng_ctx = {0};
    sss_status = sss_rng_context_init(&sss_rng_ctx, &pCtx->host_session);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    sss_status = sss_rng_get_random(&sss_rng_ctx, key, keyLen);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    sss_status = sss_rng_context_free(&sss_rng_ctx);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

exit:
    return sss_status;
}

static sss_status_t puf_insert_scp03_keys(uint8_t *enc_key, uint8_t *mac_key, uint8_t *dek_key)
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
        keyCodeENC_01,
        PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);
    result = PUF_SetUserKey(PUF,
        kPUF_KeyIndex_00,
        mac_key,
        PUF_INTRINSIC_KEY_SIZE,
        keyCodeMAC_01,
        PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);
    result = PUF_SetUserKey(PUF,
        kPUF_KeyIndex_00,
        dek_key,
        PUF_INTRINSIC_KEY_SIZE,
        keyCodeDEK_01,
        PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);

    // LOG_MAU8_I("KeyCode_ENC", keyCodeENC_01, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    // LOG_MAU8_I("KeyCode_MAC", keyCodeMAC_01, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    // LOG_MAU8_I("KeyCode_DEK", keyCodeDEK_01, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));

    return kStatus_SSS_Success;

cleanup:
    return kStatus_SSS_Fail;
}

static sss_status_t select_applet(ex_sss_boot_ctx_t *pCtx)
{
    sss_session_t *pSession                 = &pCtx->session;
    pCtx->se05x_open_ctx.skip_select_applet = 0;
    pCtx->se05x_open_ctx.connType           = kType_SE_Conn_Type_T1oI2C;
    sss_status_t status =
        sss_session_open(pSession, kType_SSS_SE_SE05x, 0, kSSS_ConnectionType_Encrypted, &pCtx->se05x_open_ctx);
    if (status == kStatus_SSS_Success) {
        LOG_I("Applet selection successful!");
    }
    else {
        LOG_E("Applet selection failed!");
    }
    return status;
}

static sss_status_t deselect_applet(ex_sss_boot_ctx_t *pCtx)
{
    sss_session_t *pSession                 = &pCtx->session;
    pCtx->se05x_open_ctx.skip_select_applet = 1;
    pCtx->se05x_open_ctx.connType           = kType_SE_Conn_Type_T1oI2C;
    sss_status_t status =
        sss_session_open(pSession, kType_SSS_SE_SE05x, 0, kSSS_ConnectionType_Encrypted, &pCtx->se05x_open_ctx);
    if (status == kStatus_SSS_Success) {
        LOG_I("Applet deselection successful!");
    }
    else {
        LOG_E("Applet deselection failed!");
    }
    return status;
}

static sss_status_t test_random(ex_sss_boot_ctx_t *pCtx)
{
    sss_rng_context_t rng;
    uint8_t rndData[256] = {0};

    sss_status_t status = sss_rng_context_init(&rng, &pCtx->session);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);
    status = sss_rng_get_random(&rng, rndData, 32);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_rng_context_free(&rng);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:
    return status;
}

static sss_status_t rotate_platformscp_keys(uint8_t *enc, uint8_t *mac, uint8_t *dek, ex_sss_boot_ctx_t *pCtx)
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

static sss_status_t createKeyData(uint8_t *key, uint8_t *targetStore, ex_sss_boot_ctx_t *pCtx, uint32_t Id)
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

static sss_status_t genKCVandEncryptKey(
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

static sss_status_t s_platform_prepare_host(sss_session_t *pHostSession,
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

static sss_status_t s_alloc_Scp03key_Host(sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId)
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