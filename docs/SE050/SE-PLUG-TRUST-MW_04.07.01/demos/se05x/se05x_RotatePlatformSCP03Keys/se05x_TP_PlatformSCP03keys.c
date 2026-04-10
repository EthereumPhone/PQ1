/* Copyright 2019,2024,2025 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "se05x_TP_PlatformSCP03keys.h"

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <ex_sss_scp03_keys.h>
#include <fsl_sss_se05x_apis.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>
#include <stdio.h>
#include <string.h>

#if !AX_EMBEDDED
#include <sys/stat.h>
#ifdef _MSC_VER
#include <direct.h>
#endif // _MSC_VER
#endif // !AX_EMBEDDED

#if defined(_MSC_VER)
#define DO_MKDIR(DIR_NAME) _mkdir((DIR_NAME));
#else //#if defined(__linux__) || defined(__CYGWIN__) || defined(__clang__)
#define DO_MKDIR(DIR_NAME) \
    mkdir((DIR_NAME), S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IXOTH);
#endif

#define FPRINTF(FP, TXT)         \
    if (fprintf(FP, TXT) < 0) {  \
        LOG_E("fprintf error");  \
        return kStatus_SSS_Fail; \
    }

#include "ex_sss_auth.h"
#include "smCom.h"

static ex_sss_boot_ctx_t gex_sss_tp_keys_boot_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_tp_keys_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* This application wants only ISD selection as the keys are for ISD */
/* So applet selection has been skipped */
#define EX_SSS_BOOT_SKIP_SELECT_APPLET 1

#define AES_MAX_KEY_LEN 32

/*
* 1 => Rotate example with 16 bytes SCP keys.
* 0 => Rotate example with 32 bytes SCP keys.
*/
#define ROTATE_PLATFORMSCP03_128BITLEN 1

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

static sss_status_t tp_PlatformKeys(uint8_t *enc, uint8_t *mac, uint8_t *dek, int key_len, ex_sss_boot_ctx_t *pCtx);
static sss_status_t createKeyData(
    uint8_t *key, int key_len, uint8_t *targetStore, ex_sss_boot_ctx_t *pCtx, uint32_t Id);
static sss_status_t genKCVandEncryptKey(uint8_t *encryptedkey,
    int key_len,
    uint8_t *keyCheckVal,
    uint8_t *plainKey,
    ex_sss_boot_ctx_t *pCtx,
    uint32_t keyId);

#ifdef EX_SSS_SCP03_FILE_PATH
static sss_status_t write_keys_toFile(uint8_t *enc, uint8_t *mac, uint8_t *dek, int key_len);
#endif //!AX_EMBEDDED

/* doc:start:new-scp03-keys */
#if ROTATE_PLATFORMSCP03_128BITLEN
#define EX_SSS_AUTH_NEW_ENC_KEY                                                                        \
    {                                                                                                  \
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F \
    }

#define EX_SSS_AUTH_NEW_MAC_KEY                                                                        \
    {                                                                                                  \
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F \
    }

#define EX_SSS_AUTH_NEW_DEK_KEY                                                                        \
    {                                                                                                  \
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F \
    }
#else
#define EX_SSS_AUTH_NEW_ENC_KEY                                                                                     \
    {                                                                                                               \
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, \
            0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F                      \
    }

#define EX_SSS_AUTH_NEW_MAC_KEY                                                                                     \
    {                                                                                                               \
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, \
            0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F                      \
    }

#define EX_SSS_AUTH_NEW_DEK_KEY                                                                                     \
    {                                                                                                               \
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, \
            0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F                      \
    }
#endif
/* doc:end:new-scp03-keys */

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status    = kStatus_SSS_Fail;
    size_t pfscp_keybitlen = AES_MAX_KEY_LEN * 8;
    size_t pfscp_keylen    = AES_MAX_KEY_LEN;
    uint8_t PROV_KEY_ENC[] = EX_SSS_AUTH_NEW_ENC_KEY;
    uint8_t PROV_KEY_MAC[] = EX_SSS_AUTH_NEW_MAC_KEY;
    uint8_t PROV_KEY_DEK[] = EX_SSS_AUTH_NEW_DEK_KEY;

    /* doc:start:old-scp03-keys */
    uint8_t OLD_KEY_ENC[AES_MAX_KEY_LEN] = {0};
    uint8_t OLD_KEY_MAC[AES_MAX_KEY_LEN] = {0};
    uint8_t OLD_KEY_DEK[AES_MAX_KEY_LEN] = EX_SSS_AUTH_SE05X_KEY_DEK;
    size_t dek_len                       = EX_SSS_AUTH_SE05X_KEY_LEN;
    /* doc:end:old-scp03-keys */

    status = sss_host_key_store_get_key(pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->Enc.keyStore,
        &pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->Enc,
        OLD_KEY_ENC,
        &pfscp_keylen,
        &pfscp_keybitlen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    pfscp_keybitlen = AES_MAX_KEY_LEN * 8;
    pfscp_keylen    = AES_MAX_KEY_LEN;

    status = sss_host_key_store_get_key(pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->Mac.keyStore,
        &pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->Mac,
        OLD_KEY_MAC,
        &pfscp_keylen,
        &pfscp_keybitlen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

#ifdef EX_SSS_SCP03_FILE_PATH

    uint8_t dek[AES_MAX_KEY_LEN] = {0};
    dek_len                      = AES_MAX_KEY_LEN;
    status                       = ex_scp03_keys_from_path(dek, &dek_len);

    if (status == kStatus_SSS_Success) {
        memcpy(OLD_KEY_DEK, dek, dek_len);
    }
    else {
        dek_len = pfscp_keylen;
    }

    LOG_AU8_D(OLD_KEY_DEK, dek_len);

#endif // EX_SSS_SCP03_FILE_PATH

    pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->key_len = dek_len;

    status = sss_host_key_store_set_key(pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->Dek.keyStore,
        &pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->Dek,
        OLD_KEY_DEK,
        sizeof(OLD_KEY_DEK),
        sizeof(OLD_KEY_DEK) * 8,
        NULL,
        0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = tp_PlatformKeys(PROV_KEY_ENC, PROV_KEY_MAC, PROV_KEY_DEK, sizeof(PROV_KEY_ENC), pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* doc:start:revert-scp03-keys */
    status = tp_PlatformKeys(OLD_KEY_ENC, OLD_KEY_MAC, OLD_KEY_DEK, dek_len, pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    /* doc:end:revert-scp03-keys */

#if SSS_HAVE_SE05X_VER_GTE_07_02
    LOG_I(
        " \n\n NOTE:\n SE05x uses KVN (Key Version Number) 11 to authenticate the PlatformSCP channel. \n"
        " SE051 has an additional key in KVN 12 injected. \n"
        " To use KVN 12 for PlatformSCP authentication, update 'EX_SSS_AUTH_SE05X_KEY_VERSION_NO' in ex_sss_auth.h "
        "file. \n");
    LOG_I(" \n ");
#endif

cleanup:

    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_TP_PlatformSCP03keys Example Success !!!...");
    }
    else {
        LOG_E("se05x_TP_PlatformSCP03keys Example Failed !!!...");
    }
    return status;
}

static sss_status_t tp_PlatformKeys(uint8_t *enc, uint8_t *mac, uint8_t *dek, int key_len, ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                   = kStatus_SSS_Fail;
    uint8_t keyVersion                    = pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->keyVerNo;
    tlvHeader_t hdr                       = {{GP_CLA_BYTE, GP_INS_PUTKEY, keyVersion, GP_P2_MULTIPLEKEYS}};
    smStatus_t st                         = SM_NOT_OK;
    uint8_t response[64]                  = {0};
    size_t responseLen                    = sizeof(response);
    uint8_t cmdBuf[128]                   = {0};
    uint8_t len                           = 0;
    uint8_t keyChkValLen                  = 0;
    uint8_t keyChkValues[AES_MAX_KEY_LEN] = {0};

    /* Prepare the packet for SCP03 keys Provision */
    cmdBuf[len] = keyVersion; //keyVersion to replace
    len += 1;
    keyChkValues[keyChkValLen] = keyVersion;
    keyChkValLen += 1;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;

    LOG_I("Updating key with version - %02x", keyVersion);

    /* Prepare the packet for ENC Key */
    status = createKeyData(enc, key_len, &cmdBuf[len], pCtx, MAKE_TEST_ID(__LINE__));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    memcpy(&keyChkValues[keyChkValLen], &cmdBuf[len + 3 + key_len + 1], CRYPTO_KEY_CHECK_LEN);
    len += (3 + key_len + 1 + CRYPTO_KEY_CHECK_LEN);
    keyChkValLen += CRYPTO_KEY_CHECK_LEN;

    /* Prepare the packet for MAC Key */
    status = createKeyData(mac, key_len, &cmdBuf[len], pCtx, MAKE_TEST_ID(__LINE__));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    memcpy(&keyChkValues[keyChkValLen], &cmdBuf[len + 3 + key_len + 1], CRYPTO_KEY_CHECK_LEN);
    len += (3 + key_len + 1 + CRYPTO_KEY_CHECK_LEN);
    keyChkValLen += CRYPTO_KEY_CHECK_LEN;

    /* Prepare the packet for DEK Key */
    status = createKeyData(dek, key_len, &cmdBuf[len], pCtx, MAKE_TEST_ID(__LINE__));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    memcpy(&keyChkValues[keyChkValLen], &cmdBuf[len + 3 + key_len + 1], CRYPTO_KEY_CHECK_LEN);
    len += (3 + key_len + 1 + CRYPTO_KEY_CHECK_LEN);
    keyChkValLen += CRYPTO_KEY_CHECK_LEN;

    /* Reset status to fail */
    status = kStatus_SSS_Fail;
    st     = DoAPDUTxRx_s_Case4(&pSession->s_ctx, &hdr, cmdBuf, len, response, &responseLen);
    ENSURE_OR_GO_CLEANUP(st == SM_OK);

    // reconstruct Return Value
    st = (response[responseLen - 2] << 8) + response[responseLen - 1];
    ENSURE_OR_GO_CLEANUP(st == SM_OK);
    if ((memcmp(response, keyChkValues, keyChkValLen) == 0)) {
        LOG_I("Congratulations !!! Key Rotation Successful!!!!");
#ifdef EX_SSS_SCP03_FILE_PATH
        status = write_keys_toFile(enc, mac, dek, key_len);
        if (status == kStatus_SSS_Success) {
            LOG_W("Changed keys logged to %s.", EX_SSS_SCP03_FILE_PATH);
        }
        else {
            LOG_W("Changed keys are not logged to any file.");
            /* No need to get concerned with status here.
             * Because although file writing failed, Key has changed inside the IC.
             * This status will be overwirtten below */
        }
#endif //EX_SSS_SCP03_FILE_PATH
    }
    else {
        LOG_E("!!! Key Rotation Failed!!!!");
        goto cleanup;
    }
    status = kStatus_SSS_Success;

cleanup:
    return status;
}

#ifdef EX_SSS_SCP03_FILE_PATH
static int do_mkdir()
{
    const char *dir_name = EX_SSS_SCP03_FILE_DIR;
    int ret              = DO_MKDIR(dir_name);
    return ret;
}

static sss_status_t write_keys_toFile(uint8_t *penc, uint8_t *pmac, uint8_t *pdek, int key_len)
{
    FILE *fp = NULL;
    struct stat info;
    int ret = 0;

    const char *file_name = EX_SSS_SCP03_FILE_PATH;
    const char *dir_name  = EX_SSS_SCP03_FILE_DIR;

    ret = stat(dir_name, &info);

    if (ret != 0) {
        LOG_W("Cannot access SCP03 keys directory '%s'", EX_SSS_SCP03_FILE_DIR);
    }
    if ((ret == 0) && (info.st_mode & S_IFDIR)) {
        LOG_I("SCP03 keys directory exists");
        /* Nothing to be done */
    }
    else {
        LOG_I("Creating directory");
        ret = do_mkdir();
        if (ret != 0) {
            LOG_E("Failed to create directory '%s'", dir_name);
            return kStatus_SSS_Fail;
        }
    }

    fp = fopen(file_name, "wb+");
    if (fp == NULL) {
        LOG_W("Could not open '%s'", EX_SSS_SCP03_FILE_PATH);
        return kStatus_SSS_Fail;
    }

    FPRINTF(fp, "ENC ");
    for (int i = 0; i < key_len; i++) {
        if (fprintf(fp, "%02x", penc[i]) < 0) {
            LOG_E("fprintf error");
        }
    }

    FPRINTF(fp, "\n");
    FPRINTF(fp, "MAC ");
    for (int i = 0; i < key_len; i++) {
        if (fprintf(fp, "%02x", pmac[i]) < 0) {
            LOG_E("fprintf error");
        }
    }

    FPRINTF(fp, "\n");
    FPRINTF(fp, "DEK ");
    for (int i = 0; i < key_len; i++) {
        if (fprintf(fp, "%02x", pdek[i]) < 0) {
            LOG_E("fprintf error");
        }
    }
    FPRINTF(fp, "\n");
    if (fclose(fp) != 0) {
        LOG_E("fclose error");
    }
    return kStatus_SSS_Success;
}
#endif // EX_SSS_SCP03_FILE_PATH

static sss_status_t createKeyData(uint8_t *key, int key_len, uint8_t *targetStore, ex_sss_boot_ctx_t *pCtx, uint32_t Id)
{
    uint8_t keyCheckValues[AES_MAX_KEY_LEN] = {0};
    sss_status_t status                     = kStatus_SSS_Fail;

    /* For Each Key add Key Type Length of Key data and key length*/

    targetStore[0]           = PUT_KEYS_KEY_TYPE_CODING_AES; //Key Type
    targetStore[1]           = key_len + 1;                  // Length of the 'AES key data'
    targetStore[2]           = key_len;                      // Length of 'AES key'
    targetStore[3 + key_len] = CRYPTO_KEY_CHECK_LEN;         //Lenth of KCV

    /* Encrypt Key and generate key check values */
    status = genKCVandEncryptKey(&targetStore[3], key_len, keyCheckValues, key, pCtx, Id);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Copy the Key Check values */
    memcpy(&targetStore[3 + key_len + 1], &keyCheckValues[0], CRYPTO_KEY_CHECK_LEN);

cleanup:
    return status;
}

static sss_status_t genKCVandEncryptKey(uint8_t *encryptedkey,
    int key_len,
    uint8_t *keyCheckVal,
    uint8_t *plainKey,
    ex_sss_boot_ctx_t *pCtx,
    uint32_t keyId)
{
    sss_algorithm_t algorithm            = kAlgorithm_SSS_AES_CBC;
    sss_mode_t mode                      = kMode_SSS_Encrypt;
    sss_status_t status                  = kStatus_SSS_Fail;
    uint8_t keyCheckValLen               = key_len;
    uint8_t encryptedkeyLen              = key_len;
    uint8_t refOneArray[AES_MAX_KEY_LEN] = {0};
    sss_symmetric_t symm;
    sss_object_t keyObj;
    uint8_t DekEnckey[AES_MAX_KEY_LEN];
    size_t DekEnckeyLen                  = AES_MAX_KEY_LEN;
    size_t DekEnckeyBitLen               = AES_MAX_KEY_LEN * 8;
    uint8_t dummyBuffer[AES_MAX_KEY_LEN] = {0};
    uint8_t iv[16]                       = {0};

    /* Initialize the key Object */
    status = sss_host_key_object_init(&keyObj, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Allocate the key Object handle */
    status = sss_host_key_object_allocate_handle(
        &keyObj, keyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, AES_MAX_KEY_LEN, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Set the key */
    status = sss_host_key_store_set_key(&pCtx->host_ks, &keyObj, plainKey, key_len, (size_t)(key_len)*8, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Init EBC Encrypt Symmetric Algorithm */
    status = sss_host_symmetric_context_init(&symm, &pCtx->host_session, &keyObj, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    memset(refOneArray, 1, sizeof(refOneArray));

    /* Generate key check values*/
    status = sss_host_cipher_one_go(&symm, iv, sizeof(iv), refOneArray, keyCheckVal, keyCheckValLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Encyrpt the sensitive data */
    status = sss_host_key_store_get_key(&pCtx->host_ks,
        &pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->Dek,
        DekEnckey,
        &DekEnckeyLen,
        &DekEnckeyBitLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Set the key */
    status = sss_host_key_store_set_key(&pCtx->host_ks,
        &keyObj,
        DekEnckey,
        pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->key_len,
        (size_t)(pCtx->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx->key_len) * 8,
        NULL,
        0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_host_symmetric_context_init(&symm, &pCtx->host_session, &keyObj, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Encrypt the key */
    status = sss_host_cipher_one_go(&symm, iv, sizeof(iv), plainKey, dummyBuffer, encryptedkeyLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    memcpy(encryptedkey, dummyBuffer, encryptedkeyLen);

    /* Free Symmetric Object */
    if (symm.keyObject) {
        sss_host_symmetric_context_free(&symm);
    }
    sss_host_key_object_free(&keyObj);
cleanup:
    return status;
}
