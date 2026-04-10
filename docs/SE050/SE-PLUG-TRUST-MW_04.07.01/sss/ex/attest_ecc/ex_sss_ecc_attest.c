/*
*
* Copyright 2018-2020,2025 NXP
* SPDX-License-Identifier: Apache-2.0
*/

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxEnsure.h>
#include <nxLog_App.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define EC_KEY_NIST256_BIT_LEN 256
#define EC_KEY_NIST256_HEADER_LEN 26
#define SHA256_HASH_LEN 0x20

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_ecc_boot_ctx;
sss_object_t ecc_key;
sss_object_t attestation_ecc_key;
sss_algorithm_t attst_algorithm = kAlgorithm_SSS_ECDSA_SHA256;
sss_se05x_attst_data_t attestation_data;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */
static sss_status_t ex_sss_initialise_attst_data(sss_se05x_attst_data_t *attst_data);
static sss_status_t ex_sss_verify_attested_key(ex_sss_boot_ctx_t *pCtx, uint8_t *publicKey, size_t publicKeyByteLen);

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */
#if SSS_HAVE_SE05X_VER_GTE_07_02
extern int add_taglength_to_data(uint8_t **buf,
    size_t *bufLen,
    const size_t actualBufLen,
    SE05x_TAG_t tag,
    const uint8_t *cmd,
    size_t cmdLen,
    bool extendedLength);
#endif //#if SSS_HAVE_SE05X_VER_GTE_07_02

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_ecc_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

/* clang-format off */

const uint8_t ecc_keyPairData[] = {
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
    0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
    0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,
    0x01, 0x01, 0x04, 0x20, 0x78, 0xE5, 0x20, 0x6A,
    0x08, 0xED, 0xD2, 0x52, 0x36, 0x33, 0x8A, 0x24,
    0x84, 0xE4, 0x2F, 0x1F, 0x7D, 0x1F, 0x6D, 0x94,
    0x37, 0xA9, 0x95, 0x86, 0xDA, 0xFC, 0xD2, 0x23,
    0x6F, 0xA2, 0x87, 0x35, 0xA1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0xED, 0xA7, 0xE9, 0x0B, 0xF9, 0x20,
    0xCF, 0xFB, 0x9D, 0xF6, 0xDB, 0xCE, 0xF7, 0x20,
    0xE1, 0x23, 0x8B, 0x3C, 0xEE, 0x84, 0x86, 0xD2,
    0x50, 0xE4, 0xDF, 0x30, 0x11, 0x50, 0x1A, 0x15,
    0x08, 0xA6, 0x2E, 0xD7, 0x49, 0x52, 0x78, 0x63,
    0x6E, 0x61, 0xE8, 0x5F, 0xED, 0xB0, 0x6D, 0x87,
    0x92, 0x0A, 0x04, 0x19, 0x14, 0xFE, 0x76, 0x63,
    0x55, 0xDF, 0xBD, 0x68, 0x61, 0x59, 0x31, 0x8E,
    0x68, 0x7C
};

const uint8_t ecc_PubKeyData[] =
{
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xED, 0xA7, 0xE9, 0x0B, 0xF9,
    0x20, 0xCF, 0xFB, 0x9D, 0xF6, 0xDB, 0xCE, 0xF7,
    0x20, 0xE1, 0x23, 0x8B, 0x3C, 0xEE, 0x84, 0x86,
    0xD2, 0x50, 0xE4, 0xDF, 0x30, 0x11, 0x50, 0x1A,
    0x15, 0x08, 0xA6, 0x2E, 0xD7, 0x49, 0x52, 0x78,
    0x63, 0x6E, 0x61, 0xE8, 0x5F, 0xED, 0xB0, 0x6D,
    0x87, 0x92, 0x0A, 0x04, 0x19, 0x14, 0xFE, 0x76,
    0x63, 0x55, 0xDF, 0xBD, 0x68, 0x61, 0x59, 0x31,
    0x8E, 0x68, 0x7C
};

/* clang-format on */

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status     = kStatus_SSS_Success;
    uint8_t publicKey[256]  = {0};
    size_t publicKeyByteLen = sizeof(publicKey);
    size_t publicKeyBitLen  = sizeof(publicKey) * 8;
    uint8_t random[16]      = {1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7};

#if SSS_HAVE_SE05X_VER_GTE_07_02
    const sss_policy_u ecc_key_pol = {.type = KPolicy_Asym_Key,
        .auth_obj_id                        = 0,
        .policy                             = {.asymmkey = {
                       .can_Verify        = 1,
                       .can_Encrypt       = 1,
                       .can_Gen           = 1,
                       .can_Import_Export = 1,
                       .can_KA            = 1,
                       .can_Attest        = 1,
                   }}};
    const sss_policy_u common      = {.type = KPolicy_Common,
        .auth_obj_id                   = 0,
        .policy                        = {.common = {
                       .can_Delete = 1,
                       .can_Read   = 1,
                   }}};
#else
    const sss_policy_u ecc_key_pol = {.type = KPolicy_Asym_Key,
        .auth_obj_id                        = 0,
        .policy                             = {.asymmkey = {
                       .can_Verify        = 1,
                       .can_Encrypt       = 1,
                       .can_KD            = 1,
                       .can_Wrap          = 1,
                       .can_Write         = 1,
                       .can_Gen           = 1,
                       .can_Import_Export = 1,
                       .can_KA            = 1,
                       .can_Read          = 1,
                       .can_Attest        = 1,
                   }}};
    const sss_policy_u common      = {.type = KPolicy_Common,
        .auth_obj_id                   = 0,
        .policy                        = {.common = {
                       .can_Delete = 1,
                   }}};
#endif
    sss_policy_t attestation_ecc_key_pol = {.nPolicies = 2, .policies = {&ecc_key_pol, &common}};

    LOG_I("Running ECC key attestation example ex_sss_attest_ecc.c ");

    LOG_I("Inject ECC key pair - 'ecc_key'");

    status = sss_key_object_init(&ecc_key, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&ecc_key,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        256,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        &pCtx->ks, &ecc_key, ecc_keyPairData, sizeof(ecc_keyPairData), EC_KEY_NIST256_BIT_LEN, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Create a attestation ECC key pair - 'attestation_ecc_key'");

    status = sss_key_object_init(&attestation_ecc_key, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&attestation_ecc_key,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        256,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status =
        sss_key_store_generate_key(&pCtx->ks, &attestation_ecc_key, EC_KEY_NIST256_BIT_LEN, &attestation_ecc_key_pol);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = ex_sss_initialise_attst_data(&attestation_data);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Read public key from ECC key pair 'ecc_key' with attestation");

    status = sss_se05x_key_store_get_key_attst((sss_se05x_key_store_t *)(&pCtx->ks),
        (sss_se05x_object_t *)(&ecc_key),
        publicKey,
        &publicKeyByteLen,
        &publicKeyBitLen,
        (sss_se05x_object_t *)(&attestation_ecc_key),
        attst_algorithm,
        random,
        sizeof(random),
        &attestation_data);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Attested Key -->");
    LOG_MAU8_I("Public Key", publicKey, publicKeyByteLen);
    LOG_MAU8_I("Attribute", attestation_data.data[0].attribute, attestation_data.data[0].attributeLen);
    LOG_MAU8_I("Time Stamp", attestation_data.data[0].timeStamp.ts, attestation_data.data[0].timeStampLen);
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    LOG_MAU8_I("Out Random Value", attestation_data.data[0].outrandom, attestation_data.data[0].outrandomLen);
#endif
    LOG_MAU8_I("Chip Id", attestation_data.data[0].chipId, attestation_data.data[0].chipIdLen);
    LOG_MAU8_I("Signature", attestation_data.data[0].signature, attestation_data.data[0].signatureLen);

    /********* Verify attestation signature *********/
    LOG_I("Verify attestation signature using 'attestation_ecc_key' key");

    /* Singing is done on public key without header */
    status = ex_sss_verify_attested_key(
        pCtx, (publicKey + EC_KEY_NIST256_HEADER_LEN), (publicKeyByteLen - EC_KEY_NIST256_HEADER_LEN));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Verification success ");

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_attest_ecc Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_attest_ecc Example Failed !!!...");
    }

    return status;
}

static sss_status_t ex_sss_verify_attested_key(ex_sss_boot_ctx_t *pCtx, uint8_t *publicKey, size_t publicKeyByteLen)
{
    sss_status_t status     = kStatus_SSS_Success;
    sss_digest_t digest_ctx = {
        0,
    };
    sss_asymmetric_t asymVerifyCtx = {
        0,
    };
    uint8_t plainData[1024]          = {0};
    size_t plainDateLen              = sizeof(plainData);
    uint8_t digest[64]               = {0}; /* Max - SHA512 */
    size_t digestLen                 = sizeof(digest);
    sss_algorithm_t digest_algorithm = kAlgorithm_SSS_SHA256;
#if SSS_HAVE_SE05X_VER_GTE_07_02
    uint8_t *pData        = &plainData[0];
    size_t buffLen        = sizeof(plainData);
    uint8_t cmdHashed[64] = {0};
    size_t cmdHashedLen   = sizeof(cmdHashed);
    int tlvRet            = 0;
    uint8_t timestamp[32] = {0};
    uint8_t objLenRet[2]  = {
        0,
    };
#endif

#if SSS_HAVE_SE05X_VER_GTE_07_02
    ENSURE_OR_GO_CLEANUP(
        (size_t)(publicKeyByteLen + attestation_data.data[0].attributeLen + attestation_data.data[0].timeStampLen +
                 SHA256_HASH_LEN + attestation_data.data[0].chipIdLen) <
        (size_t)(1UL << ((sizeof(size_t) * 4UL) - 1UL)));
    if (plainDateLen < publicKeyByteLen + attestation_data.data[0].attributeLen +
                           attestation_data.data[0].timeStampLen + SHA256_HASH_LEN +
                           attestation_data.data[0].chipIdLen) {
        return kStatus_SSS_Fail;
    }
#else
    ENSURE_OR_GO_CLEANUP(
        (size_t)(publicKeyByteLen + attestation_data.data[0].attributeLen + attestation_data.data[0].timeStampLen +
                 attestation_data.data[0].outrandomLen + attestation_data.data[0].chipIdLen) <
        (size_t)(1UL << ((sizeof(size_t) * 4UL) - 1UL)));
    if (plainDateLen < publicKeyByteLen + attestation_data.data[0].attributeLen +
                           attestation_data.data[0].timeStampLen + attestation_data.data[0].outrandomLen +
                           attestation_data.data[0].chipIdLen) {
        return kStatus_SSS_Fail;
    }
#endif
    else {
#if SSS_HAVE_SE05X_VER_GTE_07_02

        status = sss_digest_context_init(&digest_ctx, &pCtx->session, digest_algorithm, kMode_SSS_Digest);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_MAU8_D("Cmd ", attestation_data.data[0].cmd, attestation_data.data[0].cmdLen);
        status = sss_digest_one_go(
            &digest_ctx, attestation_data.data[0].cmd, (attestation_data.data[0].cmdLen), cmdHashed, &cmdHashedLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_MAU8_D("Cmd Hashed ", cmdHashed, cmdHashedLen);
        sss_digest_context_free(&digest_ctx);
        size_t plainDataLen = 0;

        memcpy(pData, cmdHashed, cmdHashedLen);
        plainDataLen = plainDataLen + cmdHashedLen;
        pData        = pData + plainDataLen;

        tlvRet = add_taglength_to_data(&pData, &plainDataLen, buffLen, kSE05x_TAG_1, publicKey, publicKeyByteLen, true);
        ENSURE_OR_GO_CLEANUP(tlvRet == 0);
        tlvRet = add_taglength_to_data(&pData,
            &plainDataLen,
            buffLen,
            kSE05x_TAG_2,
            attestation_data.data[0].chipId,
            attestation_data.data[0].chipIdLen,
            true);
        ENSURE_OR_GO_CLEANUP(tlvRet == 0);
        tlvRet = add_taglength_to_data(&pData,
            &plainDataLen,
            buffLen,
            kSE05x_TAG_3,
            attestation_data.data[0].attribute,
            attestation_data.data[0].attributeLen,
            true);
        ENSURE_OR_GO_CLEANUP(tlvRet == 0);

        size_t pubkey_len = EC_KEY_NIST256_BIT_LEN / 8;
        objLenRet[0]      = (uint8_t)((pubkey_len >> 1 * 8) & 0xFF);
        objLenRet[1]      = (uint8_t)((pubkey_len >> 0 * 8) & 0xFF);

        if (0 != memcmp(objLenRet, attestation_data.data[0].objSize, attestation_data.data[0].objSizeLen)) {
            LOG_E("Read Length for EC  Object is not as expected!!!");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        tlvRet = add_taglength_to_data(&pData,
            &plainDataLen,
            buffLen,
            kSE05x_TAG_4,
            attestation_data.data[0].objSize,
            attestation_data.data[0].objSizeLen,
            true);
        ENSURE_OR_GO_CLEANUP(tlvRet == 0);

        memcpy(timestamp, &(attestation_data.data[0].timeStamp), attestation_data.data[0].timeStampLen);

        tlvRet = add_taglength_to_data(&pData,
            &plainDataLen,
            buffLen,
            kSE05x_TAG_TIMESTAMP,
            timestamp,
            attestation_data.data[0].timeStampLen,
            true);
        ENSURE_OR_GO_CLEANUP(tlvRet == 0);

        LOG_MAU8_D("plainData ", plainData, plainDataLen);

        plainDateLen = plainDataLen;
#else
        memcpy(plainData, publicKey, publicKeyByteLen);
        memcpy(plainData + publicKeyByteLen, attestation_data.data[0].attribute, attestation_data.data[0].attributeLen);
        memcpy(plainData + publicKeyByteLen + attestation_data.data[0].attributeLen,
            &(attestation_data.data[0].timeStamp),
            attestation_data.data[0].timeStampLen);
        memcpy(plainData + publicKeyByteLen + attestation_data.data[0].attributeLen +
                   attestation_data.data[0].timeStampLen,
            attestation_data.data[0].outrandom,
            attestation_data.data[0].outrandomLen);
        memcpy(plainData + publicKeyByteLen + attestation_data.data[0].attributeLen +
                   attestation_data.data[0].timeStampLen + attestation_data.data[0].outrandomLen,
            attestation_data.data[0].chipId,
            attestation_data.data[0].chipIdLen);
        plainDateLen = publicKeyByteLen + attestation_data.data[0].attributeLen +
                       attestation_data.data[0].timeStampLen + attestation_data.data[0].outrandomLen +
                       attestation_data.data[0].chipIdLen;
#endif //#if SSS_HAVE_SE05X_VER_GTE_07_02
    }

    status = sss_digest_context_init(&digest_ctx, &pCtx->session, digest_algorithm, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_digest_one_go(&digest_ctx, plainData, plainDateLen, digest, &digestLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* verify the attestation signature */

    status = sss_asymmetric_context_init(
        &asymVerifyCtx, &pCtx->session, &attestation_ecc_key, attst_algorithm, kMode_SSS_Verify);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_asymmetric_verify_digest(
        &asymVerifyCtx, digest, digestLen, attestation_data.data[0].signature, attestation_data.data[0].signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:
    if (digest_ctx.session != NULL) {
        sss_digest_context_free(&digest_ctx);
    }

    if (asymVerifyCtx.session != NULL) {
        sss_asymmetric_context_free(&asymVerifyCtx);
    }

    if (kStatus_SSS_Success != status) {
        LOG_I("Verification of attestation signature failed !!!...");
    }

    return status;
}

static sss_status_t ex_sss_initialise_attst_data(sss_se05x_attst_data_t *attst_data)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t i;

    if (attst_data != NULL) {
        memset(attst_data, 0, sizeof(sss_se05x_attst_data_t));

        for (i = 0; i < SE05X_MAX_ATTST_DATA; i++) {
#if SSS_HAVE_SE05X_VER_GTE_07_02
            attst_data->data[i].cmdLen     = sizeof(attst_data->data[i].cmd);
            attst_data->data[i].objSizeLen = sizeof(attst_data->data[i].objSize);
#else
            attst_data->data[i].outrandomLen = sizeof(attst_data->data[i].outrandom);
#endif //#if SSS_HAVE_SE05X_VER_GTE_07_02
            attst_data->data[i].timeStampLen = sizeof(attst_data->data[i].timeStamp);
            attst_data->data[i].chipIdLen    = sizeof(attst_data->data[i].chipId);
            attst_data->data[i].attributeLen = sizeof(attst_data->data[i].attribute);
            attst_data->data[i].signatureLen = sizeof(attst_data->data[i].signature);
        }
        attst_data->valid_number = SE05X_MAX_ATTST_DATA;

        status = kStatus_SSS_Success;
    }
    return status;
}
