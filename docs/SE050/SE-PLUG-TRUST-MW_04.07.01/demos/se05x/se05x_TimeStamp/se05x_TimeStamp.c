/* Copyright 2020,2025 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <ex_sss.h>
#include <ex_sss_auth.h>
#include <ex_sss_boot.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include <se05x_APDU_apis.h>
#include <se05x_tlv.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

#define EC_KEY_BIT_LEN 256
#define ATTESTATION_KEY_ID 0xAFFE5F
#define OBJECT_TO_ATTEST 0xF5EFFA
#define SHA256_HASH_LEN 0x20

#if (SSS_HAVE_SE05X_AUTH_USERID) || (SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03) //UserID Session
#define EX_LOCAL_OBJ_AUTH_ID EX_SSS_AUTH_SE05X_UserID_AUTH_ID
#elif (SSS_HAVE_SE05X_AUTH_NONE) || (SSS_HAVE_SE05X_AUTH_PLATFSCP03) //No auth
#define EX_LOCAL_OBJ_AUTH_ID EX_SSS_AUTH_SE05X_NONE_AUTH_ID
#elif (SSS_HAVE_SE05X_AUTH_AESKEY) || (SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03) //AESKey
#define EX_LOCAL_OBJ_AUTH_ID EX_SSS_AUTH_SE05X_APPLETSCP_AUTH_ID
#elif (SSS_HAVE_SE05X_AUTH_ECKEY) || (SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03) //ECKey session
#define EX_LOCAL_OBJ_AUTH_ID EX_SSS_AUTH_SE05X_ECKEY_ECDSA_AUTH_ID
#endif
/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_get_timestamp_boot_ctx;
#define EX_SSS_BOOT_PCONTEXT (&gex_sss_get_timestamp_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

static sss_status_t create_attestation_key(ex_sss_boot_ctx_t *pCtx, uint32_t keyId, size_t keyBitLen);
static sss_status_t create_host_public_key(
    ex_sss_boot_ctx_t *pCtx, uint32_t keyId, size_t keyBitLen, sss_object_t *verification_object);
static sss_status_t create_binary_object_to_attest(ex_sss_boot_ctx_t *pCtx, uint32_t keyId);
static sss_status_t attest_binary_object(ex_sss_boot_ctx_t *pCtx,
    uint32_t attestation_key_id,
    uint32_t object_key_id,
    sss_object_t *verification_object,
    SE05x_TimeStamp_t *timestamp);
static int compare_array(uint8_t *array1, uint8_t *array2, size_t bytes_to_compare);
static void clean_attestation_objects(ex_sss_boot_ctx_t *pCtx, uint32_t attestation_key_id, uint32_t keyid_to_attest);

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

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status           = kStatus_SSS_Fail;
    smStatus_t sm_status          = SM_NOT_OK;
    uint32_t attestation_key_id   = ATTESTATION_KEY_ID;
    uint32_t keyid_to_attest      = OBJECT_TO_ATTEST;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    pSe05xSession_t s_ctx         = &pSession->s_ctx;
    SE05x_TimeStamp_t timestamp = {0}, new_timestamp = {0};
    int result = -1;
    /* verification context */
    sss_object_t verification_object = {0};

    sm_status = Se05x_API_GetTimestamp(s_ctx, &timestamp);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    status = kStatus_SSS_Success;
    LOG_AU8_I(timestamp.ts, sizeof(timestamp.ts));

    /* Generate Random Attestation key
     * We use NIST-P 256 in this example
     */
    status = create_attestation_key(pCtx, attestation_key_id, EC_KEY_BIT_LEN);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = create_host_public_key(pCtx, attestation_key_id, EC_KEY_BIT_LEN, &verification_object);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Import any object into the SE which will be
     * read with attestation. In this example, we are
     * importing a binary objecct
     */
    status = create_binary_object_to_attest(pCtx, keyid_to_attest);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = attest_binary_object(pCtx, attestation_key_id, keyid_to_attest, &verification_object, &new_timestamp);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_AU8_I(new_timestamp.ts, sizeof(new_timestamp.ts));

    result = compare_array(timestamp.ts, new_timestamp.ts, sizeof(timestamp.ts));
    status = ((result == 1) || (result == -1)) ? kStatus_SSS_Fail : kStatus_SSS_Success;

cleanup:
    clean_attestation_objects(pCtx, attestation_key_id, keyid_to_attest);
    sss_key_object_free(&verification_object);
    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_TimeStamp Example Success !!!...");
    }
    else {
        LOG_E("se05x_TimeStamp Example Failed !!!...");
    }
    return status;
}

static sss_status_t create_attestation_key(ex_sss_boot_ctx_t *pCtx, uint32_t keyId, size_t keyBitLen)
{
    sss_status_t status          = kStatus_SSS_Fail;
    size_t keylen                = keyBitLen / 8;
    sss_object_t key_attst       = {0};
    sss_cipher_type_t cipherType = kSSS_CipherType_EC_NIST_P;
    sss_policy_u key_pol;
    sss_policy_u common;
    sss_policy_t policy_for_ec_key;

    status = sss_key_object_init(&key_attst, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Generate asymmetric key */
    status = sss_key_object_allocate_handle(
        &key_attst, keyId, kSSS_KeyPart_Pair, cipherType, keylen, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
#if SSS_HAVE_SE05X_VER_GTE_07_02
    key_pol = (sss_policy_u){.type = KPolicy_Asym_Key,
        .auth_obj_id               = EX_LOCAL_OBJ_AUTH_ID,
        .policy                    = {.asymmkey = {
                       .can_Verify        = 1,
                       .can_Encrypt       = 1,
                       .can_Gen           = 1,
                       .can_Import_Export = 1,
                       .can_KA            = 1,
                       .can_Attest        = 1,
                   }}};

    common = (sss_policy_u){.type = KPolicy_Common,
        .auth_obj_id              = EX_LOCAL_OBJ_AUTH_ID,
        .policy                   = {.common = {
                       .can_Delete = 1,
                       .can_Read   = 1,
                   }}};
#else
    key_pol = (sss_policy_u){.type = KPolicy_Asym_Key,
        .auth_obj_id               = EX_LOCAL_OBJ_AUTH_ID,
        .policy                    = {.asymmkey = {
                       .can_Verify        = 1,
                       .can_Encrypt       = 1,
                       .can_Wrap          = 1,
                       .can_Write         = 1,
                       .can_Gen           = 1,
                       .can_Import_Export = 1,
                       .can_KA            = 1,
                       .can_Read          = 1,
                       .can_Attest        = 1,
                   }}};

    common = (sss_policy_u){.type = KPolicy_Common,
        .auth_obj_id              = EX_LOCAL_OBJ_AUTH_ID,
        .policy                   = {.common = {
                       .can_Delete = 1,
                   }}};
#endif
    policy_for_ec_key = (sss_policy_t){.nPolicies = 2, .policies = {&key_pol, &common}};

    status = sss_key_store_generate_key(&pCtx->ks, &key_attst, keyBitLen, &policy_for_ec_key);

cleanup:
    return status;
}

static sss_status_t create_host_public_key(
    ex_sss_boot_ctx_t *pCtx, uint32_t keyId, size_t keyBitLen, sss_object_t *verification_object)
{
    sss_status_t status          = kStatus_SSS_Fail;
    sss_object_t attestation_key = {0};
    uint8_t public_key[100]      = {0};
    size_t public_key_len        = sizeof(public_key);

    status = sss_key_object_init(&attestation_key, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&attestation_key, keyId);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_get_key(&pCtx->ks, &attestation_key, public_key, &public_key_len, &keyBitLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_init(verification_object, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(verification_object,
        __LINE__,
        kSSS_KeyPart_Public,
        (sss_cipher_type_t)attestation_key.cipherType,
        public_key_len,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->host_ks, verification_object, public_key, public_key_len, keyBitLen, NULL, 0);

cleanup:
    sss_key_object_free(&attestation_key);
    return status;
}

static sss_status_t create_binary_object_to_attest(ex_sss_boot_ctx_t *pCtx, uint32_t keyId)
{
    sss_status_t status           = kStatus_SSS_Fail;
    sss_object_t object_to_attest = {0};
    sss_key_part_t key_part       = kSSS_KeyPart_Default;
    sss_cipher_type_t cipherType  = kSSS_CipherType_Binary;
    uint8_t data[]                = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    size_t dataLen                = sizeof(data);
    sss_policy_u obj_pol;
    sss_policy_u common;
    sss_policy_t policy_for_bin_obj;

    status = sss_key_object_init(&object_to_attest, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Generate asymmetric key */
    status = sss_key_object_allocate_handle(
        &object_to_attest, keyId, key_part, cipherType, dataLen, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    obj_pol            = (sss_policy_u){.type = KPolicy_File,
        .auth_obj_id               = EX_LOCAL_OBJ_AUTH_ID,
        .policy                    = {.file = {
                       .can_Write = 1,
                       .can_Read  = 1,
                   }}};
    common             = (sss_policy_u){.type = KPolicy_Common,
        .auth_obj_id              = EX_LOCAL_OBJ_AUTH_ID,
        .policy                   = {.common = {
                       .can_Delete = 1,
                   }}};
    policy_for_bin_obj = (sss_policy_t){.nPolicies = 2, .policies = {&obj_pol, &common}};

    status = sss_key_store_set_key(
        &pCtx->ks, &object_to_attest, data, dataLen, dataLen, &policy_for_bin_obj, sizeof(policy_for_bin_obj));

cleanup:
    return status;
}

static sss_status_t attest_binary_object(ex_sss_boot_ctx_t *pCtx,
    uint32_t attestation_key_id,
    uint32_t object_key_id,
    sss_object_t *verification_object,
    SE05x_TimeStamp_t *timestamp)
{
    sss_status_t status                      = kStatus_SSS_Fail;
    uint8_t attested_object_data[2500]       = {0};
    size_t attestedObjByteLen                = sizeof(attested_object_data);
    size_t objBitLen                         = attestedObjByteLen * 8;
    sss_algorithm_t algorithm                = kAlgorithm_SSS_ECDSA_SHA256;
    sss_object_t sss_attestation_object      = {0};
    sss_object_t sss_object_to_attest        = {0};
    sss_se05x_attst_comp_data_t comp_data[2] = {0};
    sss_se05x_attst_data_t att_data          = {.valid_number = 2};
    /* Random data from the host to check if SE
     * answers to current attestation request and
     * not an older response is used */

    /* clang-format off */
    uint8_t freshness[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    /* clang-format on */

    /* Variables for verification */
    uint8_t plainData[2600] = {0};
    size_t plainDataLen     = sizeof(plainData);
    uint8_t digest[64]      = {0};
    size_t digestLen        = sizeof(digest);
    sss_digest_t digest_ctx;
    sss_algorithm_t digest_algorithm = kAlgorithm_SSS_SHA256;
    sss_asymmetric_t verify_ctx;

#if SSS_HAVE_SE05X_VER_GTE_07_02
    uint8_t *pData                     = &plainData[0];
    size_t buffLen                     = sizeof(plainData);
    uint8_t cmdHashed[SHA256_HASH_LEN] = {0};
    size_t cmdHashedLen                = sizeof(cmdHashed);
    int tlvRet                         = 0;
    uint8_t timestamp_1[32]            = {0};
    uint8_t objLenRet[2]               = {
        0,
    };
#endif

    /* Initialize Attesttation Object */
    status = sss_key_object_init(&sss_attestation_object, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&sss_attestation_object, attestation_key_id);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Initialize object to attest */
    status = sss_key_object_init(&sss_object_to_attest, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&sss_object_to_attest, object_key_id);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    /* Prepare/init attestation data structure */

    memcpy(&att_data.data, &comp_data[0], sizeof(comp_data));
    att_data.data[0].attributeLen = sizeof(att_data.data[0].attribute);
#if SSS_HAVE_SE05X_VER_GTE_07_02
    att_data.data[0].cmdLen     = sizeof(att_data.data[0].cmd);
    att_data.data[0].objSizeLen = sizeof(att_data.data[0].objSize);
#else
    att_data.data[0].outrandomLen = sizeof(att_data.data[0].outrandom);
#endif
    att_data.data[0].chipIdLen    = sizeof(att_data.data[0].attribute);
    att_data.data[0].signatureLen = sizeof(att_data.data[0].signature);
    att_data.data[1].attributeLen = sizeof(att_data.data[1].attribute);
#if SSS_HAVE_SE05X_VER_GTE_07_02
    att_data.data[1].cmdLen     = sizeof(att_data.data[1].cmd);
    att_data.data[1].objSizeLen = sizeof(att_data.data[1].objSize);
#else
    att_data.data[1].outrandomLen = sizeof(att_data.data[1].outrandom);
#endif
    att_data.data[1].chipIdLen    = sizeof(att_data.data[1].attribute);
    att_data.data[1].signatureLen = sizeof(att_data.data[1].signature);

    /* Execute attested read
     * We use attestation object to attest (sign) all read data + object attributes
     * Returns object attributes and signature in att_data
     */

    status = sss_se05x_key_store_get_key_attst((sss_se05x_key_store_t *)&pCtx->ks,
        (sss_se05x_object_t *)&sss_object_to_attest,
        attested_object_data,
        &attestedObjByteLen,
        &objBitLen,
        (sss_se05x_object_t *)&sss_attestation_object,
        algorithm,
        freshness,
        sizeof(freshness),
        &att_data);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Perform verification operation here on the following data
     *      (key + offset) +
     *      att_data->data[0].attribute +
     *      att_data->data[0].timestamp +
     *      att_data->data[0].outrandom +
     *      att_data->data[0].chipId
     * with signature
     *      att_data->data[0].signature
     *
     * We perform signature verification on host.
     * First we digest the data then pass it to verify API
     */
#if SSS_HAVE_SE05X_VER_GTE_07_02
    plainDataLen = attestedObjByteLen + att_data.data[0].attributeLen + att_data.data[0].timeStampLen +
                   SHA256_HASH_LEN + att_data.data[0].chipIdLen;
#else
    plainDataLen = attestedObjByteLen + att_data.data[0].attributeLen + att_data.data[0].timeStampLen +
                   att_data.data[0].outrandomLen + att_data.data[0].chipIdLen;
#endif

    if (plainDataLen > sizeof(plainData)) {
        LOG_E("Insufficient Buffer");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }
#if SSS_HAVE_SE05X_VER_GTE_07_02
    status = sss_digest_context_init(&digest_ctx, &pCtx->host_session, digest_algorithm, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_D("Cmd ", attst_data.data[0].cmd, attst_data.data[0].cmdLen);
    status = sss_digest_one_go(&digest_ctx, att_data.data[0].cmd, (att_data.data[0].cmdLen), cmdHashed, &cmdHashedLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_D("Cmd Hashed ", cmdHashed, cmdHashedLen);
    sss_digest_context_free(&digest_ctx);
    plainDataLen = 0;

    memcpy(pData, cmdHashed, cmdHashedLen);
    plainDataLen = plainDataLen + cmdHashedLen;
    pData        = pData + plainDataLen;

    tlvRet = add_taglength_to_data(
        &pData, &plainDataLen, buffLen, kSE05x_TAG_1, attested_object_data, attestedObjByteLen, true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);
    tlvRet = add_taglength_to_data(
        &pData, &plainDataLen, buffLen, kSE05x_TAG_2, att_data.data[0].chipId, att_data.data[0].chipIdLen, true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);
    tlvRet = add_taglength_to_data(
        &pData, &plainDataLen, buffLen, kSE05x_TAG_3, att_data.data[0].attribute, att_data.data[0].attributeLen, true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);

    objLenRet[0] = (uint8_t)((attestedObjByteLen >> 1 * 8) & 0xFF);
    objLenRet[1] = (uint8_t)((attestedObjByteLen >> 0 * 8) & 0xFF);
    if (0 != memcmp(objLenRet, att_data.data[0].objSize, att_data.data[0].objSizeLen)) {
        LOG_E("Read Length for Binary Object is not as expected!!!");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    tlvRet = add_taglength_to_data(
        &pData, &plainDataLen, buffLen, kSE05x_TAG_4, att_data.data[0].objSize, att_data.data[0].objSizeLen, true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);

    memcpy(timestamp_1, &(att_data.data[0].timeStamp), att_data.data[0].timeStampLen);

    tlvRet = add_taglength_to_data(
        &pData, &plainDataLen, buffLen, kSE05x_TAG_TIMESTAMP, timestamp_1, att_data.data[0].timeStampLen, true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);

    LOG_MAU8_D("plainData ", plainData, plainDataLen);

#else
    memcpy(plainData, attested_object_data, attestedObjByteLen);
    memcpy(plainData + attestedObjByteLen, att_data.data[0].attribute, att_data.data[0].attributeLen);
    memcpy(plainData + attestedObjByteLen + att_data.data[0].attributeLen,
        &(att_data.data[0].timeStamp),
        att_data.data[0].timeStampLen);
    memcpy(plainData + attestedObjByteLen + att_data.data[0].attributeLen + att_data.data[0].timeStampLen,
        att_data.data[0].outrandom,
        att_data.data[0].outrandomLen);
    memcpy(plainData + attestedObjByteLen + att_data.data[0].attributeLen + att_data.data[0].timeStampLen +
               att_data.data[0].outrandomLen,
        att_data.data[0].chipId,
        att_data.data[0].chipIdLen);
#endif

    status = sss_digest_context_init(&digest_ctx, &pCtx->host_session, digest_algorithm, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_digest_one_go(&digest_ctx, plainData, plainDataLen, digest, &digestLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    sss_digest_context_free(&digest_ctx);

    /* Verify signature */
    sss_asymmetric_context_init(&verify_ctx, &pCtx->host_session, verification_object, algorithm, kMode_SSS_Verify);

    status = sss_asymmetric_verify_digest(
        &verify_ctx, digest, digestLen, att_data.data[0].signature, att_data.data[0].signatureLen);

    sss_asymmetric_context_free(&verify_ctx);
    sss_key_object_free(&sss_object_to_attest);
    sss_key_object_free(&sss_attestation_object);

    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    memcpy(timestamp, &(att_data.data[0].timeStamp), att_data.data[0].timeStampLen);

cleanup:
    return status;
}

static void clean_attestation_objects(ex_sss_boot_ctx_t *pCtx, uint32_t attestation_key_id, uint32_t keyid_to_attest)
{
    sss_status_t status           = kStatus_SSS_Fail;
    sss_object_t object_to_delete = {0};
    status                        = sss_key_object_init(&object_to_delete, &pCtx->ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    /* Delete attestation object */
    status = sss_key_object_get_handle(&object_to_delete, attestation_key_id);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_store_erase_key(&pCtx->ks, &object_to_delete);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    /* Delete object to attest */
    status = sss_key_object_get_handle(&object_to_delete, keyid_to_attest);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_store_erase_key(&pCtx->ks, &object_to_delete);

exit:
    return;
}

static int compare_array(uint8_t *array1, uint8_t *array2, size_t bytes_to_compare)
{
    size_t i         = 0;
    int compareValue = 0;
    for (i = 0; i < bytes_to_compare; i++) {
        if (array1[i] > array2[i]) {
            compareValue = 1;
            break;
        }
        else if (array1[i] < array2[i]) {
            compareValue = 2;
            break;
        }
    }
    return compareValue;
}
