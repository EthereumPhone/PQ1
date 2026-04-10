/* Copyright 2020,2021,2025 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <ex_sss.h>
#include <ex_sss_auth.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include <se05x_APDU_apis.h>
#include <se05x_ReadWithAttestation.h>
#include <se05x_enums.h>
#include <string.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

#if (SSS_HAVE_SE05X_AUTH_USERID) || (SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03) //UserID Session
#define EX_LOCAL_OBJ_AUTH_ID EX_SSS_AUTH_SE05X_UserID_AUTH_ID
#elif (SSS_HAVE_SE05X_AUTH_NONE) || (SSS_HAVE_SE05X_AUTH_PLATFSCP03) //No auth
#define EX_LOCAL_OBJ_AUTH_ID EX_SSS_AUTH_SE05X_NONE_AUTH_ID
#elif (SSS_HAVE_SE05X_AUTH_AESKEY) || (SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03) //AESKey
#define EX_LOCAL_OBJ_AUTH_ID EX_SSS_AUTH_SE05X_APPLETSCP_AUTH_ID
#elif (SSS_HAVE_SE05X_AUTH_ECKEY) || (SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03) //ECKey session
#define EX_LOCAL_OBJ_AUTH_ID EX_SSS_AUTH_SE05X_ECKEY_ECDSA_AUTH_ID
#endif

#define AUTHENTICATION_OBJ_ATTR_POLICYLEN_OFFSET 14
#define KEYOBJ_VERSION_LENGTH 4

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

typedef struct authObj_attributes
{
    uint16_t auth_attempts_cntr;
    uint16_t max_auth_attempts_cntr;
} authObj_attributes_t;

typedef struct non_authObj_attributes
{
    uint16_t min_tagLen_for_AEAD;
    uint16_t rfu;
} non_authObj_attributes_t;

typedef union attr {
    authObj_attributes_t authObjAttr;
    non_authObj_attributes_t nonAuthObjAttr;
} attr_u;

typedef struct ObjAttr
{
    uint32_t object_id;
    SE05x_SecObjTyp_t object_type;
    SE05x_SetIndicator_t auth_attr;
    attr_u attr;
    uint32_t auth_obj_id_owner;
    SE05x_Origin_t object_origin;
    uint32_t object_version;
} ObjAttr_t;

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_attst_read_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */
#if SSS_HAVE_SE05X_VER_GTE_07_02
extern int add_taglength_to_data(uint8_t **buf,
    size_t *bufLen,
    const size_t actualBufLen,
    SE05x_TAG_t tag,
    const uint8_t *cmd,
    size_t cmdLen,
    bool extendedLength);
#endif

static sss_status_t create_object_to_attest(ex_sss_boot_ctx_t *pCtx, uint32_t *applied_policy);
static void log_attribute_type(const SE05x_SecObjTyp_t type);
static void log_attribute_auth(const SE05x_SetIndicator_t auth);
static void log_attribute_access_rule(uint32_t ar_header);
static void log_attribute_origin(const SE05x_Origin_t origin);
sss_status_t read_large_object_with_attestation(sss_se05x_key_store_t *keyStore,
    sss_se05x_object_t *keyObject,
    uint8_t *key,
    size_t *keylen,
    size_t *pKeyBitLen,
    sss_algorithm_t algorithm_attst,
    uint8_t *random_attst,
    size_t randomLen_attst,
    sss_se05x_attst_data_t *attst_data,
    sss_object_t *verification_object);
static sss_status_t create_host_public_key(
    ex_sss_boot_ctx_t *pCtx, uint32_t keyId, size_t keyBitLen, sss_object_t *verification_object);
static void clean_attestated_object(ex_sss_boot_ctx_t *pCtx, uint32_t keyid_to_attest);

#if !(SSS_HAVE_SE05X_VER_GTE_07_02)
static sss_status_t check_for_reliable_attestation(
    ex_sss_boot_ctx_t *pCtx, uint32_t objPolicies, ObjAttr_t Obj_attr, size_t LengthTag1Tag2);
#endif

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_attst_read_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    LOG_I("Running example se05x_ReadWithAttestation");

    sss_status_t status                 = kStatus_SSS_Success;
    uint8_t obj[2500]                   = {0};
    size_t objByteLen                   = sizeof(obj);
    size_t objBitLen                    = objByteLen * 8;
    sss_object_t sss_object_to_attest   = {0};
    sss_object_t sss_attestation_object = {0};
    sss_algorithm_t algorithm           = kAlgorithm_SSS_ECDSA_SHA256;
    uint32_t auth_obj                   = 0;

    /* Variables for verification */
    sss_object_t verification_object = {0};
    uint8_t plainData[2500]          = {0};
    size_t plainDataLen              = sizeof(plainData);
    uint8_t data[]                   = OBJECT_TO_ATTEST;
#if SSS_HAVE_SE05X_VER_GTE_07_02
    uint8_t *pData        = &plainData[0];
    size_t buffLen        = sizeof(plainData);
    uint8_t cmdHashed[32] = {0};
    size_t cmdHashedLen   = sizeof(cmdHashed);
    int tlvRet            = 0;
    uint8_t timestamp[32] = {0};
    uint8_t objLenRet[2]  = {
        0,
    };

#endif
    uint8_t digest[64] = {0};
    size_t digestLen   = sizeof(digest);
    sss_digest_t digest_ctx;
    sss_algorithm_t digest_algorithm = kAlgorithm_SSS_SHA256;
    sss_asymmetric_t verify_ctx;
    uint8_t datai           = 0;
    uint8_t *att            = NULL;
    uint8_t i               = 0;
    size_t attr_Len         = 0;
    uint8_t attr_Cnt        = 0;
    ObjAttr_t attrib        = {0};
    uint32_t applied_policy = 0;
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    size_t lengthTag1Tag2 = 0;
#endif

    /* doc:start:read-w-attestation */
    /* Prepare/init attestation data structure */

    sss_se05x_attst_comp_data_t comp_data[2] = {0};
    sss_se05x_attst_data_t att_data          = {.valid_number = 2};
    /* Random data from the host to check if SE
     * answers to current attestation request and
     * not an older response is used */

    /* clang-format off */
    uint8_t freshness[16] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
    /* doc:end:read-w-attestation */

    /* Use pre-provisioned Attestation key
    * For SE05x A & C EC key is at 0xF0000012
    * For SE05x B it RSA key at 0xF0000010 */

    status = create_host_public_key(
        pCtx, ATTESTATION_KEY_ID, KEY_BIT_LEN, &verification_object);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Import any object into the SE which will be
     * read with attestation. In this example, we are
     * importing a binary objecct
     */
    status = create_object_to_attest(pCtx, &applied_policy);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Initialize Attestation Object */
    status = sss_key_object_init(&sss_attestation_object, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status =
        sss_key_object_get_handle(&sss_attestation_object, ATTESTATION_KEY_ID);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Initialize object to attest */
    status = sss_key_object_init(&sss_object_to_attest, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&sss_object_to_attest, OBJECT_KEY_ID);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* doc:start:read-w-attestation */
    memcpy(&att_data.data, &comp_data[0], sizeof(comp_data));
    att_data.data[0].attributeLen = sizeof(att_data.data[0].attribute);
#if SSS_HAVE_SE05X_VER_GTE_07_02
    att_data.data[0].cmdLen = sizeof(att_data.data[0].cmd);
    att_data.data[0].objSizeLen = sizeof(att_data.data[0].objSize);

#else
    att_data.data[0].outrandomLen = sizeof(att_data.data[0].outrandom);
#endif
    att_data.data[0].chipIdLen = sizeof(att_data.data[0].chipId);
    att_data.data[0].signatureLen = sizeof(att_data.data[0].signature);
    att_data.data[1].attributeLen = sizeof(att_data.data[1].attribute);
#if SSS_HAVE_SE05X_VER_GTE_07_02
    att_data.data[1].cmdLen = sizeof(att_data.data[1].cmd);
    att_data.data[1].objSizeLen = sizeof(att_data.data[1].objSize);
#else
    att_data.data[1].outrandomLen = sizeof(att_data.data[1].outrandom);
#endif
    att_data.data[1].chipIdLen = sizeof(att_data.data[1].chipId);
    att_data.data[1].signatureLen = sizeof(att_data.data[1].signature);

    /* clang-format on */

    /* Execute attested read
     * We use attestation object to attest (sign) all read data + object attributes
     * Returns object attributes and signature in att_data
     */

    status = sss_se05x_key_store_get_key_attst((sss_se05x_key_store_t *)&pCtx->ks,
        (sss_se05x_object_t *)&sss_object_to_attest,
        obj,
        &objByteLen,
        &objBitLen,
        (sss_se05x_object_t *)&sss_attestation_object,
        algorithm,
        freshness,
        sizeof(freshness),
        &att_data);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

#if !SSS_HAVE_SE05X_VER_GTE_07_02
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

    memcpy(plainData, obj, objByteLen);
    memcpy(plainData + objByteLen, att_data.data[0].attribute, att_data.data[0].attributeLen);
    lengthTag1Tag2 = objByteLen + att_data.data[0].attributeLen;
    memcpy(plainData + objByteLen + att_data.data[0].attributeLen,
        &(att_data.data[0].timeStamp),
        att_data.data[0].timeStampLen);

    memcpy(plainData + objByteLen + att_data.data[0].attributeLen + att_data.data[0].timeStampLen,
        att_data.data[0].outrandom,
        att_data.data[0].outrandomLen);
    memcpy(plainData + objByteLen + att_data.data[0].attributeLen + att_data.data[0].timeStampLen +
               att_data.data[0].outrandomLen,
        att_data.data[0].chipId,
        att_data.data[0].chipIdLen);

    plainDataLen = objByteLen + att_data.data[0].attributeLen + att_data.data[0].timeStampLen +
                   att_data.data[0].outrandomLen + att_data.data[0].chipIdLen;
#else
    /* Perform verification operation here on the following data
    *      Perform hash on capdu +
    *      Tag(0x41) + Length + data +
    *      Tag(0x42) + Length +att_data.data[0].chipId +
    *      Tag(0x43) + Length +att_data.data[0].attribute +
    *      Tag(0x44) + Length +dataLen +
    *      Tag(0x4F) + Length +att_data.data[0].timestamp
    * We perform signature verification on host.
    * First we digest the data then pass it to verify API with recv signature
    */

    status = sss_digest_context_init(&digest_ctx, &pCtx->host_session, digest_algorithm, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("Cmd ", att_data.data[0].cmd, att_data.data[0].cmdLen);

    status = sss_digest_one_go(&digest_ctx, att_data.data[0].cmd, (att_data.data[0].cmdLen), cmdHashed, &cmdHashedLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("Cmd Hashed ", cmdHashed, cmdHashedLen);
    sss_digest_context_free(&digest_ctx);
    plainDataLen = 0;

    memcpy(pData, cmdHashed, cmdHashedLen);
    plainDataLen = plainDataLen + cmdHashedLen;
    pData        = pData + plainDataLen;

    tlvRet = add_taglength_to_data(&pData, &plainDataLen, buffLen, kSE05x_TAG_1, obj, objByteLen, true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);
    tlvRet = add_taglength_to_data(
        &pData, &plainDataLen, buffLen, kSE05x_TAG_2, att_data.data[0].chipId, att_data.data[0].chipIdLen, true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);
    tlvRet = add_taglength_to_data(
        &pData, &plainDataLen, buffLen, kSE05x_TAG_3, att_data.data[0].attribute, att_data.data[0].attributeLen, true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);

    objLenRet[0] = (uint8_t)((objByteLen >> 1 * 8) & 0xFF);
    objLenRet[1] = (uint8_t)((objByteLen >> 0 * 8) & 0xFF);
    if (0 != memcmp(objLenRet, att_data.data[0].objSize, att_data.data[0].objSizeLen)) {
        LOG_E("Read Length for Binary Object is not as expected!!!");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    tlvRet = add_taglength_to_data(
        &pData, &plainDataLen, buffLen, kSE05x_TAG_4, att_data.data[0].objSize, att_data.data[0].objSizeLen, true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);

    memcpy(timestamp, &(att_data.data[0].timeStamp), att_data.data[0].timeStampLen);

    tlvRet = add_taglength_to_data(
        &pData, &plainDataLen, buffLen, kSE05x_TAG_TIMESTAMP, timestamp, att_data.data[0].timeStampLen, true);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);

    LOG_MAU8_I("plainData ", plainData, plainDataLen);

#endif

    status = sss_digest_context_init(&digest_ctx, &pCtx->host_session, digest_algorithm, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_digest_one_go(&digest_ctx, plainData, plainDataLen, digest, &digestLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    sss_digest_context_free(&digest_ctx);

    /* Verify signature */
    sss_asymmetric_context_init(&verify_ctx, &pCtx->host_session, &verification_object, algorithm, kMode_SSS_Verify);

    status = sss_asymmetric_verify_digest(
        &verify_ctx, digest, digestLen, att_data.data[0].signature, att_data.data[0].signatureLen);

    sss_asymmetric_context_free(&verify_ctx);

    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    /* doc:end:read-w-attestation */

    if (0 != memcmp(obj, data, objByteLen)) {
        status = kStatus_SSS_Fail;
        LOG_E("Set data and retrieved are not same!!!");
        goto cleanup;
    }

    /* Only look at first part of attested data
     * object-type-dependend further parts contain same policy data */
    LOG_MAU8_D("Key att content", obj, objByteLen);
    LOG_MAU8_I("Key att data", (uint8_t *)att_data.data[datai].attribute, att_data.data[datai].attributeLen);

    att      = (uint8_t *)att_data.data[datai].attribute;
    attr_Len = att_data.data[datai].attributeLen;

    attrib.object_id =
        (uint32_t)att[attr_Cnt] << 24 | att[attr_Cnt + 1] << 16 | att[attr_Cnt + 2] << 8 | att[attr_Cnt + 3] << 0;
    attr_Cnt += 4;
    attrib.object_type = (SE05x_SecObjTyp_t)att[attr_Cnt++];
    attrib.auth_attr   = (SE05x_SetIndicator_t)att[attr_Cnt++];

    /*Verify the Object ID*/
    if (attrib.object_id == OBJECT_KEY_ID) {
        LOG_I("Object Id 0x%04X", attrib.object_id);
    }
    else {
        status = kStatus_SSS_Fail;
        LOG_E("Set Object Id and retrieved are not same!!!");
        goto cleanup;
    }

    /*Verify the Object Type*/
    if (attrib.object_type == obj_Binary) {
        LOG_I("Object Type  0x%X", attrib.object_type);
        /* Log object type */
        log_attribute_type(attrib.object_type);
    }
    else {
        status = kStatus_SSS_Fail;
        LOG_E("Set Object Type and retrieved are not same!!!");
        goto cleanup;
    }

    LOG_I("Object Auth Attribute  0x%X", attrib.auth_attr);
    /* Log Object Auth Attribute */
    log_attribute_auth(attrib.auth_attr);

    i = AUTHENTICATION_OBJ_ATTR_POLICYLEN_OFFSET;
    //attr_policyLen = att[i];

    /* Check for existing policies and loop over them to log */
    while (att[i] >= 4) {
        uint8_t ar_length = att[i++];
        if ((ar_length < 4) | (ar_length > 40)) {
            LOG_E("Access rule header invalid length 0X%02X", ar_length);
        }

        auth_obj = (uint32_t)att[i] << 24 | att[i + 1] << 16 | att[i + 2] << 8 | att[i + 3];
        LOG_I("Auth Object:");
        if (auth_obj == 0) {
            LOG_I("\tNo authentication required");
        }
        else {
            LOG_I("\tAuthentication required");
            LOG_I("\t0x%08X", auth_obj);
        }

        i += 4;

        uint32_t ar_header = (uint32_t)att[i] << 24 | att[i + 1] << 16 | att[i + 2] << 8 | att[i + 3];
        i += 4;

        /* Log Access Rules (Policies) associated with the object */
        log_attribute_access_rule(ar_header);
        if (ar_header == applied_policy) {
            LOG_I("Applied Policies and retrieved policies for the object are same!!!");
        }
        else {
            status = kStatus_SSS_Fail;
            LOG_E("Applied Policies and retrieved policies for the object are not same!!!");
            goto cleanup;
        }

        /* Print AR extension for POLICY_OBJ_REQUIRE_PCR_VALUE */
        if (ar_length > 4) {
            if (ar_header & POLICY_OBJ_REQUIRE_PCR_VALUE) {
                LOG_MAU8_I("AR Extension: ", att + i + 4, ar_length - 4);
                i += ar_length;
            }
        }
    }

    /* Parse origin flag */
    attrib.object_origin = (SE05x_Origin_t)att[i++];

    if (i == attr_Len) { /*Data is retrieved for Se050*/
        attrib.attr.authObjAttr.auth_attempts_cntr = (uint16_t)att[attr_Cnt] << 8 | att[attr_Cnt + 1];
        attr_Cnt += 2;
        attrib.auth_obj_id_owner =
            (uint32_t)att[attr_Cnt] << 24 | att[attr_Cnt + 1] << 16 | att[attr_Cnt + 2] << 8 | att[attr_Cnt + 3] << 0;
        attr_Cnt += 4;
        attrib.attr.authObjAttr.max_auth_attempts_cntr = (uint16_t)att[attr_Cnt] << 8 | att[attr_Cnt + 1];
        attr_Cnt += 2;
        if (attr_Cnt == AUTHENTICATION_OBJ_ATTR_POLICYLEN_OFFSET) {
            //origin needs to be filled and printed
            log_attribute_origin(attrib.object_origin);
            status = kStatus_SSS_Success;
        }
    }
    else {
        attrib.object_version = att[i] << 24 | att[i + 1] << 16 | att[i + 2] << 8 | att[i + 3];
        i += KEYOBJ_VERSION_LENGTH;
        if (i == attr_Len) { /*Data is retrieved for Se051*/
            if (attrib.auth_attr == kSE05x_SetIndicator_NOT_SET || attrib.auth_attr == kSE05x_SetIndicator_SET) {
                if (attrib.auth_attr == kSE05x_SetIndicator_NOT_SET) {
                    attrib.attr.nonAuthObjAttr.min_tagLen_for_AEAD = (uint16_t)att[attr_Cnt] << 8 | att[attr_Cnt + 1];
                    attr_Cnt += 2;
                    attrib.auth_obj_id_owner = (uint32_t)att[attr_Cnt] << 24 | att[attr_Cnt + 1] << 16 |
                                               att[attr_Cnt + 2] << 8 | att[attr_Cnt + 3] << 0;
                    attr_Cnt += 4;
                    attrib.attr.nonAuthObjAttr.rfu = (uint16_t)att[attr_Cnt] << 8 | att[attr_Cnt + 1];

                    /* Log min tagLen for AEAD obj*/
                    LOG_I("tagLen for AEAD:0x%02X", attrib.attr.nonAuthObjAttr.min_tagLen_for_AEAD);
                    /* Log RFU bytes*/
                    LOG_I("RFU bytes:0x%02X", attrib.attr.nonAuthObjAttr.rfu);
                }
                else if (attrib.auth_attr == kSE05x_SetIndicator_SET) {
                    attrib.attr.authObjAttr.auth_attempts_cntr = (uint16_t)att[attr_Cnt] << 8 | att[attr_Cnt + 1];
                    attr_Cnt += 2;
                    attrib.auth_obj_id_owner = (uint32_t)att[attr_Cnt] << 24 | att[attr_Cnt + 1] << 16 |
                                               att[attr_Cnt + 2] << 8 | att[attr_Cnt + 3] << 0;
                    attr_Cnt += 4;
                    attrib.attr.authObjAttr.max_auth_attempts_cntr = (uint16_t)att[attr_Cnt] << 8 | att[attr_Cnt + 1];
                    /* Log Auth attempts cntr*/
                    LOG_I("Auth attempts cntr:0x%02X", attrib.attr.authObjAttr.auth_attempts_cntr);
                    /* Log Max auth attempts cntr*/
                    LOG_I("Max auth attempts cntr:0x%02X", attrib.attr.authObjAttr.max_auth_attempts_cntr);
                }
                attr_Cnt += 2;
                if (attr_Cnt == AUTHENTICATION_OBJ_ATTR_POLICYLEN_OFFSET) {
                    /* Log object id owner*/
                    LOG_I("Owner:0x%04X", attrib.auth_obj_id_owner);
                    /* Log object origin*/
                    LOG_I("Object origin : 0x%X", attrib.object_origin);
                    log_attribute_origin(attrib.object_origin);
                    /* Log object version*/
                    LOG_I("Object Version : 0x%04X", attrib.object_version);
                    status = kStatus_SSS_Success;
                }
            }
            else {
                status = kStatus_SSS_Fail;
            }
        }
        else {
            status = kStatus_SSS_Fail;
        }
    }
#if !(SSS_HAVE_SE05X_VER_GTE_07_02)
    status = check_for_reliable_attestation(pCtx, applied_policy, attrib, lengthTag1Tag2);
#endif

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_ReadWithAttestation Example Success !!!");
    }
    else {
        LOG_E("se05x_ReadWithAttestation Example Failed !!!");
    }

    clean_attestated_object(pCtx, OBJECT_KEY_ID);
    sss_key_object_free(&verification_object);
    sss_key_object_free(&sss_attestation_object);
    return status;
}

#if !(SSS_HAVE_SE05X_VER_GTE_07_02)
static sss_status_t check_for_reliable_attestation(
    ex_sss_boot_ctx_t *pCtx, uint32_t objPolicies, ObjAttr_t Obj_attr, size_t LengthTag1Tag2)
{
    sss_status_t status           = kStatus_SSS_Fail;
    smStatus_t sm_status          = SM_NOT_OK;
    uint16_t key_size_bytes       = 0;
    uint16_t key_size_bits        = 0;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;

    if (objPolicies & POLICY_OBJ_REQUIRE_PCR_VALUE) {
        LOG_W("\t PCR policy MUST NOT be present on the attested object");
        goto exit;
    }
    if ((Obj_attr.object_origin == kSE05x_Origin_INTERNAL) &&
        ((Obj_attr.object_type >= kSE05x_SecObjTyp_RSA_KEY_PAIR) |
            (Obj_attr.object_type <= kSE05x_SecObjTyp_RSA_PUB_KEY))) {
        sm_status = Se05x_API_ReadSize(&pSession->s_ctx, Obj_attr.object_id, &key_size_bytes);
        if (sm_status != SM_OK) {
            LOG_E("Se05x_API_ReadSize failed while checking reliable attestation!!!");
            return kStatus_SSS_Fail;
        }
        key_size_bits = key_size_bytes * 8;
        if ((key_size_bits * 8 == 1024) | (key_size_bits * 8 == 1152) | (key_size_bits * 8 == 2048)) {
            LOG_W(" RSA keys  size 1024, 1152 or 2048 MUST NOT have the Origin INTERNAL");
            goto exit;
        }
    }

    /* For SE050*/
    if ((Obj_attr.object_origin == kSE05x_Origin_EXTERNAL) && (LengthTag1Tag2 > 59)) {
        LOG_W(
            "Secure Objects with Origin EXTERNAL and a length of \
                   TAG41 and TAG42 MUST NOT be longer than 59 byte");
        goto exit;
    }
    status = kStatus_SSS_Success;

exit:
    if (status == kStatus_SSS_Fail) {
        LOG_E("Attestation performed is not reliable!!!");
    }
    return status;
}

#endif //#if !(SSS_HAVE_SE05X_VER_GTE_07_02)

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
    return status;
}

static sss_status_t create_object_to_attest(ex_sss_boot_ctx_t *pCtx, uint32_t *applied_policy)
{
    sss_status_t status           = kStatus_SSS_Fail;
    sss_object_t object_to_attest = {0};
    sss_key_part_t key_part       = kSSS_KeyPart_Default;
    sss_cipher_type_t cipherType  = kSSS_CipherType_Binary;
    uint8_t data[]                = OBJECT_TO_ATTEST;
    size_t dataLen                = sizeof(data);
    uint32_t keyId                = OBJECT_KEY_ID;

#if SSS_HAVE_SE05X_VER_GTE_07_02
    const sss_policy_u common       = {.type = KPolicy_Common,
        .auth_obj_id                   = EX_LOCAL_OBJ_AUTH_ID,
        .policy                        = {.common = {
                       .can_Delete = 1,
                       .can_Write  = 1,
                       .can_Read   = 1,
                   }}};
    *applied_policy                 = *applied_policy | POLICY_OBJ_ALLOW_DELETE;
    *applied_policy                 = *applied_policy | POLICY_OBJ_ALLOW_READ;
    *applied_policy                 = *applied_policy | POLICY_OBJ_ALLOW_WRITE;
    sss_policy_t policy_for_bin_obj = {.nPolicies = 1, .policies = {&common}};

#else
    const sss_policy_u obj_pol = {.type = KPolicy_File,
        .auth_obj_id                    = EX_LOCAL_OBJ_AUTH_ID,
        .policy                         = {.file = {
                       .can_Write = 1,
                       .can_Read  = 1,
                   }}};
    *applied_policy            = *applied_policy | POLICY_OBJ_ALLOW_READ;
    *applied_policy            = *applied_policy | POLICY_OBJ_ALLOW_WRITE;

    const sss_policy_u common       = {.type = KPolicy_Common,
        .auth_obj_id                   = EX_LOCAL_OBJ_AUTH_ID,
        .policy                        = {.common = {
                       .can_Delete = 1,
                   }}};
    *applied_policy                 = *applied_policy | POLICY_OBJ_ALLOW_DELETE;
    sss_policy_t policy_for_bin_obj = {.nPolicies = 2, .policies = {&obj_pol, &common}};
#endif
    status = sss_key_object_init(&object_to_attest, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &object_to_attest, keyId, key_part, cipherType, dataLen, kKeyObject_Mode_Persistent);

    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(
        &pCtx->ks, &object_to_attest, data, dataLen, dataLen * 8, &policy_for_bin_obj, sizeof(policy_for_bin_obj));

cleanup:
    return status;
}

static void log_attribute_type(const SE05x_SecObjTyp_t type)
{
    LOG_I("Type:");
    switch (type) {
    case kSE05x_SecObjTyp_EC_KEY_PAIR:
        LOG_I("\tEC_KEY_PAIR");
        break;
    case kSE05x_SecObjTyp_EC_PRIV_KEY:
        LOG_I("\tEC_PRIV_KEY");
        break;
    case kSE05x_SecObjTyp_EC_PUB_KEY:
        LOG_I("\tEC_PUB_KEY");
        break;
    case kSE05x_SecObjTyp_RSA_KEY_PAIR:
        LOG_I("\tRSA_KEY_PAIR");
        break;
    case kSE05x_SecObjTyp_RSA_KEY_PAIR_CRT:
        LOG_I("\tRSA_KEY_PAIR_CRT");
        break;
    case kSE05x_SecObjTyp_RSA_PRIV_KEY:
        LOG_I("\tRSA_PRIV_KEY");
        break;
    case kSE05x_SecObjTyp_RSA_PRIV_KEY_CRT:
        LOG_I("\tRSA_PRIV_KEY_CRT");
        break;
    case kSE05x_SecObjTyp_RSA_PUB_KEY:
        LOG_I("\tRSA_PUB_KEY");
        break;
    case kSE05x_SecObjTyp_AES_KEY:
        LOG_I("\tAES_KEY");
        break;
    case kSE05x_SecObjTyp_DES_KEY:
        LOG_I("\tDES_KEY");
        break;
    case kSE05x_SecObjTyp_BINARY_FILE:
        LOG_I("\tBINARY_FILE");
        break;
    case kSE05x_SecObjTyp_UserID:
        LOG_I("\tUserID");
        break;
    case kSE05x_SecObjTyp_COUNTER:
        LOG_I("\tCOUNTER");
        break;
    case kSE05x_SecObjTyp_PCR:
        LOG_I("\tPCR_KEY_PAIR");
        break;
    case kSE05x_SecObjTyp_CURVE:
        LOG_I("\tCURVE");
        break;
    case kSE05x_SecObjTyp_HMAC_KEY:
        LOG_I("\tHMAC_KEY");
        break;
    default:
        LOG_E("Unknown secure object type\n");
    }
}

static void log_attribute_auth(const SE05x_SetIndicator_t auth)
{
    LOG_I("Auth:");
    switch (auth) {
    case kSE05x_SetIndicator_NOT_SET:
        LOG_I("\tNot Set");
        break;
    case kSE05x_SetIndicator_SET:
        LOG_I("\tSet");
        break;
    default:
        LOG_E("not allwed set indicator in object attribute\n");
    }
}

static void log_attribute_origin(const SE05x_Origin_t origin)
{
    LOG_I("Origin:");
    switch (origin) {
    case kSE05x_Origin_INTERNAL:
        LOG_I("\tINTERNAL");
        break;
    case kSE05x_Origin_EXTERNAL:
        LOG_I("\tEXTERNAL");
        break;
    case kSE05x_Origin_PROVISIONED:
        LOG_I("\tPROVISIONED");
        break;
    case kSE05x_Origin_NA:
    default:
        LOG_E("\tORIGIN INVALID");
    }
}

static void log_attribute_access_rule(uint32_t ar_header)
{
    LOG_I("Policies:");
    if (ar_header & POLICY_OBJ_FORBID_ALL) {
        LOG_I("\tPOLICY_OBJ_FORBID_ALL");
    };
    if (ar_header & POLICY_OBJ_ALLOW_SIGN) {
        LOG_I("\t POLICY_OBJ_ALLOW_SIGN");
    };
    if (ar_header & POLICY_OBJ_ALLOW_VERIFY) {
        LOG_I("\tPOLICY_OBJ_ALLOW_VERIFY");
    };
    if (ar_header & POLICY_OBJ_ALLOW_KA) {
        LOG_I("\tPOLICY_OBJ_ALLOW_KA");
    };
    if (ar_header & POLICY_OBJ_ALLOW_ENC) {
        LOG_I("\tPOLICY_OBJ_ALLOW_ENC");
    };
    if (ar_header & POLICY_OBJ_ALLOW_DEC) {
        LOG_I("\tPOLICY_OBJ_ALLOW_DEC");
    };
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    if (ar_header & POLICY_OBJ_ALLOW_KDF) {
        LOG_I("\tPOLICY_OBJ_ALLOW_KDF");
    };
#endif
    if (ar_header & POLICY_OBJ_ALLOW_WRAP) {
        LOG_I("\tPOLICY_OBJ_ALLOW_WRAP");
    };
    if (ar_header & POLICY_OBJ_ALLOW_READ) {
        LOG_I("\tPOLICY_OBJ_ALLOW_READ");
    };
    if (ar_header & POLICY_OBJ_ALLOW_WRITE) {
        LOG_I("\tPOLICY_OBJ_ALLOW_WRITE");
    };
    if (ar_header & POLICY_OBJ_ALLOW_GEN) {
        LOG_I("\tPOLICY_OBJ_ALLOW_GEN");
    };
    if (ar_header & POLICY_OBJ_ALLOW_DELETE) {
        LOG_I("\tPOLICY_OBJ_ALLOW_DELETE");
    };
    if (ar_header & POLICY_OBJ_REQUIRE_SM) {
        LOG_I("\tPOLICY_OBJ_REQUIRE_SM");
    };
    if (ar_header & POLICY_OBJ_REQUIRE_PCR_VALUE) {
        LOG_I("\tPOLICY_OBJ_REQUIRE_PCR_VALUE");
    };
    if (ar_header & POLICY_OBJ_ALLOW_ATTESTATION) {
        LOG_I("\tPOLICY_OBJ_ALLOW_ATTESTATION");
    };
    if (ar_header & POLICY_OBJ_ALLOW_DESFIRE_AUTHENTICATION) {
        LOG_I("\tPOLICY_OBJ_ALLOW_DESFIRE_AUTHENTICATION");
    };
    if (ar_header & POLICY_OBJ_ALLOW_DESFIRE_DUMP_SESSION_KEYS) {
        LOG_I("\tPOLICY_OBJ_ALLOW_DESFIRE_DUMP_SESSION_KEYS");
    };
    if (ar_header & POLICY_OBJ_ALLOW_IMPORT_EXPORT) {
        LOG_I("\tPOLICY_OBJ_ALLOW_IMPORT_EXPORT");
    };
#if SSS_HAVE_SE05X_VER_GTE_07_02
    if (ar_header & POLICY_OBJ_FORBID_DERIVED_OUTPUT) {
        LOG_I("\tPOLICY_OBJ_FORBID_DERIVED_OUTPUT");
    };
    if (ar_header & POLICY_OBJ_ALLOW_KDF_EXT_RANDOM) {
        LOG_I("\tPOLICY_OBJ_ALLOW_KDF_EXT_RANDOM");
    };
#endif
#if SSS_HAVE_SE05X_VER_GTE_07_02
    if (ar_header & POLICY_OBJ_ALLOW_TLS_KDF) {
        LOG_I("\t POLICY_OBJ_ALLOW_TLS_KDF");
    };
    if (ar_header & POLICY_OBJ_ALLOW_TLS_PMS) {
        LOG_I("\t POLICY_OBJ_ALLOW_TLS_PMS");
    };
    if (ar_header & POLICY_OBJ_ALLOW_HKDF) {
        LOG_I("\t POLICY_OBJ_ALLOW_HKDF");
    };
    if (ar_header & POLICY_OBJ_ALLOW_DESFIRE_CHANGEKEY) {
        LOG_I("\t POLICY_OBJ_ALLOW_DESFIRE_CHANGEKEY");
    };
    if (ar_header & POLICY_OBJ_ALLOW_DERIVED_INPUT) {
        LOG_I("\t POLICY_OBJ_ALLOW_DERIVED_INPUT");
    };
    if (ar_header & POLICY_OBJ_ALLOW_PBKDF) {
        LOG_I("\t POLICY_OBJ_ALLOW_PBKDF");
    };
    if (ar_header & POLICY_OBJ_ALLOW_DESFIRE_KDF) {
        LOG_I("\t POLICY_OBJ_ALLOW_DESFIRE_KDF");
    };
    if (ar_header & POLICY_OBJ_FORBID_EXTERNAL_IV) {
        LOG_I("\t POLICY_OBJ_FORBID_EXTERNAL_IV");
    };
    if (ar_header & POLICY_OBJ_ALLOW_USAGE_AS_HMAC_PEPPER) {
        LOG_I("\t POLICY_OBJ_ALLOW_USAGE_AS_HMAC_PEPPER");
    };
#endif
}

static void clean_attestated_object(ex_sss_boot_ctx_t *pCtx, uint32_t keyid_to_attest)
{
    sss_status_t status           = kStatus_SSS_Fail;
    sss_object_t object_to_delete = {0};
    status                        = sss_key_object_init(&object_to_delete, &pCtx->ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    /* Delete object to attest */
    status = sss_key_object_get_handle(&object_to_delete, keyid_to_attest);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_store_erase_key(&pCtx->ks, &object_to_delete);

exit:
    return;
}

/* doc:start:read-large-binary-obj-w-attestation */
sss_status_t read_large_object_with_attestation(sss_se05x_key_store_t *keyStore,
    sss_se05x_object_t *keyObject,
    uint8_t *key,
    size_t *keylen,
    size_t *pKeyBitLen,
    sss_algorithm_t algorithm_attst,
    uint8_t *random_attst,
    size_t randomLen_attst,
    sss_se05x_attst_data_t *attst_data,
    sss_object_t *verification_object)
{
    AX_UNUSED_ARG(pKeyBitLen);
    AX_UNUSED_ARG(algorithm_attst);
    smStatus_t status                  = SM_NOT_OK;
    sss_status_t sss_status            = kStatus_SSS_Fail;
    uint16_t rem_data                  = 0;
    uint16_t offset                    = 0;
    uint16_t size                      = 0;
    size_t max_buffer                  = 0;
    size_t signatureLen                = 0;
    uint32_t attestID                  = ATTESTATION_KEY_ID;
    SE05x_AttestationAlgo_t attestAlgo = kSE05x_AttestationAlgo_EC_SHA_256;

    /* Variables for verification */
    uint8_t plainData[2500] = {0};
    size_t plainDataLen     = sizeof(plainData);
    uint8_t digest[64]      = {0};
    size_t digestLen        = sizeof(digest);
    sss_digest_t digest_ctx;
    sss_algorithm_t algorithm        = kAlgorithm_SSS_ECDSA_SHA256;
    sss_algorithm_t digest_algorithm = kAlgorithm_SSS_SHA256;
    sss_asymmetric_t verify_ctx;
#if SSS_HAVE_SE05X_VER_GTE_07_02
    uint8_t *pData        = &plainData[0];
    size_t buffLen        = sizeof(plainData);
    uint8_t cmdHashed[32] = {0};
    size_t cmdHashedLen   = sizeof(cmdHashed);
    int tlvRet            = 0;
    uint8_t timestamp[32] = {0};
#endif

    status = Se05x_API_ReadSize(&keyStore->session->s_ctx, keyObject->keyId, &size);
    ENSURE_OR_GO_CLEANUP(status == SM_OK);

    if (*keylen < size) {
        LOG_E("Insufficient buffer ");
        goto cleanup;
    }

    rem_data = size;
    *keylen  = size;
    while (rem_data > 0) {
        uint16_t chunk = (rem_data > BINARY_WRITE_MAX_LEN) ? BINARY_WRITE_MAX_LEN : rem_data;
        rem_data       = rem_data - chunk;
        max_buffer     = chunk;

        signatureLen                     = attst_data->data[0].signatureLen;
        attst_data->data[0].timeStampLen = sizeof(SE05x_TimeStamp_t);
#if !SSS_HAVE_SE05X_VER_GTE_07_02
        status = Se05x_API_ReadObject_W_Attst(&keyStore->session->s_ctx,
            keyObject->keyId,
            offset,
            chunk,
            attestID,
            attestAlgo,
            random_attst,
            randomLen_attst,
            (key + offset),
            &max_buffer,
            attst_data->data[0].attribute,
            &(attst_data->data[0].attributeLen),
            &(attst_data->data[0].timeStamp),
            attst_data->data[0].outrandom,
            &(attst_data->data[0].outrandomLen),
            attst_data->data[0].chipId,
            &(attst_data->data[0].chipIdLen),
            attst_data->data[0].signature,
            &signatureLen);
#else

        attst_data->data[0].cmdLen       = sizeof(attst_data->data[0].cmd);
        attst_data->data[0].objSizeLen   = sizeof(attst_data->data[0].objSize);
        attst_data->data[0].attributeLen = sizeof(attst_data->data[0].attribute);
        attst_data->data[0].chipIdLen    = sizeof(attst_data->data[0].chipId);
        pData                            = &plainData[0];
        status                           = Se05x_API_ReadObject_W_Attst_V2(&keyStore->session->s_ctx,
            keyObject->keyId,
            offset,
            chunk,
            attestID,
            attestAlgo,
            random_attst,
            randomLen_attst,
            (key + offset),
            &max_buffer,
            attst_data->data[0].attribute,
            &(attst_data->data[0].attributeLen),
            &(attst_data->data[0].timeStamp),
            attst_data->data[0].chipId,
            &(attst_data->data[0].chipIdLen),
            attst_data->data[0].cmd,
            &(attst_data->data[0].cmdLen),
            attst_data->data[0].objSize,
            &(attst_data->data[0].objSizeLen),
            attst_data->data[0].signature,
            &signatureLen);
#endif
        if (attst_data->data[0].signatureLen < signatureLen) {
            sss_status = kStatus_SSS_Fail;
            goto cleanup;
        }
        attst_data->data[0].signatureLen -= signatureLen;
        attst_data->valid_number = 1;

        ENSURE_OR_GO_CLEANUP(status == SM_OK);
        //#if !SSS_HAVE_SE05X_VER_GTE_07_02
        /* Perform verification operation here on the following data
         *      (key + offset) +
         *      attst_data->data[0].attribute +
         *      attst_data->data[0].timestamp +
         *      attst_data->data[0].outrandom +
         *      attst_data->data[0].chipId
         * with signature
         *      attst_data->data[0].signature
         *
         * We perform signature verification on host.
         * First we digest the data then pass it to verify API
         */

        memcpy(plainData, (key + offset), max_buffer);
        memcpy(plainData + max_buffer, attst_data->data[0].attribute, attst_data->data[0].attributeLen);
        memcpy(plainData + max_buffer + attst_data->data[0].attributeLen,
            &(attst_data->data[0].timeStamp),
            attst_data->data[0].timeStampLen);
#if !SSS_HAVE_SE05X_VER_GTE_07_02
        memcpy(plainData + max_buffer + attst_data->data[0].attributeLen + attst_data->data[0].timeStampLen,
            attst_data->data[0].outrandom,
            attst_data->data[0].outrandomLen);
        memcpy(plainData + max_buffer + attst_data->data[0].attributeLen + attst_data->data[0].timeStampLen +
                   attst_data->data[0].outrandomLen,
            attst_data->data[0].chipId,
            attst_data->data[0].chipIdLen);
        plainDataLen = max_buffer + attst_data->data[0].attributeLen + attst_data->data[0].timeStampLen +
                       attst_data->data[0].outrandomLen + attst_data->data[0].chipIdLen;
#else
        /* Perform verification operation here on the following data
        *      Perform hash on capdu +
        *      Tag(0x41) + Length + data +
        *      Tag(0x42) + Length +att_data.data[0].chipId +
        *      Tag(0x43) + Length +att_data.data[0].attribute +
        *      Tag(0x44) + Length +dataLen +
        *      Tag(0x4F) + Length +att_data.data[0].timestamp
        * We perform signature verification on host.
        * First we digest the data then pass it to verify API with recv signature
        */

        sss_status = sss_digest_context_init(
            &digest_ctx, verification_object->keyStore->session, digest_algorithm, kMode_SSS_Digest);
        ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

        LOG_MAU8_I("Cmd ", attst_data->data[0].cmd, attst_data->data[0].cmdLen);

        sss_status = sss_digest_one_go(
            &digest_ctx, attst_data->data[0].cmd, (attst_data->data[0].cmdLen), cmdHashed, &cmdHashedLen);
        ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

        LOG_MAU8_I("Cmd Hashed ", cmdHashed, cmdHashedLen);
        sss_digest_context_free(&digest_ctx);
        plainDataLen = 0;

        memcpy(pData, cmdHashed, cmdHashedLen);
        plainDataLen = plainDataLen + cmdHashedLen;
        pData        = pData + plainDataLen;

        tlvRet = add_taglength_to_data(&pData, &plainDataLen, buffLen, kSE05x_TAG_1, (key + offset), max_buffer, true);
        ENSURE_OR_GO_CLEANUP(tlvRet == 0);
        tlvRet = add_taglength_to_data(&pData,
            &plainDataLen,
            buffLen,
            kSE05x_TAG_2,
            attst_data->data[0].chipId,
            attst_data->data[0].chipIdLen,
            true);
        ENSURE_OR_GO_CLEANUP(tlvRet == 0);
        tlvRet = add_taglength_to_data(&pData,
            &plainDataLen,
            buffLen,
            kSE05x_TAG_3,
            attst_data->data[0].attribute,
            attst_data->data[0].attributeLen,
            true);
        ENSURE_OR_GO_CLEANUP(tlvRet == 0);
        tlvRet = add_taglength_to_data(&pData,
            &plainDataLen,
            buffLen,
            kSE05x_TAG_4,
            attst_data->data[0].objSize,
            attst_data->data[0].objSizeLen,
            true);
        ENSURE_OR_GO_CLEANUP(tlvRet == 0);

        memcpy(timestamp, &(attst_data->data[0].timeStamp), attst_data->data[0].timeStampLen);

        tlvRet = add_taglength_to_data(
            &pData, &plainDataLen, buffLen, kSE05x_TAG_TIMESTAMP, timestamp, attst_data->data[0].timeStampLen, true);
        ENSURE_OR_GO_CLEANUP(tlvRet == 0);

        LOG_MAU8_I("plainData ", plainData, plainDataLen);

#endif
        sss_status = sss_digest_context_init(
            &digest_ctx, verification_object->keyStore->session, digest_algorithm, kMode_SSS_Digest);
        ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

        sss_status = sss_digest_one_go(&digest_ctx, plainData, plainDataLen, digest, &digestLen);
        ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

        sss_digest_context_free(&digest_ctx);

        /* Verify signature */
        sss_status = sss_asymmetric_context_init(
            &verify_ctx, verification_object->keyStore->session, verification_object, algorithm, kMode_SSS_Verify);
        ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

        sss_status =
            sss_asymmetric_verify_digest(&verify_ctx, digest, digestLen, attst_data->data[0].signature, signatureLen);

        sss_asymmetric_context_free(&verify_ctx);

        ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

        offset = offset + chunk;
    }

cleanup:
    return sss_status;
}
/* doc:end:read-large-binary-obj-w-attestation */
