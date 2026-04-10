/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>
#include <string.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include "ex_sss_auth.h"

#if SSS_HAVE_APPLET_SE05X_IOT
static ex_sss_boot_ctx_t gex_sss_pcr_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_pcr_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>
#if (SSS_HAVE_SE05X_AUTH_USERID) || (SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03) //UserID Session
#define EX_LOCAL_OBJ_AUTH_ID EX_SSS_AUTH_SE05X_UserID_AUTH_ID
#elif (SSS_HAVE_SE05X_AUTH_NONE) || (SSS_HAVE_SE05X_AUTH_PLATFSCP03) //No auth
#define EX_LOCAL_OBJ_AUTH_ID EX_SSS_AUTH_SE05X_NONE_AUTH_ID
#elif (SSS_HAVE_SE05X_AUTH_AESKEY) || (SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03) //AESKey
#define EX_LOCAL_OBJ_AUTH_ID EX_SSS_AUTH_SE05X_APPLETSCP_AUTH_ID
#elif (SSS_HAVE_SE05X_AUTH_ECKEY) || (SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03) //ECKey session
#define EX_LOCAL_OBJ_AUTH_ID EX_SSS_AUTH_SE05X_ECKEY_ECDSA_AUTH_ID
#endif
#define ECC256R1_KEY_BIT_LENGTH 256

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status           = kStatus_SSS_Fail;
    smStatus_t retval             = SM_NOT_OK;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;

    sss_object_t ec_keyPair;
    sss_asymmetric_t asymm                     = {0};
    uint8_t digest[32]                         = "Hello World";
    size_t digestLen                           = sizeof(digest);
    uint8_t signature[ECC256R1_KEY_BIT_LENGTH] = {0};
    size_t signatureLen                        = sizeof(signature);

    sss_object_t pcr_object;
    uint8_t pcr_init_value[32]   = {0x12, 0xa1, 0x49, 0x82, 0x32};
    uint8_t pcr_update_value[]   = {0x12, 0xa1, 0x49, 0x82, 0x32};
    size_t pcr_init_value_size   = sizeof(pcr_init_value);
    size_t pcr_update_value_size = sizeof(pcr_update_value);

    uint32_t keyId = (0xEF000000u + __LINE__);
    size_t keylen  = ECC256R1_KEY_BIT_LENGTH / 8;

#if SSS_HAVE_SE05X_VER_GTE_07_02
    /* clang-format off */
    uint8_t pcr_expected_value[] = {
        0x87, 0xD3, 0xE3, 0x93, 0x19, 0x8F, 0x5C, 0x80, 0xE0, 0xBC, 0x9B, 0xC9, 0x82, 0x00, 0x1F, 0xB0, 0xEE, 0x20, 0x1C, 0x27, 0x0B, 0x6D, 0xC8, 0x84, 0x52, 0xE4, 0x13, 0xA3, 0x25, 0x56, 0x81, 0x75};
#else
    uint8_t pcr_expected_value[] = {
        0x89, 0x51, 0x56, 0x9f, 0x41, 0x5f, 0xeb, 0x4f, 0xb6, 0x37, 0x02, 0x86, 0xe7, 0xdd, 0xa0, 0x99, 0x33, 0x6c, 0x46, 0x36, 0xbc, 0xbb, 0x4c, 0x11, 0x04, 0x10, 0x0a, 0x86, 0x0d, 0x0c, 0xa4, 0x14};
    /* clang-format on */
#endif
    size_t pcr_expected_value_size = sizeof(pcr_expected_value);

    /* clang-format off */

    /* Policies for ecc key */
    const sss_policy_u key_withPol = {
        .type = KPolicy_Asym_Key,
        .auth_obj_id = EX_LOCAL_OBJ_AUTH_ID,
        .policy = {
        .asymmkey = {
        .can_Sign = 1,
        .can_Verify = 1,
        .can_Encrypt = 1,
        .can_Decrypt = 1,
        .can_KD = 1,
        .can_Wrap = 1,
        .can_Write = 1,
        .can_Gen = 1,
        .can_Import_Export = 1,
        .can_KA = 1,
        .can_Read = 1,
        .can_Attest = 1,
    }
    }
    };

    /* Common rules */
    const sss_policy_u common = {
        .type = KPolicy_Common,
        .auth_obj_id = EX_LOCAL_OBJ_AUTH_ID,
        .policy = {
        .common = {
        .req_Sm = 0,
        .can_Delete = 1,
        .forbid_All = 0,
    }
    }
    };

    sss_policy_u pcr = {
        .type = KPolicy_Common_PCR_Value,
        .auth_obj_id = EX_LOCAL_OBJ_AUTH_ID,
        .policy = {
        .common_pcr_value = {
        .pcrObjId = 0x7fffffff,
    }
    }
    };
    memset(pcr.policy.common_pcr_value.pcrExpectedValue,
        0x00,
        sizeof(pcr.policy.common_pcr_value.pcrExpectedValue));
    memcpy(pcr.policy.common_pcr_value.pcrExpectedValue,
        pcr_expected_value, pcr_expected_value_size);

    /* create policy set */
    sss_policy_t policy_for_ec_key = {
        .nPolicies = 3,
        .policies = { &key_withPol, &common,&pcr}
    };
    /* clang-format on */

    status = sss_key_object_init(&ec_keyPair, &pCtx->ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &ec_keyPair, keyId, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, keylen, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_store_generate_key(&pCtx->ks, &ec_keyPair, ECC256R1_KEY_BIT_LENGTH, &policy_for_ec_key);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_asymmetric_context_init(&asymm, &pCtx->session, &ec_keyPair, kAlgorithm_SSS_SHA256, kMode_SSS_Sign);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_asymmetric_sign_digest(&asymm, digest, digestLen, signature, &signatureLen);
    if (status == kStatus_SSS_Fail) {
        LOG_I("Sign failed due to PCR expected value mismatch!!!");
    }
    sss_asymmetric_context_free(&asymm);

    /* Create a PCR Object */

    status = sss_key_object_init(&pcr_object, &pCtx->ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(
        &pcr_object, 0x7fffffff, kSSS_KeyPart_Default, kSSS_CipherType_PCR, pcr_init_value_size, kKeyObject_Mode_None);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    /*
    *Inject PCR object and update value
    */
    retval = Se05x_API_WritePCR_WithType(
        &(pSession->s_ctx), kSE05x_INS_NA, NULL, 0x7fffffff, pcr_init_value, pcr_init_value_size, NULL, 0);
    ENSURE_OR_GO_EXIT(retval == SM_OK);
    retval = Se05x_API_WritePCR_WithType(
        &(pSession->s_ctx), kSE05x_INS_NA, NULL, 0x7fffffff, NULL, 0, pcr_update_value, pcr_update_value_size);
    ENSURE_OR_GO_EXIT(retval == SM_OK);
    status = sss_asymmetric_context_init(&asymm, &pCtx->session, &ec_keyPair, kAlgorithm_SSS_SHA256, kMode_SSS_Sign);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_asymmetric_sign_digest(&asymm, digest, digestLen, signature, &signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    sss_asymmetric_context_free(&asymm);

    status = sss_asymmetric_context_init(&asymm, &pCtx->session, &ec_keyPair, kAlgorithm_SSS_SHA256, kMode_SSS_Verify);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_asymmetric_verify_digest(&asymm, digest, digestLen, signature, signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_I("Sign & Verify is Success with Expected PCR value!!!");

    sss_asymmetric_context_free(&asymm);

    status = sss_key_store_erase_key(&pCtx->ks, &ec_keyPair);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_store_erase_key(&pCtx->ks, &pcr_object);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = kStatus_SSS_Success;
exit:
    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_PCR Example Success !!!...");
    }
    else {
        LOG_E("se05x_PCR Example Failed !!!...");
    }
    return status;
}
#endif //if SSS_HAVE_APPLET_SE05X_IOT
