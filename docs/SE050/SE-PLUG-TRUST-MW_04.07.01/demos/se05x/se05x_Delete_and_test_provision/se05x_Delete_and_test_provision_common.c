/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
/* Only for quick testing.... Not for production use ................. */
/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */

/* TO BE Run only under default session */

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>
#include <sm_types.h>
#include <string.h>

#include "ex_sss_auth.h"
#include "smCom.h"
#include "fsl_sss_se05x_policy.h"

void ReInitializeTestSample(ex_sss_boot_ctx_t *pCtx);
void AddAttestationKeys(ex_sss_boot_ctx_t *pCtx);

#define POLICY_BUF_LEN 9
#define POLICY_BUF_POLICY_LEN 8
#define POLICY_BUF_POLICY_OFFSET 5

/* clang-format off */
#define DELETE_ALL_UserID_VALUE                    \
    {                                           \
        'E', 'R', 'A', 'S', 'E', 'R'            \
    }

#define MandateSCP_UserID_VALUE                 \
    {                                           \
        'N', 'E', 'E', 'D', 'S', 'C', 'P'            \
    }

#define RESTRICT_AES_VALUE                     \
    {                                                \
       'R','E','S','T','R','I','C','T','S','E','C','O','B','J','S','E',    \
    }

#define kSE05x_AppletResID_0x7FFF0203 0x7FFF0203

#define RSA_ATTESTATION_KEY_ID 0xF0000010
#define ECC_ATTESTATION_KEY_ID 0xF0000012

/* clang-format ON */

void ReInitializeTestSample(ex_sss_boot_ctx_t *pCtx)
{
    smStatus_t status;
    SE05x_Result_t objExists = kSE05x_Result_NA;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    Se05xSession_t *pSe05xSession = &pSession->s_ctx;
    uint8_t hasSession_orig = pSe05xSession->hasSession;
    uint32_t delete_policy = POLICY_OBJ_ALLOW_DELETE;
    uint32_t read_delete_policy = POLICY_OBJ_ALLOW_DELETE | POLICY_OBJ_ALLOW_READ;
    uint8_t policy_buf[POLICY_BUF_LEN] = {0};
    Se05xPolicy_t policy_for_auth_obj = {0};
    policy_buf[0] = POLICY_BUF_POLICY_LEN;
    policy_buf[POLICY_BUF_POLICY_OFFSET]   = (uint8_t)((delete_policy & 0xFF000000) >> (8 * 3));
    policy_buf[POLICY_BUF_POLICY_OFFSET+1] = (uint8_t)((delete_policy & 0x00FF0000) >> (8 * 2));
    policy_buf[POLICY_BUF_POLICY_OFFSET+2] = (uint8_t)((delete_policy & 0x0000FF00) >> (8 * 1));
    policy_buf[POLICY_BUF_POLICY_OFFSET+3] = (uint8_t)((delete_policy & 0x000000FF) >> (8 * 0));
    policy_for_auth_obj.value = policy_buf;
    policy_for_auth_obj.value_len = POLICY_BUF_LEN;

    const uint8_t ECKey_SE_PublicEcdsakey[] = {
        0x04, 0x3C, 0x9E, 0x47, 0xED, 0xF0, 0x51, 0xA3,
        0x58, 0x9F, 0x67, 0x30, 0x2D, 0x22, 0x56, 0x7C,
        0x2E, 0x17, 0x22, 0x9E, 0x88, 0x83, 0x33, 0x8E,
        0xC3, 0xB7, 0xD5, 0x27, 0xF9, 0xEE, 0x71, 0xD0,
        0xA8, 0x1A, 0xAE, 0x7F, 0xE2, 0x1C, 0xAA, 0x66,
        0x77, 0x78, 0x3A, 0xA8, 0x8D, 0xA6, 0xD6, 0xA8,
        0xAD, 0x5E, 0xC5, 0x3B, 0x10, 0xBC, 0x0B, 0x11,
        0x09, 0x44, 0x82, 0xF0, 0x4D, 0x24, 0xB5, 0xBE,
        0xC4 };

    const uint8_t ECKey_SE_PublicEcdsakey2[] = {

        0x04, 0x0d, 0x0e, 0x03, 0xdd, 0x40, 0x1e, 0x77,
        0xff, 0xab, 0xa8, 0xb5, 0x79, 0xdb, 0x8a, 0xf4,
        0x09, 0x7b, 0x59, 0x4e, 0xe8, 0xa0, 0xb8, 0x1c,
        0xeb, 0xa8, 0x53, 0x96, 0xc6, 0x13, 0x96, 0x56,
        0x13, 0x5e, 0x68, 0x75, 0xb9, 0xe9, 0x79, 0x29,
        0x28, 0x8c, 0x7d, 0xa1, 0xf2, 0x78, 0x7b, 0x66,
        0x86, 0xcc, 0x9e, 0x6b, 0xf6, 0x03, 0xc2, 0xfe,
        0x59, 0x1b, 0xab, 0x4a, 0x40, 0x24, 0x70, 0xe4,
        0x8b };

#if SSSFTR_SE05X_ECC
    status = Se05x_API_CreateCurve_prime256v1(pSe05xSession, kSE05x_ECCurve_NIST_P256);
    LOG_I("Se05x_API_CreateCurve_prime256v1 status = %04X", status);
#endif

    /* clang-format on */

    const uint8_t userid1_value[]             = EX_SSS_AUTH_SE05X_UserID_VALUE;
    const uint8_t userid2_value[]             = EX_SSS_AUTH_SE05X_UserID_VALUE2;
    const uint8_t userid_value_factoryreset[] = DELETE_ALL_UserID_VALUE;
    const uint8_t userid_value_mandatescp[]   = MandateSCP_UserID_VALUE;
    const uint8_t restrict_value[]            = RESTRICT_AES_VALUE;
    const uint8_t aes_value1[]                = EX_SSS_AUTH_SE05X_APPLETSCP_VALUE;
    const uint8_t aes_value2[]                = EX_SSS_AUTH_SE05X_APPLETSCP_VALUE2;

    status = Se05x_API_CheckObjectExists(pSe05xSession, kSE05x_AppletResID_FACTORY_RESET, &objExists);
    if (status == SM_OK && objExists == kSE05x_Result_SUCCESS) {
        LOG_W("kSE05x_AppletResID_FACTORY_RESET Object already exists");
    }
    else if (status == SM_OK && objExists == kSE05x_Result_FAILURE) {
        status = Se05x_API_WriteUserID(pSe05xSession,
            (Se05xPolicy_t *)&policy_for_auth_obj,
            SE05x_MaxAttemps_UNLIMITED,
            kSE05x_AppletResID_FACTORY_RESET,
            userid_value_factoryreset,
            sizeof(userid_value_factoryreset),
            kSE05x_AttestationType_AUTH);
        LOG_I("kSE05x_AppletResID_FACTORY_RESET status = %04X", status);
    }

    status = Se05x_API_CheckObjectExists(pSe05xSession, kSE05x_AppletResID_PLATFORM_SCP, &objExists);
    if (status == SM_OK && objExists == kSE05x_Result_SUCCESS) {
        LOG_W("kSE05x_AppletResID_PLATFORM_SCP Object already exists");
    }
    else if (status == SM_OK && objExists == kSE05x_Result_FAILURE) {
        status = Se05x_API_WriteUserID(pSe05xSession,
            (Se05xPolicy_t *)&policy_for_auth_obj,
            SE05x_MaxAttemps_NA,
            kSE05x_AppletResID_PLATFORM_SCP,
            userid_value_mandatescp,
            sizeof(userid_value_mandatescp),
            kSE05x_AttestationType_AUTH);
        LOG_I("kSE05x_AppletResID_PLATFORM_SCP status = %04X", status);
    }

    status = Se05x_API_CheckObjectExists(pSe05xSession, kEX_SSS_ObjID_UserID_Auth, &objExists);
    if (status == SM_OK && objExists == kSE05x_Result_SUCCESS) {
        LOG_W("kEX_SSS_ObjID_UserID_Auth Object already exists");
    }
    else if (status == SM_OK && objExists == kSE05x_Result_FAILURE) {
        status = Se05x_API_WriteUserID(pSe05xSession,
            (Se05xPolicy_t *)&policy_for_auth_obj,
            SE05x_MaxAttemps_UNLIMITED,
            kEX_SSS_ObjID_UserID_Auth,
            userid1_value,
            sizeof(userid1_value),
            kSE05x_AttestationType_AUTH);
        LOG_I("kEX_SSS_ObjID_UserID_Auth status = %04X", status);
    }
    status = Se05x_API_CheckObjectExists(pSe05xSession, kEX_SSS_ObjID_UserID_Auth + 0x10, &objExists);
    if (status == SM_OK && objExists == kSE05x_Result_SUCCESS) {
        LOG_W("kEX_SSS_ObjID_UserID_Auth Object already exists");
    }
    else if (status == SM_OK && objExists == kSE05x_Result_FAILURE) {
        status = Se05x_API_WriteUserID(pSe05xSession,
            (Se05xPolicy_t *)&policy_for_auth_obj,
            SE05x_MaxAttemps_UNLIMITED,
            kEX_SSS_ObjID_UserID_Auth + 0x10,
            userid2_value,
            sizeof(userid2_value),
            kSE05x_AttestationType_AUTH);
        LOG_I("kEX_SSS_ObjID_UserID_Auth + 0x10 status = %04X", status);
    }

    status = Se05x_API_CheckObjectExists(pSe05xSession, kSE05x_AppletResID_RESTRICT, &objExists);
    if (status == SM_OK && objExists == kSE05x_Result_SUCCESS) {
        LOG_W("kSE05x_AppletResID_RESTRICT Object already exists");
    }
    else if (status == SM_OK && objExists == kSE05x_Result_FAILURE) {
        status = Se05x_API_WriteSymmKey(pSe05xSession,
            (Se05xPolicy_t *)&policy_for_auth_obj,
            SE05x_MaxAttemps_UNLIMITED,
            kSE05x_AppletResID_RESTRICT,
            SE05x_KeyID_KEK_NONE,
            restrict_value,
            sizeof(restrict_value),
            (SE05x_INS_t)kSE05x_AttestationType_AUTH,
            kSE05x_SymmKeyType_AES);
        LOG_I("kSE05x_AppletResID_RESTRICT status = %04X", status);
    }

    status = Se05x_API_CheckObjectExists(pSe05xSession, kEX_SSS_ObjID_APPLETSCP03_Auth, &objExists);
    if (status == SM_OK && objExists == kSE05x_Result_SUCCESS) {
        LOG_W("kEX_SSS_ObjID_APPLETSCP03_Auth Object already exists");
    }
    else if (status == SM_OK && objExists == kSE05x_Result_FAILURE) {
        status = Se05x_API_WriteSymmKey(pSe05xSession,
            (Se05xPolicy_t *)&policy_for_auth_obj,
            SE05x_MaxAttemps_UNLIMITED,
            kEX_SSS_ObjID_APPLETSCP03_Auth,
            SE05x_KeyID_KEK_NONE,
            aes_value1,
            sizeof(aes_value1),
            (SE05x_INS_t)kSE05x_AttestationType_AUTH,
            kSE05x_SymmKeyType_AES);
        LOG_I("kEX_SSS_ObjID_APPLETSCP03_Auth status = %04X", status);
    }

    status = Se05x_API_CheckObjectExists(pSe05xSession, kEX_SSS_ObjID_APPLETSCP03_Auth + 0x10, &objExists);
    if (status == SM_OK && objExists == kSE05x_Result_SUCCESS) {
        LOG_W("kEX_SSS_ObjID_APPLETSCP03_Auth Object already exists");
    }
    else if (status == SM_OK && objExists == kSE05x_Result_FAILURE) {
        status = Se05x_API_WriteSymmKey(pSe05xSession,
            (Se05xPolicy_t *)&policy_for_auth_obj,
            SE05x_MaxAttemps_UNLIMITED,
            kEX_SSS_ObjID_APPLETSCP03_Auth + 0x10,
            SE05x_KeyID_KEK_NONE,
            aes_value2,
            sizeof(aes_value2),
            (SE05x_INS_t)kSE05x_AttestationType_AUTH,
            kSE05x_SymmKeyType_AES);
        LOG_I("kEX_SSS_ObjID_APPLETSCP03_Auth + 0x10 status = %04X", status);
    }
    /* Store FAST SCP Auth ECDSA Pubkey to SE */

    size_t publicKeyLen                      = sizeof(ECKey_SE_PublicEcdsakey);
    uint16_t attempt                         = SE05x_MaxAttemps_UNLIMITED;
    policy_buf[POLICY_BUF_POLICY_OFFSET]     = (uint8_t)((read_delete_policy & 0xFF000000) >> (8 * 3));
    policy_buf[POLICY_BUF_POLICY_OFFSET + 1] = (uint8_t)((read_delete_policy & 0x00FF0000) >> (8 * 2));
    policy_buf[POLICY_BUF_POLICY_OFFSET + 2] = (uint8_t)((read_delete_policy & 0x0000FF00) >> (8 * 1));
    policy_buf[POLICY_BUF_POLICY_OFFSET + 3] = (uint8_t)((read_delete_policy & 0x000000FF) >> (8 * 0));

    status = Se05x_API_CheckObjectExists(pSe05xSession, kEX_SSS_objID_ECKEY_Auth, &objExists);
    if (status == SM_OK && objExists == kSE05x_Result_SUCCESS) {
        LOG_W("kEX_SSS_objID_ECKEY_Auth Object already exists");
    }
    else if (status == SM_OK && objExists == kSE05x_Result_FAILURE) {
        status = Se05x_API_WriteECKey(pSe05xSession,
            (Se05xPolicy_t *)&policy_for_auth_obj,
            attempt,
            kEX_SSS_objID_ECKEY_Auth,
            kSE05x_ECCurve_NIST_P256,
            NULL,
            0,
            ECKey_SE_PublicEcdsakey,
            publicKeyLen,
            (SE05x_INS_t)kSE05x_AttestationType_AUTH,
            kSE05x_KeyPart_Public);
        LOG_I("kSE05x_ECCurve_NIST_P256 status = %04X", status);
    }
    status = Se05x_API_CheckObjectExists(pSe05xSession, kEX_SSS_objID_ECKEY_Auth + 0x10, &objExists);
    if (status == SM_OK && objExists == kSE05x_Result_SUCCESS) {
        LOG_W("kEX_SSS_objID_ECKEY_Auth Object already exists");
    }
    else if (status == SM_OK && objExists == kSE05x_Result_FAILURE) {
        status = Se05x_API_WriteECKey(pSe05xSession,
            (Se05xPolicy_t *)&policy_for_auth_obj,
            attempt,
            kEX_SSS_objID_ECKEY_Auth + 0x10,
            kSE05x_ECCurve_NIST_P256,
            NULL,
            0,
            ECKey_SE_PublicEcdsakey2,
            publicKeyLen,
            (SE05x_INS_t)kSE05x_AttestationType_AUTH,
            kSE05x_KeyPart_Public);
        LOG_I("kSE05x_ECCurve_NIST_P256 + 0x10 status = %04X", status);
    }

    pSe05xSession->hasSession = hasSession_orig;
}

void AddAttestationKeys(ex_sss_boot_ctx_t *pCtx)
{
    smStatus_t status;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    Se05xSession_t *pSe05xSession = &pSession->s_ctx;
    SE05x_Result_t objExists      = kSE05x_Result_NA;
    uint32_t ecdsa_policy         = POLICY_OBJ_ALLOW_DELETE | POLICY_OBJ_ALLOW_READ | POLICY_OBJ_ALLOW_ATTESTATION;
    uint8_t ecdsa_policy_buf[POLICY_BUF_LEN]       = {0};
    Se05xPolicy_t policy_for_auth_obj              = {0};
    ecdsa_policy_buf[0]                            = POLICY_BUF_POLICY_LEN;
    ecdsa_policy_buf[POLICY_BUF_POLICY_OFFSET]     = (uint8_t)((ecdsa_policy & 0xFF000000) >> (8 * 3));
    ecdsa_policy_buf[POLICY_BUF_POLICY_OFFSET + 1] = (uint8_t)((ecdsa_policy & 0x00FF0000) >> (8 * 2));
    ecdsa_policy_buf[POLICY_BUF_POLICY_OFFSET + 2] = (uint8_t)((ecdsa_policy & 0x0000FF00) >> (8 * 1));
    ecdsa_policy_buf[POLICY_BUF_POLICY_OFFSET + 3] = (uint8_t)((ecdsa_policy & 0x000000FF) >> (8 * 0));
    policy_for_auth_obj.value                      = ecdsa_policy_buf;
    policy_for_auth_obj.value_len                  = POLICY_BUF_LEN;

#if SSSFTR_SE05X_ECC
    status = Se05x_API_CreateCurve_prime256v1(pSe05xSession, kSE05x_ECCurve_NIST_P256);
    LOG_I("Se05x_API_CreateCurve_prime256v1 status = %04X", status);
#endif

    status = Se05x_API_CheckObjectExists(pSe05xSession, ECC_ATTESTATION_KEY_ID, &objExists);
    if (status == SM_OK && objExists == kSE05x_Result_SUCCESS) {
        LOG_W("ECC_ATTESTATION_KEY_ID Object already exists");
    }
    else {
        status = Se05x_API_WriteECKey(pSe05xSession,
            (Se05xPolicy_t *)&policy_for_auth_obj,
            SE05x_MaxAttemps_NA,
            ECC_ATTESTATION_KEY_ID,
            kSE05x_ECCurve_NIST_P256,
            NULL,
            0,
            NULL,
            0,
            kSE05x_INS_NA,
            kSE05x_KeyPart_Pair);
        LOG_I("Se05x_API_WriteECKey (Attestation key - ECC_ATTESTATION_KEY_ID) status = %04X", status);
    }

    status = Se05x_API_CheckObjectExists(pSe05xSession, RSA_ATTESTATION_KEY_ID, &objExists);
    if (status == SM_OK && objExists == kSE05x_Result_SUCCESS) {
        LOG_W("RSA_ATTESTATION_KEY_ID Object already exists");
    }
    else {
        status = Se05x_API_WriteRSAKey(pSe05xSession,
            (Se05xPolicy_t *)&policy_for_auth_obj,
            RSA_ATTESTATION_KEY_ID,
            2048,
            SE05X_RSA_NO_p,
            SE05X_RSA_NO_q,
            SE05X_RSA_NO_dp,
            SE05X_RSA_NO_dq,
            SE05X_RSA_NO_qInv,
            SE05X_RSA_NO_pubExp,
            SE05X_RSA_NO_priv,
            SE05X_RSA_NO_pubMod,
            kSE05x_INS_NA,
            kSE05x_KeyPart_Pair,
            kSE05x_RSAKeyFormat_CRT);
        LOG_I("Se05x_API_WriteRSAKey (Attestation key - RSA_ATTESTATION_KEY_ID) status = %04X", status);
    }
}
