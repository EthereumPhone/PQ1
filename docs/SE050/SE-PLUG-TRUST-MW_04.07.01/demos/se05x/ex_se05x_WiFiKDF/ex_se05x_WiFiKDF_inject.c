/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>
#include <stdio.h>

#include "ex_se05x_WiFiKDF.h"

#define WIFI_PASSWRD "some-wifi-password"

static ex_sss_boot_ctx_t gex_sss_wifi_kdf;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_wifi_kdf)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

static sss_status_t create_hmac_object(
    ex_sss_boot_ctx_t *pCtx, uint32_t hmackeyid, const uint8_t *password, uint32_t password_len)
{
    sss_status_t status;
    sss_object_t hmacKeyObj;

    const sss_policy_u common = {.type = KPolicy_Common,
        .auth_obj_id                   = 0,
        .policy                        = {.common = {
                       .req_Sm     = 0,
                       .can_Delete = 1,
                   }}};

    const sss_policy_u hmackeyPol    = {.type = KPolicy_Sym_Key,
        .auth_obj_id                       = 0,
        .policy                            = {.symmkey = {
                       .can_Write = 1,
                       .can_PBKDF = 1,
                   }}};
    sss_policy_t policy_for_hmac_key = {.nPolicies = 2, .policies = {&hmackeyPol, &common}};

    status = sss_key_object_init(&hmacKeyObj, &pCtx->ks);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_key_object_init Failed");
        return status;
    }

    status = sss_key_object_allocate_handle(
        &hmacKeyObj, hmackeyid, kSSS_KeyPart_Default, kSSS_CipherType_HMAC, password_len, kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_key_object_allocate_handle Failed");
        return status;
    }

    if (password_len > UINT32_MAX / 8) {
        return status;
    }

    status = sss_key_store_set_key(&pCtx->ks,
        &hmacKeyObj,
        password,
        password_len,
        password_len * 8,
        &policy_for_hmac_key,
        sizeof(policy_for_hmac_key));
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_key_store_set_key Failed");
        return status;
    }

    return kStatus_SSS_Success;
}

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    smStatus_t status;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    SE05x_Result_t pExists        = kSE05x_Result_NA;
    const uint8_t wifi_password[] = WIFI_PASSWRD;

    status = Se05x_API_CheckObjectExists(&pSession->s_ctx, WIFI_OBJ_ID, &pExists);

    if (status == SM_OK && pExists == kSE05x_Result_SUCCESS) {
        status = Se05x_API_DeleteSecureObject(&pSession->s_ctx, WIFI_OBJ_ID);
        if (status != SM_OK) {
            LOG_W("Error, could not delete object. ");
            goto cleanup;
        }
    }

    LOG_I("Injecting wifi_password='%s'", wifi_password);
    if (create_hmac_object(pCtx, WIFI_OBJ_ID, wifi_password, sizeof(wifi_password) - 1) != kStatus_SSS_Success) {
        LOG_E("create_hmac_object Failed");
        goto cleanup;
    }

    sss_status = kStatus_SSS_Success;

cleanup:
    return sss_status;
}
