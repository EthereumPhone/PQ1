/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/*******************************************************************
* Header Files
*******************************************************************/
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "sa_qi_provisioning.h"

#include <fsl_sss_api.h>
#include <fsl_sss_se05x_apis.h>

#include <fsl_sss_se05x_policy.h>
#include "sm_types.h"

#include "nxLog_App.h"

#include <ex_sss.h>
#include <ex_sss_boot.h>

static ex_sss_boot_ctx_t gex_qi_provisioning_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_qi_provisioning_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

/* clang-format off */
/* EC Key policies for Qi credentials */
const sss_policy_u qi_key_policy_common_mgmt = {
    .type = KPolicy_Common,
    /* Authentication object based on management credential */
    .auth_obj_id = EX_MANAGEMENT_CREDENTIAL_ID,
    .policy = {
        .common = {
            .can_Read = 1,
            .can_Write = 1,
            .can_Delete = 1,
        }
    }
};

const sss_policy_u qi_key_policy_asymm_mgmt = {
    .type = KPolicy_Asym_Key,
    /* Authentication object based on management credential */
    .auth_obj_id = EX_MANAGEMENT_CREDENTIAL_ID,
    .policy = {
        .asymmkey = {
            .can_Gen = 1,
        }
    }
};

const sss_policy_u qi_key_policy_common_all = {
    .type = KPolicy_Common,
    .auth_obj_id = 0,
    .policy = {
        .common = {
            .can_Read = 1,
        }
    }
};

const sss_policy_u qi_key_policy_asymm_all = {
    .type = KPolicy_Asym_Key,
    .auth_obj_id = 0,
    .policy = {
        .asymmkey = {
            .can_Sign = 1,
            .can_Verify = 1,
        }
    }
};

/* Binary object policies for Qi credentials */
const sss_policy_u qi_cert_policy_common_mgmt = {
    .type = KPolicy_Common,
    /* Authentication object based on management credential */
    .auth_obj_id = EX_MANAGEMENT_CREDENTIAL_ID,
    .policy = {
        .common = {
            .can_Write = 1,
            .can_Delete = 1,
            .can_Read = 1,
        }
    }
};

/* Binary object policies for Qi credentials */
const sss_policy_u qi_cert_policy_common_all = {
    .type = KPolicy_Common,
    .auth_obj_id = 0,
    .policy = {
        .common = {
            .can_Read = 1,
        }
    }
};
/* clang-format on */

/*******************************************************************
* Static Functions
*******************************************************************/
sss_status_t add_qi_credential(sss_object_t *pKeyObject,
    sss_key_store_t *pKs,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    const uint8_t *buff,
    size_t buff_size,
    size_t keyBitLen,
    uint32_t keyId,
    sss_policy_t *pPolicy);

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status       = kStatus_SSS_Success;
    uint32_t qi_key_id        = QI_SLOT_ID_TO_KEY_ID(QI_PROVISIONING_SLOT_ID);
    uint32_t qi_cert_id       = QI_SLOT_ID_TO_CERT_ID(QI_PROVISIONING_SLOT_ID);
    sss_object_t qi_kp_object = {0}, qi_cert_chain_object = {0};

    sss_policy_t policy_for_ec_key     = {.nPolicies = 4,
        .policies                                = {&qi_key_policy_asymm_mgmt,
            &qi_key_policy_common_mgmt,
            &qi_key_policy_asymm_all,
            &qi_key_policy_common_all}};
    sss_policy_t policy_for_cert_chain = {
        .nPolicies = 2, .policies = {&qi_cert_policy_common_mgmt, &qi_cert_policy_common_all}};

    status = add_qi_credential(&qi_kp_object,
        &pCtx->ks,
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        qi_ec_priv_key,
        qi_ec_priv_key_len,
        256,
        qi_key_id,
        &policy_for_ec_key);
    if (status != kStatus_SSS_Success) {
        LOG_E("Failed to store Qi private key");
        goto exit;
    }

    status = add_qi_credential(&qi_cert_chain_object,
        &pCtx->ks,
        kSSS_KeyPart_Default,
        kSSS_CipherType_Binary,
        qi_certificate_chain,
        qi_certificate_chain_len,
        qi_certificate_chain_len * 8,
        qi_cert_id,
        &policy_for_cert_chain);
    if (status != kStatus_SSS_Success) {
        LOG_E("Failed to store Qi certificate chain");
        goto exit;
    }

    LOG_I("Qi Provisioning successful");
exit:
    LOG_I("Qi Provisioning Example Finished");
    return status;
}

sss_status_t add_qi_credential(sss_object_t *pKeyObject,
    sss_key_store_t *pKs,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    const uint8_t *buff,
    size_t buff_size,
    size_t keyBitLen,
    uint32_t keyId,
    sss_policy_t *pPolicy)
{
    sss_status_t status = kStatus_SSS_Success;

    status = sss_key_object_init(pKeyObject, pKs);
    if (status != kStatus_SSS_Success) {
        LOG_I("sss_key_object_init failed");
        goto exit;
    }

    status =
        sss_key_object_allocate_handle(pKeyObject, keyId, keyPart, cipherType, buff_size, kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_key_object_allocate_handle failed");
        goto exit;
    }

    status = sss_key_store_set_key(pKs, pKeyObject, buff, buff_size, keyBitLen, pPolicy, sizeof(*pPolicy));
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_key_store_set_key failed");
        goto exit;
    }
exit:
    return status;
}
