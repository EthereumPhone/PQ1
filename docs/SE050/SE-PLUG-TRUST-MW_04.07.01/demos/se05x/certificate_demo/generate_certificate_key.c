/* Copyright 2019 NXP
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
#include <string.h>

#include "certificate.h"

static ex_sss_boot_ctx_t gex_sss_gen_cert;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_gen_cert)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

#define ECC_KEY_BIT_LEN 256

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status          = kStatus_SSS_Fail;
    uint32_t keyId               = CERTIFICATE_KEY_ID;
    size_t keyBitLen             = ECC_KEY_BIT_LEN;
    size_t keyLen                = keyBitLen * 8;
    sss_key_part_t keyPart       = kSSS_KeyPart_Pair;
    sss_cipher_type_t cipherType = kSSS_CipherType_EC_NIST_P;
    sss_object_t obj             = {0};

    status = sss_key_object_init(&obj, &pCtx->ks);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_key_object_init Failed!!!");
        return status;
    }

    status = sss_key_object_allocate_handle(&obj, keyId, keyPart, cipherType, keyLen, kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
        LOG_E("Object allocate handle failed");
        return status;
    }
    status = sss_key_store_generate_key(&pCtx->ks, &obj, keyBitLen, NULL);
    if (status != kStatus_SSS_Success) {
        LOG_E("Failed to inject key");
    }
    else {
        LOG_I("Success");
    }

    return status;
}
