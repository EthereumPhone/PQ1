/*
 *
 * Copyright 2018,2019,2020 NXP
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
#include "se05x_InjectCertificate.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_ecc_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_ecc_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Success;
    sss_object_t ecc_cert_object, rsa_cert_object;
    uint8_t ecc_cert[]     = ECC_CERTIFICATE;
    uint8_t rsa_cert[]     = RSA_CERTIFICATE;
    uint32_t ecc_object_id = ECC_CERTIFICATE_KEYID;
    uint32_t rsa_object_id = RSA_CERTIFICATE_KEYID;

    LOG_I("Inject certificate example");

    status = sss_key_object_init(&ecc_cert_object, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_object_init(&rsa_cert_object, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&ecc_cert_object,
        ecc_object_id,
        kSSS_KeyPart_Default,
        kSSS_CipherType_Binary,
        sizeof(ecc_cert),
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Injecting ECC certificate at 0x%08X", ecc_object_id);
    status =
        sss_key_store_set_key(&pCtx->ks, &ecc_cert_object, ecc_cert, sizeof(ecc_cert), sizeof(ecc_cert) * 8, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&rsa_cert_object,
        rsa_object_id,
        kSSS_KeyPart_Default,
        kSSS_CipherType_Binary,
        sizeof(rsa_cert),
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Injecting RSA certificate at 0x%08X", rsa_object_id);
    status =
        sss_key_store_set_key(&pCtx->ks, &rsa_cert_object, rsa_cert, sizeof(rsa_cert), sizeof(rsa_cert) * 8, NULL, 0);

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_InjectCertificate Example Success !!!...");
    }
    else {
        LOG_E("se05x_InjectCertificate Example Failed !!!...");
    }
    return status;
}
