/*
 *
 * Copyright 2018,2019 NXP
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
#include <string.h>
/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define ECC_KEY_BIT_LENGTH 256
/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_ecdh_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_ecdh_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status             = kStatus_SSS_Success;
    sss_algorithm_t algorithm       = kAlgorithm_SSS_ECDH;
    sss_mode_t mode                 = kMode_SSS_ComputeSharedSecret;
    uint8_t ecdhKey[32]             = {0};
    size_t ecdhKeyLen               = sizeof(ecdhKey);
    size_t ecdhKeyBitLen            = sizeof(ecdhKey) * 8;
    sss_derive_key_t ctx_derive_key = {0};
    sss_object_t deriveKey          = {0};
    sss_object_t keyPair            = {0};
    sss_object_t public_key         = {0};
    uint8_t publicKey[128]          = {0};
    size_t publicKeyLen             = sizeof(publicKey);
    size_t publicKeyBitLen          = sizeof(publicKey) * 8;

    LOG_I("Running ECDH Example ex_sss_ecdh.c");

    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&keyPair,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        256,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, ECC_KEY_BIT_LENGTH, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_get_key(&pCtx->ks, &keyPair, publicKey, &publicKeyLen, &publicKeyBitLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_init(&public_key, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&public_key,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Public,
        kSSS_CipherType_EC_NIST_P,
        256,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->ks, &public_key, publicKey, publicKeyLen, ECC_KEY_BIT_LENGTH, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_init(&deriveKey, &pCtx->host_ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&deriveKey,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        ecdhKeyLen,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_derive_key_context_init(&ctx_derive_key, &pCtx->session, &keyPair, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_derive_key_dh(&ctx_derive_key, &public_key, &deriveKey);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_get_key(&pCtx->host_ks, &deriveKey, ecdhKey, &ecdhKeyLen, &ecdhKeyBitLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("ECDH successful !!!");
    LOG_MAU8_I("ECDH derive Key", ecdhKey, ecdhKeyLen);
cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_ecdh Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_ecdh Example Failed !!!...");
    }
    if (ctx_derive_key.session != NULL) {
        sss_derive_key_context_free(&ctx_derive_key);
    }
    if (deriveKey.keyStore != NULL) {
        sss_key_object_free(&deriveKey);
    }
    if (keyPair.keyStore != NULL) {
        sss_key_object_free(&keyPair);
    }
    if (public_key.keyStore != NULL) {
        sss_key_object_free(&public_key);
    }
    return status;
}
