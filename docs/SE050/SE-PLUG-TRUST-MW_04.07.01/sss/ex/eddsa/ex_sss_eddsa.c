/*
 *
 * Copyright 2021 NXP
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
#define EC_KEY_BIT_LEN 256
/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* clang-format off */
// RFC8410 format
const uint8_t keyPairData[] = {
0x30,  0x72,  0x02,  0x01,  0x01,  0x30,  0x05,  0x06,   0x03,  0x2B,  0x65,  0x70,  0x04,  0x22,  0x04,  0x20,
0xD4,  0xEE,  0x72,  0xDB,  0xF9,  0x13,  0x58,  0x4A,   0xD5,  0xB6,  0xD8,  0xF1,  0xF7,  0x69,  0xF8,  0xAD,
0x3A,  0xFE,  0x7C,  0x28,  0xCB,  0xF1,  0xD4,  0xFB,   0xE0,  0x97,  0xA8,  0x8F,  0x44,  0x75,  0x58,  0x42,
0xA0,  0x1F,  0x30,  0x1D,  0x06,  0x0A,  0x2A,  0x86,   0x48,  0x86,  0xF7,  0x0D,  0x01,  0x09,  0x09,  0x14,
0x31,  0x0F,  0x0C,  0x0D,  0x43,  0x75,  0x72,  0x64,   0x6C,  0x65,  0x20,  0x43,  0x68,  0x61,  0x69,  0x72,
0x73,  0x81,  0x21,  0x00,  0x19,  0xBF,  0x44,  0x09,   0x69,  0x84,  0xCD,  0xFE,  0x85,  0x41,  0xBA,  0xC1,
0x67,  0xDC,  0x3B,  0x96,  0xC8,  0x50,  0x86,  0xAA,   0x30,  0xB6,  0xB6,  0xCB,  0x0C,  0x5C,  0x38,  0xAD,
0x70,  0x31,  0x66,  0xE1 };


const uint8_t extPubKeyData[] = {
0x30,  0x2A,  0x30,  0x05,  0x06,  0x03,  0x2B,  0x65,   0x70,  0x03,  0x21,  0x00,  0x19,  0xBF,  0x44,  0x09,
0x69,  0x84,  0xCD,  0xFE,  0x85,  0x41,  0xBA,  0xC1,   0x67,  0xDC,  0x3B,  0x96,  0xC8,  0x50,  0x86,  0xAA,
0x30,  0xB6,  0xB6,  0xCB,  0x0C,  0x5C,  0x38,  0xAD,   0x70,  0x31,  0x66,  0xE1
};

/* clang-format on */

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
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Success;
    uint8_t srcData[50] = "Hello World";
    size_t srcDataLen;
    uint8_t signature[256] = {0};
    size_t signatureLen;
    sss_object_t keyPair;
    sss_object_t key_pub;
    sss_asymmetric_t ctx_asymm  = {0};
    sss_asymmetric_t ctx_verify = {0};

    LOG_I("Running EDDSA Example ex_sss_eddsa.c");

    srcDataLen = sizeof(srcData);

    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    // Allocate a slot with key ID MAKE_TEST_ID in the SE and then inject a EdDSA keypair
    status = sss_key_object_allocate_handle(&keyPair,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_TWISTED_ED,
        sizeof(keyPairData),
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->ks, &keyPair, keyPairData, sizeof(keyPairData), EC_KEY_BIT_LEN, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_asymmetric_context_init(&ctx_asymm, &pCtx->session, &keyPair, kAlgorithm_SSS_SHA512, kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    signatureLen = sizeof(signature);
    LOG_I("Do Signing");
    LOG_MAU8_I("Source Data", srcData, srcDataLen);

    status =
        sss_se05x_asymmetric_sign((sss_se05x_asymmetric_t *)&ctx_asymm, srcData, srcDataLen, signature, &signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_I("signature", signature, signatureLen);
    LOG_I("Signing Successful !!!");
    sss_asymmetric_context_free(&ctx_asymm);

    /* Pre requiste for Verifying Part*/
    // Allocate a slot with key ID MAKE_TEST_ID in the SE and then inject a EdDSA public key
    status = sss_key_object_init(&key_pub, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&key_pub,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Public,
        kSSS_CipherType_EC_TWISTED_ED,
        sizeof(extPubKeyData),
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->ks, &key_pub, extPubKeyData, sizeof(extPubKeyData), EC_KEY_BIT_LEN, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status =
        sss_asymmetric_context_init(&ctx_verify, &pCtx->session, &key_pub, kAlgorithm_SSS_SHA512, kMode_SSS_Verify);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Do Verify");
    LOG_MAU8_I("Source Data", srcData, srcDataLen);
    LOG_MAU8_I("signature", signature, signatureLen);

    status = sss_se05x_asymmetric_verify(
        (sss_se05x_asymmetric_t *)&ctx_verify, srcData, srcDataLen, signature, signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Verification Successful !!!");

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_eddsa Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_eddsa Example Failed !!!...");
    }
    if (ctx_asymm.session != NULL)
        sss_asymmetric_context_free(&ctx_asymm);
    if (ctx_verify.session != NULL)
        sss_asymmetric_context_free(&ctx_verify);
    return status;
}
