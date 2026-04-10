/*
 *
 * Copyright 2018, 2019, 2020 NXP
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
#include <stdio.h>
#include <stdlib.h>

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

uint32_t gAuthid    = 0;
uint32_t gKeyid     = 0;
char *gportName     = 0;
uint32_t gLoopCount = 0;

static ex_sss_boot_ctx_t gex_ecc_cc_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

static sss_status_t parse_command_line_args(int argc, const char **argv);
/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_ecc_cc_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1

#include <ex_sss_main_cc_inc.h>

static void usage()
{
    LOG_W(
        "\n\
    usage:\n\
    se05x_ConcurrentEcc.exe \n\
        -authid <auth object id to open Session >\n\
        -keyid <Key id to store Key>\n\
        -cnt <no of times to loop the operation >\n \
        -port <port to be connected >\n");
    return;
}

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status    = kStatus_SSS_Success;
    int argc               = gex_sss_argc;
    const char **argv      = gex_sss_argv;
    uint8_t digest[32]     = {0};
    size_t digestLen       = sizeof(digest);
    uint8_t idigestcnt     = 0;
    uint8_t signature[256] = {0};
    size_t signatureLen;
    sss_object_t keyPair;
    sss_object_t key_pub;
    uint8_t pbKey[256] = {
        0,
    };
    size_t pbKeyByteLen         = sizeof(pbKey);
    size_t pbKeyBitLen          = pbKeyByteLen * 8;
    sss_asymmetric_t ctx_asymm  = {0};
    sss_asymmetric_t ctx_verify = {0};
    uint32_t uLoopCnt           = 0;
    uint32_t uLooplimit         = 200;
    const char *portName        = NULL;

    LOG_I("\n\n");
    LOG_I("Running Elliptic Curve Cryptography Example se05x_ConcurrentEcc");
    LOG_I("\n\n");

    /* Parse commandline arguments */
    status = parse_command_line_args(argc, argv);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    if (gLoopCount != 0) {
        /*Accept the loopcount from user*/
        uLooplimit = gLoopCount;
    }

    portName = gportName;

    /*Open session at given Auth ID*/
    if (gAuthid > INT32_MAX) {
        return kStatus_SSS_Fail;
    }
    status = ex_sss_boot_open_on_id(pCtx, portName, gAuthid);

    status = ex_sss_key_store_and_object_init((pCtx));
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_key_store_and_object_init Failed");
        goto exit;
    }

    //keep the crypto operations in loop
    for (uLoopCnt = 0; uLoopCnt < uLooplimit; uLoopCnt++) {
        LOG_I("LoopCount (loop = %d)\n", uLoopCnt);
        /* Pre-requisite for Signing Part*/
        status = sss_key_object_init(&keyPair, &pCtx->ks);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_key_object_allocate_handle(
            &keyPair, gKeyid, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, 256, kKeyObject_Mode_Persistent);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_key_store_generate_key(&pCtx->ks, &keyPair, EC_KEY_BIT_LEN, 0);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status =
            sss_asymmetric_context_init(&ctx_asymm, &pCtx->session, &keyPair, kAlgorithm_SSS_SHA256, kMode_SSS_Sign);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        signatureLen = sizeof(signature);
        /* Do Signing */
        LOG_I("Do Signing");

        /* Changing  the digest each iteration */
        for (idigestcnt = 0; idigestcnt < 32; idigestcnt++) {
            digest[idigestcnt] = idigestcnt;
        }

        LOG_MAU8_I("digest", digest, digestLen);
        status = sss_asymmetric_sign_digest(&ctx_asymm, digest, digestLen, signature, &signatureLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_MAU8_I("signature", signature, signatureLen);
        LOG_I("Signing Successful !!!");
        sss_asymmetric_context_free(&ctx_asymm);

        /* Pre requiste for Verifying Part*/
        status = sss_key_object_init(&key_pub, &pCtx->ks);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_key_object_allocate_handle(&key_pub,
            (gKeyid + (__LINE__)),
            kSSS_KeyPart_Public,
            kSSS_CipherType_EC_NIST_P,
            sizeof(pbKey),
            kKeyObject_Mode_Persistent);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        /* Get Public Key */
        status = sss_key_store_get_key(&pCtx->ks, &keyPair, pbKey, &pbKeyByteLen, &pbKeyBitLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_key_store_set_key(&pCtx->ks, &key_pub, pbKey, pbKeyByteLen, 256, NULL, 0);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status =
            sss_asymmetric_context_init(&ctx_verify, &pCtx->session, &key_pub, kAlgorithm_SSS_SHA256, kMode_SSS_Verify);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_MAU8_I("digest", digest, digestLen);
        LOG_MAU8_I("signature", signature, signatureLen);
        status = sss_asymmetric_verify_digest(&ctx_verify, digest, digestLen, signature, signatureLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_I("Verification Successful !!!");
        sss_asymmetric_context_free(&ctx_asymm);
        sss_asymmetric_context_free(&ctx_verify);
    }

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_ConcurrentEcc Example Success !!!...");
    }
    else {
        LOG_E("se05x_ConcurrentEcc Example Failed !!!...");
    }
    if (ctx_asymm.session != NULL) {
        sss_asymmetric_context_free(&ctx_asymm);
    }
    if (ctx_verify.session != NULL) {
        sss_asymmetric_context_free(&ctx_verify);
    }
exit:
    return status;
}

static sss_status_t parse_command_line_args(int argc, const char **argv)
{
    bool authid_passed = false;
    bool keyid_passed  = false;
    bool port_passed   = false;

    for (int j = 1; j < argc; j++) {
        if (strcmp(argv[j], "-authid") == 0) {
            if (++j < argc) {
                gAuthid = (uint32_t)strtoul(argv[j], NULL, 16);
                if (gAuthid == 0) {
                    LOG_E("Parse cmd line args for loop count using strtoul failed");
                    return kStatus_SSS_Fail;
                }
                authid_passed = true;
            }
        }
        else if (strcmp(argv[j], "-keyid") == 0) {
            if (++j < argc) {
                gKeyid = (uint32_t)strtoul(argv[j], NULL, 16);
                if (gKeyid == 0) {
                    LOG_E("Parse cmd line args for keyid using strtoul failed");
                    return kStatus_SSS_Fail;
                }
                keyid_passed = true;
            }
        }
        else if (strcmp(argv[j], "-cnt") == 0) {
            if (++j < argc) {
                gLoopCount = (uint32_t)strtoul(argv[j], NULL, 10);
                if (gLoopCount == 0) {
                    LOG_E("Parse cmd line args for loop count using strtoul failed");
                    return kStatus_SSS_Fail;
                }
            }
        }
        else if (strcmp(argv[j], "-port") == 0) {
            if (++j < argc) {
                gportName   = (char *)argv[j];
                port_passed = true;
            }
        }
    }
    if (!authid_passed) {
        LOG_E("Auth key Id not passed");
        usage();
        return kStatus_SSS_Fail;
    }
    if (!keyid_passed) {
        LOG_E("Object key Id  not passed");
        usage();
        return kStatus_SSS_Fail;
    }
    if (!port_passed) {
        LOG_E("Port  not passed");
        usage();
        return kStatus_SSS_Fail;
    }

    return kStatus_SSS_Success;
}
