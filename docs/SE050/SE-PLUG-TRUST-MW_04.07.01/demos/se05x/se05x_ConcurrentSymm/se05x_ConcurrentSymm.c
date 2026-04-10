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
#define KEY_BIT_LEN 128
/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

uint32_t gAuthid    = 0;
uint32_t gKeyid     = 0;
uint8_t gAlgo       = 0;
char *gportName     = NULL;
uint32_t gLoopCount = 0;
static ex_sss_boot_ctx_t gex_sym_cc_boot_ctx;

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

#define EX_SSS_BOOT_PCONTEXT (&gex_sym_cc_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1

#include <ex_sss_main_cc_inc.h>

static void usage()
{
    LOG_W(
        "\n\
    usage:\n\
    se05x_ConcurrentSymm.exe \n\
        -authid <auth object id to open Session >\n\
        -keyid <Key id to store Key>\n\
        -algo <block cipher mode, choose 1 for ebc or 2 for cbc>\n\
        -cnt <no of times to loop the operation >\n \
        -port <port to connect to>\n");
    return;
}

#define CIPHER_BLOCK_SIZE_TEST 55

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status       = kStatus_SSS_Success;
    int argc                  = gex_sss_argc;
    const char **argv         = gex_sss_argv;
    size_t i                  = 0;
    size_t blocksize          = CIPHER_BLOCK_SIZE_TEST;
    sss_algorithm_t algorithm = kAlgorithm_None;
    sss_mode_t mode;
    /* clang-format off */
    uint8_t srcData[1024] = { 0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x31, 0 };
    uint8_t encData[1100] = { 0, };
    size_t encDataLen = 0;
    uint8_t keystring[KEY_BIT_LEN / 8] = { 0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x31 }; /*HELLOHELLOHELLO1*/
    uint8_t destData[1024] = {0,};
    uint8_t iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t ivlen = sizeof(iv);
    sss_key_part_t keyPart;
    sss_cipher_type_t cipherType;
    size_t keyByteLenMax = KEY_BIT_LEN/8;
    sss_object_t key;
    sss_symmetric_t ctx_symm_encrypt = { 0 };
    sss_symmetric_t ctx_symm_decrypt = { 0 };
    size_t tempOutbufLen = 0;
    size_t tempdataLen = 0;
    size_t output_offset = 0;
    uint32_t uLoopCnt = 0;
    uint32_t uLooplimit = 200;
    const char *portName = NULL;

    /* clang-format on */

    keyPart    = kSSS_KeyPart_Default;
    cipherType = kSSS_CipherType_AES;
    mode       = kMode_SSS_Encrypt;

    LOG_I("\n\n");
    LOG_I("Running AES symmetric Example se05x_ConcurrentSymm.c");
    LOG_I("\n\n");

    /* Parse commandline arguments */
    status = parse_command_line_args(argc, argv);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    algorithm = (sss_algorithm_t)gAlgo;

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
        goto cleanup;
    }

    /* Pre-requisite for encryption Part*/
    //keep the crypto operations in loop
    for (uLoopCnt = 0; uLoopCnt < uLooplimit; uLoopCnt++) {
        LOG_I("LoopCount (loop = %d)\n", uLoopCnt);
        status = sss_key_object_init(&key, &pCtx->ks);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_key_object_allocate_handle(
            &key, gKeyid, keyPart, cipherType, keyByteLenMax, kKeyObject_Mode_Persistent);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_key_store_set_key(&pCtx->ks, &key, keystring, sizeof(keystring), sizeof(keystring) * 8, NULL, 0);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        /* doc:end ex_sss_symmetric-allocate-key */

        mode = kMode_SSS_Encrypt;
        /* doc:start ex_sss_symmetric-encrypt */
        status = sss_symmetric_context_init(&ctx_symm_encrypt, &pCtx->session, &key, algorithm, mode);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        memset(iv, 0x00, 16);
        LOG_I("Do Encryption");
        LOG_MAU8_D("iv", iv, ivlen);
        LOG_MAU8_D("srcData", srcData, sizeof(srcData));
        /*Do Encryption*/

        status = sss_cipher_init(&ctx_symm_encrypt, iv, ivlen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        for (i = 0; i < sizeof(srcData); i = i + blocksize) {
            tempdataLen   = (i + blocksize > sizeof(srcData)) ? (sizeof(srcData) - i) : blocksize;
            tempOutbufLen = tempdataLen + 16; /* To handle any unprocessed data in cache */

            status = sss_cipher_update(
                &ctx_symm_encrypt, (srcData + i), tempdataLen, (encData + output_offset), &tempOutbufLen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            output_offset = output_offset + tempOutbufLen;
        }

        tempOutbufLen = blocksize + 16; /* To handle any unprocessed data in cache */
        status        = sss_cipher_finish(&ctx_symm_encrypt, NULL, 0, (encData + output_offset), &tempOutbufLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        encDataLen = output_offset + tempOutbufLen;

        sss_symmetric_context_free(&ctx_symm_encrypt);

        LOG_I("Encryption successful !!!");
        LOG_MAU8_I("encrypted data", encData, encDataLen);

        mode = kMode_SSS_Decrypt;

        /* doc:start ex_sss_symmetric-decrypt */
        status = sss_symmetric_context_init(&ctx_symm_decrypt, &pCtx->session, &key, algorithm, mode);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_cipher_init(&ctx_symm_decrypt, iv, ivlen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Do Decryption");
        LOG_MAU8_D("iv", iv, ivlen);

        output_offset = 0;
        for (i = 0; i < encDataLen; i = i + blocksize) {
            tempdataLen   = (i + blocksize > encDataLen) ? (encDataLen - i) : blocksize;
            tempOutbufLen = tempdataLen + 16; /* To handle any unprocessed data in cache */

            if (output_offset >= sizeof(destData)) {
                status = kStatus_SSS_Fail;
                goto cleanup;
            }
            status = sss_cipher_update(
                &ctx_symm_decrypt, (encData + i), tempdataLen, (destData + output_offset), &tempOutbufLen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            output_offset = output_offset + tempOutbufLen;
        }

        tempOutbufLen = blocksize + 16; /* To handle any unprocessed data in cache */
        if (output_offset > sizeof(destData)) {
            LOG_E("Failure BufferOverflow");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
        status = sss_cipher_finish(&ctx_symm_decrypt, NULL, 0, (destData + output_offset), &tempOutbufLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Encryption successful !!!");
        LOG_MAU8_I("decrypted data", destData, sizeof(destData));

        if (memcmp(srcData, destData, sizeof(srcData)) == 0) {
            status = kStatus_SSS_Success;
        }
        else {
            status = kStatus_SSS_Fail;
        }

        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Decryption successful !!!");
        output_offset = 0;
        tempOutbufLen = 0;
        tempdataLen   = 0;
        sss_symmetric_context_free(&ctx_symm_encrypt);
        sss_symmetric_context_free(&ctx_symm_decrypt);
    }

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_ConcurrentSymm Example Success !!!...");
    }
    else {
        LOG_E("se05x_ConcurrentSymm Example Failed !!!...");
    }
    if (ctx_symm_encrypt.session != NULL) {
        sss_symmetric_context_free(&ctx_symm_encrypt);
    }
    if (ctx_symm_decrypt.session != NULL) {
        sss_symmetric_context_free(&ctx_symm_decrypt);
    }
    return status;
}

static sss_status_t parse_command_line_args(int argc, const char **argv)
{
    bool authid_passed = false;
    bool keyid_passed  = false;
    bool port_passed   = false;
    bool algo_passed   = false;

    for (int j = 1; j < argc; j++) {
        if (strcmp(argv[j], "-authid") == 0) {
            if (++j < argc) {
                gAuthid = (uint32_t)strtoul(argv[j], NULL, 16);
                if (gAuthid == 0) {
                    LOG_E("Parse cmd line args for Authid using strtoul failed");
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
        else if (strcmp(argv[j], "-algo") == 0) {
            if (++j < argc) {
                gAlgo = (uint8_t)strtoul(argv[j], NULL, 10);
                if (gAlgo == 0) {
                    LOG_E("Parse cmd line args for Algo using strtoul failed");
                    return kStatus_SSS_Fail;
                }
                if (gAlgo == 1 || gAlgo == 2) {
                    algo_passed = true;
                }
            }
        }
        else if (strcmp(argv[j], "-cnt") == 0) {
            if (++j < argc) {
                gLoopCount = (uint32_t)strtoul(argv[j], NULL, 10);
                if (gLoopCount == 0) {
                    LOG_E("Parse cmd line args for loopcount using strtoul failed");
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
    if (!algo_passed) {
        LOG_E("Symm algorithm(ecb/cbc) not passed");
        usage();
        return kStatus_SSS_Fail;
    }
    if (!keyid_passed) {
        LOG_E("Object key Id not passed");
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
