/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "mfa_process_tst.h"

#include <nxEnsure.h>
#include <nxLog_App.h>
#include <stdio.h>
#include <stdlib.h>

#include "global_platf.h"
#include "mfa_utils.h"
#include "smCom.h"

//#ifdef SMCOM_JRCP_V2
//#include <smComJRCP.h>
//#endif

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

#define MAX_TX_RX_BUFFER 1024

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static const uint32_t gkeyIdEcc = MAKE_TEST_ID(__LINE__);
static const char *FileEccSignature = "ecc_sign.txt";

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

void mfa_process_testapplet(const char *aid, const char *command)
{
    smStatus_t retStatus = SM_NOT_OK;
    uint8_t *apdu = NULL;
    size_t apdu_len = 0;
    uint8_t *aidhex = NULL;
    size_t aidhex_len = 0;

    uint8_t rx[MAX_TX_RX_BUFFER];
    U32 rlen = sizeof(rx);

    uint8_t selectResp[128] = {0x00};
    U16 selectRespLen = sizeof(selectResp);

    aidhex = hexstr_to_bytes(aid, &aidhex_len);
    if (aidhex == NULL) {
        printf("invalid hexstr in [%s]\n", aid);
        return;
    }

    /* Select card manager / ISD */
    retStatus = (smStatus_t)GP_Select(NULL,
        aidhex, /* dummy  buffer reused*/
        0,
        selectResp,
        &selectRespLen);
    if (retStatus != SM_OK) {
        LOG_E("Could not select ISD.");
        goto cleanup;
    }

    selectRespLen = sizeof(selectResp);
    /* Select applet */
    retStatus =
        (smStatus_t)GP_Select(NULL, aidhex, (U16)aidhex_len, selectResp, &selectRespLen);
    if (retStatus != SM_OK) {
        printf("Could not select applet with aid [%s]\n", aid);
        goto cleanup;
    }

    if (command) {
        apdu = hexstr_to_bytes(command, &apdu_len);
        if (apdu == NULL) {
            printf("invalid hexstr in [%s]\n", command);
            return;
        }
        printf("Executing [%s]\n", command);
        if (SW_OK !=
            smCom_TransceiveRaw(NULL, apdu, (uint16_t)apdu_len, rx, &rlen)) {
            printf("Unable to send apdu [%s]\n", command);
            free(apdu);
            free(aidhex);
            return;
        }
        U32 ret;
        ret = ((rx[rlen - 2] << 8) | (rx[rlen - 1]));
        if (SW_OK != ret) {
            printf("Unexpected response for apdu [%s]\n", command);
            free(apdu);
            free(aidhex);
            return;
        }
    }
    print_SSS_StatusCode(kStatus_SSS_Success);
cleanup:
    if (apdu) {
        free(apdu);
    }
    if (aidhex) {
        free(aidhex);
    }
}

//#ifdef SMCOM_JRCP_V2
//void mfa_process_prepareTear(const char *bytesString)
//{
//    uint32_t instruction_bytes = atoi(bytesString);
//    if (SW_OK != smComJRCP_Reset(NULL, instruction_bytes)) {
//        print_SSS_StatusCode(kStatus_SSS_Fail);
//    }
//    print_SSS_StatusCode(kStatus_SSS_Success);
//}
//#endif

void mfa_process_testIoTPreUpgrade()
{
    sss_status_t status;
    sss_algorithm_t algorithm;
    sss_mode_t mode;
    uint8_t digest[32] = "Hello World";
    size_t digestLen = sizeof(digest);
    uint8_t signature[256] = {0};
    size_t signatureLen = sizeof(signature);
    size_t keylen = 256 / 8;
    sss_asymmetric_t asymCtx = {0, };
    sss_object_t keyPair;
    /* asymmetric Sign */
    algorithm = kAlgorithm_SSS_SHA256;
    mode = kMode_SSS_Sign;
    FILE *fp = NULL;

    status = sss_key_object_init(&keyPair, &gfeature_app_sems_lite_boot_ctx.ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&keyPair,
        gkeyIdEcc,
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        keylen,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_asymmetric_context_init(&asymCtx,
        &gfeature_app_sems_lite_boot_ctx.session,
        &keyPair,
        algorithm,
        mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_generate_key(
        &gfeature_app_sems_lite_boot_ctx.ks, &keyPair, 256, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_asymmetric_sign_digest(
        &asymCtx, digest, digestLen, signature, &signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    sss_asymmetric_context_free(&asymCtx);

    fp = fopen(FileEccSignature, "wb");
    if (fp == NULL) {
        printf("File open failed");
        return;
    }
    if(fwrite(signature, 1, signatureLen, fp) != signatureLen) {
        printf("fwrite failed");
        if(fclose(fp) != 0) {
            LOG_E("Error closing file");
        }
        return;
    }
    print_SSS_StatusCode(kStatus_SSS_Success);
    if (fclose(fp) != 0) {
        LOG_E("Error in closing file.");
    }
    return;
cleanup:
    print_SSS_StatusCode(kStatus_SSS_Fail);
}

void mfa_process_testIoTPostUpgrade()
{
    sss_status_t status;
    uint8_t digest[32] = "Hello World";
    size_t digestLen = sizeof(digest);
    uint8_t signature[256] = {0};
    long int signatureLen   = sizeof(signature);
    uint8_t pbKey[256];
    size_t pbKeyBitLen = 256;
    size_t pbKeyBytetLen = sizeof(pbKey);
    sss_object_t keyPair;
    sss_object_t Pubkey;
    sss_asymmetric_t asymVerifyCtx = {0, };
    FILE *fp = NULL;
    size_t readSize = 0;

    fp = fopen(FileEccSignature, "rb");
    if (fp == NULL) {
        printf("File open failed");
        return;
    }
    if (fseek(fp, 0L, SEEK_END) != 0) {
        printf("fseek failed");
        goto cleanup;
    }
    signatureLen = ftell(fp);
    if (signatureLen < 0) {
        printf("ftell failed");
        goto cleanup;
    }
    else {
        if (fseek(fp, 0L, SEEK_SET) != 0) {
            printf("fseek failed");
            goto cleanup;
        }
        readSize = fread(signature, signatureLen, 1, fp);
        if (readSize == 0 && ferror(fp)) {
            printf("fread failed");
            goto cleanup;
        }

        status = sss_key_object_init(&keyPair, &gfeature_app_sems_lite_boot_ctx.ks);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success)

        status = sss_key_object_get_handle(&keyPair, gkeyIdEcc);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success)

        status =
            sss_key_store_get_key(&gfeature_app_sems_lite_boot_ctx.ks, &keyPair, pbKey, &pbKeyBytetLen, &pbKeyBitLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success)

        tst_asymm_alloc_and_set_key(&Pubkey,
            &gfeature_app_sems_lite_boot_ctx.ks,
            kSSS_KeyPart_Public,
            kSSS_CipherType_EC_NIST_P,
            MAKE_TEST_ID(__LINE__),
            pbKey,
            pbKeyBytetLen,
            256,
            kKeyObject_Mode_Persistent);

        status = sss_asymmetric_context_init(
            &asymVerifyCtx, &gfeature_app_sems_lite_boot_ctx.session, &Pubkey, kAlgorithm_SSS_SHA256, kMode_SSS_Verify);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_asymmetric_verify_digest(&asymVerifyCtx, digest, digestLen, signature, signatureLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success)
        sss_asymmetric_context_free(&asymVerifyCtx);
        print_SSS_StatusCode(kStatus_SSS_Success);
        if (fclose(fp) != 0) {
            LOG_E("Error in closing file.");
        }
        return;
    }
cleanup:
    if (fp != NULL) {
        if (fclose(fp) != 0) {
            LOG_E("Error in closing file.");
        }
    }
    print_SSS_StatusCode(kStatus_SSS_Fail);
}
