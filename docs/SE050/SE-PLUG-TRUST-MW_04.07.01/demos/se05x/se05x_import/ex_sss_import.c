/* Copyright 2020 NXP
 *
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
#include <se05x_APDU.h>
#include <stdio.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

#define EC_KEY_BIT_LEN 256
#define EXAMPLE_TRANSIENT_EXPORT_IMPORT_KEY_ID (0xEF00004F)

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_import_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

static const char *FileKeyExportdata  = "export_serializedECKey.bin";
static const char *FileSignExportdata = "export_serializedSingedData.bin";

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

static sss_status_t ExampleDoVerify(ex_sss_boot_ctx_t *pCtx, sss_object_t *pKeyPair);

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_import_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status           = kStatus_SSS_Fail;
    uint8_t serializedObject[512] = {0x00};
    int serializedObjectLen       = sizeof(serializedObject);
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    smStatus_t sw_status;
    SE05x_Result_t pExists = kSE05x_Result_NA;
    sss_object_t keyPair;
    FILE *fp        = NULL;
    size_t readSize = 0;

    LOG_I("Running Example ex_sss_import.c");

    /* Check object exists before importing to Host */
    sw_status = Se05x_API_CheckObjectExists(&pSession->s_ctx, EXAMPLE_TRANSIENT_EXPORT_IMPORT_KEY_ID, &pExists);
    if (SM_OK == sw_status && pExists == kSE05x_Result_SUCCESS) {
        LOG_I("Object exists!!!");
    }
    else {
        LOG_E("NO ECC Object exists!!!");
        goto cleanup;
    }

    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&keyPair, EXAMPLE_TRANSIENT_EXPORT_IMPORT_KEY_ID);

    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, EC_KEY_BIT_LEN, NULL);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("This verify must fail, because keys are different");
    ExampleDoVerify(pCtx, &keyPair);

    LOG_I("Reading contents form '%s'", FileKeyExportdata);
    fp = fopen(FileKeyExportdata, "rb");
    if (fp == NULL) {
        LOG_E("Could not open '%s'", FileKeyExportdata);
        goto cleanup;
    }
    if (fseek(fp, 0L, SEEK_SET) != 0) {
        LOG_E("fseek failed");
        goto cleanup;
    }
    serializedObjectLen = ftell(fp);
    if (serializedObjectLen <= 0) {
        LOG_E("'%s' is empty", FileKeyExportdata);
        goto cleanup;
    }
    else {
        if (fseek(fp, 0L, SEEK_SET) != 0) {
            LOG_E("fseek failed");
            goto cleanup;
        }
        readSize = fread(serializedObject, serializedObjectLen, 1, fp);
        if (readSize == 0 && ferror(fp)) {
            LOG_E("fread failed");
            goto cleanup;
        }
        LOG_MAU8_D("Serailized Contents", serializedObject, serializedObjectLen);

        /* Import Object to Host */
        sw_status = Se05x_API_ImportObject(&pSession->s_ctx,
            keyPair.keyId,
            kSE05x_RSAKeyComponent_NA, /* Since this is EC Key, */
            serializedObject,
            serializedObjectLen);
        if (SM_OK != sw_status) {
            LOG_E("Failed Se05x_API_ImportObject");
            goto cleanup;
        }

        LOG_I("This verify must pass, because keys are same");
        status = ExampleDoVerify(pCtx, &keyPair);

        status = kStatus_SSS_Success;
    }
cleanup:
    if (fp != NULL) {
        if (fclose(fp) != 0) {
            LOG_E("fclose error");
        }
    }
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_import Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_import Example Failed !!!...");
    }
    return status;
}

static sss_status_t ExampleDoVerify(ex_sss_boot_ctx_t *pCtx, sss_object_t *pKeyPair)
{
    FILE *fp                                       = NULL;
    uint8_t serializedObject[1024]                 = {0x00};
    long serializedObjectLen                       = sizeof(serializedObject);
    sss_status_t status                            = kStatus_SSS_Fail;
    sss_asymmetric_t ctx_verify                    = {0};
    const uint8_t dataToVerify[EC_KEY_BIT_LEN / 8] = "RANDOM DATA";
    size_t dataToVerifyLen                         = sizeof(dataToVerify);
    size_t readSize                                = 0;

    LOG_I("Reading contents form '%s'", FileSignExportdata);
    fp = fopen(FileSignExportdata, "rb");
    if (fp == NULL) {
        LOG_E("Could not open '%s'", FileSignExportdata);
        goto cleanup;
    }
    if (fseek(fp, 0L, SEEK_END) != 0) {
        LOG_E("fseek failed");
        goto cleanup;
    }

    serializedObjectLen = ftell(fp);
    if (serializedObjectLen <= 0) {
        LOG_E("'%s' is empty", FileSignExportdata);
        goto cleanup;
    }
    else {
        if (fseek(fp, 0L, SEEK_SET) != 0) {
            LOG_E("fseek failed");
            goto cleanup;
        }
        readSize = fread(serializedObject, serializedObjectLen, 1, fp);
        if (readSize == 0 && ferror(fp)) {
            LOG_E("fread failed");
            goto cleanup;
        }
        LOG_MAU8_D("Serailized Contents", serializedObject, serializedObjectLen);

        status =
            sss_asymmetric_context_init(&ctx_verify, &pCtx->session, pKeyPair, kAlgorithm_SSS_SHA256, kMode_SSS_Verify);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_MAU8_D("Do Verify", dataToVerify, dataToVerifyLen);
        LOG_MAU8_D("signature", serializedObject, serializedObjectLen);
        status = sss_asymmetric_verify_digest(
            &ctx_verify, (uint8_t *)dataToVerify, dataToVerifyLen, serializedObject, serializedObjectLen);
        if (status == kStatus_SSS_Success) {
            LOG_I("Verification Successful.");
        }
        else {
            LOG_W("Verification Failed!");
        }
        sss_asymmetric_context_free(&ctx_verify);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = kStatus_SSS_Success;
    }
cleanup:
    if (fp != NULL) {
        if (fclose(fp) != 0) {
            LOG_E("fclose error");
        }
    }
    return status;
}
