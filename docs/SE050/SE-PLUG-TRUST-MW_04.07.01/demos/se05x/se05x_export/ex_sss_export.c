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

static ex_sss_boot_ctx_t gex_sss_export_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

static const char *FileKeyExportdata  = "export_serializedECKey.bin";
static const char *FileSignExportdata = "export_serializedSingedData.bin";

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_export_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t keyPair;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    smStatus_t sw_status;
    sss_asymmetric_t ctx_asymm = {0};

    FILE *fpEcc                  = NULL;
    uint8_t dataBlob[1024]       = {0};
    size_t dataBlobLen           = sizeof(dataBlob);
    const uint8_t dataToSign[32] = "RANDOM DATA";
    size_t dataToSignLen         = sizeof(dataToSign);

    LOG_I("Running Example ex_sss_export.c");

    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    /* Create EC object */
    status = sss_key_object_allocate_handle(&keyPair,
        EXAMPLE_TRANSIENT_EXPORT_IMPORT_KEY_ID,
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        EC_KEY_BIT_LEN / 8,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, EC_KEY_BIT_LEN, NULL);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Export Object to Host */
    sw_status =
        Se05x_API_ExportObject(&pSession->s_ctx, keyPair.keyId, kSE05x_RSAKeyComponent_NA, dataBlob, &dataBlobLen);
    if (SM_OK != sw_status) {
        LOG_E("Failed Se05x_API_ExportObject!!!");
        goto cleanup;
    }
    status = kStatus_SSS_Success;
    LOG_AU8_D(dataBlob, dataBlobLen);
    /* Create a file and store Serialized data in file */
    LOG_I("Export ec key to '%s'!!!", FileKeyExportdata);
    fpEcc = fopen(FileKeyExportdata, "wb+");
    if (fpEcc == NULL) {
        LOG_E("File open failed!!!");
        return kStatus_SSS_Fail;
    }
    fwrite(dataBlob, 1, dataBlobLen, fpEcc);
    fclose(fpEcc);

    status = sss_asymmetric_context_init(&ctx_asymm, &pCtx->session, &keyPair, kAlgorithm_SSS_SHA256, kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    dataBlobLen = sizeof(dataBlob);
    /* Do Signing */
    LOG_MAU8_D("Signing digest", dataToSign, dataToSignLen);
    status = sss_asymmetric_sign_digest(&ctx_asymm, (uint8_t *)dataToSign, dataToSignLen, dataBlob, &dataBlobLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_D("signature", dataBlob, dataBlobLen);
    LOG_I("Signing Successful !!!");
    sss_asymmetric_context_free(&ctx_asymm);

    LOG_I("Export signature key to '%s'.", FileSignExportdata);
    fpEcc = fopen(FileSignExportdata, "wb+");
    if (fpEcc == NULL) {
        LOG_E("File open failed!!!");
        return kStatus_SSS_Fail;
    }
    fwrite(dataBlob, 1, dataBlobLen, fpEcc);
    fclose(fpEcc);

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_export Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_export Example Failed !!!...");
    }
    return status;
}
