/*
 *
 * Copyright 2025 NXP
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
#include "sm_printf.h"
#include "ex_sss_ports.h"
#include <se05x_APDU_apis.h>
#include <fsl_sss_se05x_policy.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define THREAD1_MAX_ITERATIONS 10
#define THREAD2_MAX_ITERATIONS 20

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */
ex_sss_boot_ctx_t boot_ctx_1 = {0};
ex_sss_boot_ctx_t boot_ctx_2 = {0};
ex_sss_boot_ctx_t *pCtx1     = &boot_ctx_1;
ex_sss_boot_ctx_t *pCtx2     = &boot_ctx_2;

/* ************************************************************************** */
/* Function Definitions                                                       */
/* ************************************************************************** */

static int get_portname_from_args(int argc, char *argv[], char **portname_1, char **portname_2)
{
    if (argc < 3) {
        LOG_E("Port names not provided for the demo");
        PRINTF("USAGE: se05x_multi_threads [PORTNAME_1] [PORTNAME_2]\n");
        return -1;
    }

    *portname_1 = argv[1];
    *portname_2 = argv[2];
    return 0;
}

static sss_status_t create_write_bin_and_read(void *params)
{
    ex_sss_boot_ctx_t *pCtx       = (ex_sss_boot_ctx_t *)params;
    sss_status_t status           = kStatus_SSS_Fail;
    smStatus_t smStatus           = SM_NOT_OK;
    uint8_t rand_buff[20]         = {0};
    size_t rand_buff_len          = sizeof(rand_buff);
    uint8_t buff[1024]            = {0};
    size_t buff_len               = sizeof(buff);
    sss_rng_context_t rng_ctx     = {0};
    sss_se05x_session_t *sess_ctx = (sss_se05x_session_t *)&pCtx->session;
    uint32_t bin_id               = 0xEF000011;
    SE05x_Result_t result         = kSE05x_Result_NA;

    status = sss_rng_context_init(&rng_ctx, &pCtx->session);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    for (int i = 0; i < THREAD1_MAX_ITERATIONS; i++) {
        status = sss_rng_get_random(&rng_ctx, rand_buff, rand_buff_len);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_MAU8_I(" THREAD-1: Random Data", rand_buff, rand_buff_len);

        status   = kStatus_SSS_Fail;
        smStatus = Se05x_API_CheckObjectExists(&(sess_ctx->s_ctx), bin_id, &result);
        ENSURE_OR_GO_CLEANUP(smStatus == SM_OK);

        if (result == kSE05x_Result_SUCCESS) {
            LOG_W(" THREAD-1: Object already present at ID 0x%08X. Deleting it", bin_id);
            smStatus = Se05x_API_DeleteSecureObject(&(sess_ctx->s_ctx), bin_id);
            if (smStatus != SM_OK) {
                LOG_W(" THREAD-1: Unable to delete object at ID 0x%08X", bin_id);
            }
        }

        LOG_I(" THREAD-1: Writing data to binary file at ID 0x%08X", bin_id);
        smStatus = Se05x_API_WriteBinary(&(sess_ctx->s_ctx), NULL, bin_id, 0, 0, rand_buff, rand_buff_len);
        ENSURE_OR_GO_CLEANUP(smStatus == SM_OK);

        LOG_I(" THREAD-1: Reading data from binary file at ID 0x%08X", bin_id);
        smStatus = Se05x_API_ReadObject(&(sess_ctx->s_ctx), bin_id, 0, 0, buff, &buff_len);
        ENSURE_OR_GO_CLEANUP(smStatus == SM_OK);
        LOG_MAU8_I(" THREAD-1: Data Read", buff, buff_len);

        if (memcmp(rand_buff, buff, buff_len) != 0) {
            LOG_I(" THREAD-1: Data mismatch");
            status = kStatus_SSS_Fail;
        }
        else {
            status = kStatus_SSS_Success;
        }
    }

cleanup:
    sss_rng_context_free(&rng_ctx);
    LOG_I("Closing first session");
    ex_sss_session_close(pCtx);

    return status;
}

static sss_status_t ecc_keygen_sign_verify(void *params)
{
    ex_sss_boot_ctx_t *pCtx      = (ex_sss_boot_ctx_t *)params;
    sss_status_t status          = kStatus_SSS_Success;
    uint8_t digest[32]           = "Hello World";
    size_t digestLen             = sizeof(digest);
    uint8_t signature[256]       = {0};
    size_t signatureLen          = sizeof(signature);
    sss_object_t keyPair         = {0};
    sss_asymmetric_t ctx_asymm   = {0};
    sss_asymmetric_t ctx_verify  = {0};
    uint32_t key_id              = 0xEF000022;
    size_t keyBitLen             = 256;
    size_t keyLen                = keyBitLen * 8;
    sss_key_part_t keyPart       = kSSS_KeyPart_Pair;
    sss_cipher_type_t cipherType = kSSS_CipherType_EC_NIST_P;

    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&keyPair, key_id, keyPart, cipherType, keyLen, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_asymmetric_context_init(&ctx_asymm, &pCtx->session, &keyPair, kAlgorithm_SSS_SHA256, kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status =
        sss_asymmetric_context_init(&ctx_verify, &pCtx->session, &keyPair, kAlgorithm_SSS_SHA256, kMode_SSS_Verify);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    for (int i = 0; i < THREAD2_MAX_ITERATIONS; i++) {
        signatureLen = sizeof(signature); // Re initializing signature length
        LOG_I(" THREAD-2: Generating Key Pair at ID 0x%08X", key_id);
        status = sss_key_store_generate_key(&pCtx->ks, &keyPair, keyBitLen, NULL);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_MAU8_I(" THREAD-2: Digest", digest, digestLen);
        LOG_I(" THREAD-2: Signing the digest");
        status = sss_asymmetric_sign_digest(&ctx_asymm, digest, digestLen, signature, &signatureLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_MAU8_I(" THREAD-2: Signature", signature, signatureLen);

        LOG_I(" THREAD-2: Verifying the signature");
        status = sss_asymmetric_verify_digest(&ctx_verify, digest, digestLen, signature, signatureLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_I(" THREAD-2: Verification Successful !!!");
    }
cleanup:

    if (ctx_asymm.session != NULL) {
        sss_asymmetric_context_free(&ctx_asymm);
    }
    if (ctx_verify.session != NULL) {
        sss_asymmetric_context_free(&ctx_verify);
    }
    sss_key_object_free(&keyPair);

    LOG_I("Closing second session");
    ex_sss_session_close(pCtx);
    return status;
}

void *thread_2_task(void *params)
{
    if (kStatus_SSS_Success != ecc_keygen_sign_verify(params)) {
        LOG_E("ecc_keygen_sign_verify failed");
    }
    return NULL;
}

void *thread_1_task(void *params)
{
    if (kStatus_SSS_Success != create_write_bin_and_read(params)) {
        LOG_E("create_write_bin_and_read failed");
    }
    return NULL;
}

int main(int argc, const char *argv[])
{
    sss_status_t status = kStatus_SSS_Success;
    char *portname_1    = NULL;
    char *portname_2    = NULL;
    pthread_t thread_1  = 0;
    pthread_t thread_2  = 0;

    if (get_portname_from_args(argc, (char **)argv, &portname_1, &portname_2)) {
        return -1;
    }

    LOG_I("Running Multi Threads Example se05x_multi_threads.c");

    LOG_I("Opening first session with port name \"%s\"", portname_1);
    status = ex_sss_boot_open(pCtx1, portname_1);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = ex_sss_key_store_and_object_init(pCtx1);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Opening second session with port name \"%s\"", portname_2);
    status = ex_sss_boot_open(pCtx2, portname_2);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = ex_sss_key_store_and_object_init(pCtx2);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Creating threads");

    if (pthread_create(&thread_1, NULL, thread_1_task, pCtx1) != 0) {
        LOG_E("Thread-1 creation failed!");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    if (pthread_create(&thread_2, NULL, thread_2_task, pCtx2) != 0) {
        LOG_E("Thread-2 creation failed!");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    pthread_join(thread_1, NULL);
    pthread_join(thread_2, NULL);

cleanup:

    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_multi_thread_multi_session Example Success !!!...");
    }
    else {
        LOG_E("se05x_multi_thread_multi_session Example Failed !!!...");
    }

    return 0;
}
