/* Copyright 2019,2020 NXP
* SPDX-License-Identifier: Apache-2.0
*/

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <se05x_APDU_apis.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include <string.h>

static ex_sss_boot_ctx_t gex_sss_multiCryptoObj_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_multiCryptoObj_ctx)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#define MD_LEN_BYTES 32

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

#if SSSFTR_SE05X_CREATE_DELETE_CRYPTOOBJ

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    AX_UNUSED_ARG(pCtx);
    LOG_I("Running Multiple Digest Crypto Example se05x_MultipleDigestCryptoObj.c");
    LOG_W("Disable 'SSSFTR_SE05X_CREATE_DELETE_CRYPTOOBJ' in cmake options to run this example");
    return kStatus_SSS_Success;
}

#else

sss_status_t ex_se05x_create_crypto_obj(ex_sss_boot_ctx_t *pCtx, SE05x_CryptoObjectID_t cryptoObjectId)
{
    smStatus_t status = SM_NOT_OK;
    SE05x_CryptoModeSubType_t subtype;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    pSe05xSession_t s_ctx         = &pSession->s_ctx;
    subtype.digest                = kSE05x_DigestMode_SHA256;

    status = Se05x_API_CreateCryptoObject(s_ctx, cryptoObjectId, kSE05x_CryptoContext_DIGEST, subtype);
    if (status != SM_OK) {
        return kStatus_SSS_Fail;
    }

    return kStatus_SSS_Success;
}

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status       = kStatus_SSS_Fail;
    sss_algorithm_t algorithm = kAlgorithm_SSS_SHA256;
    sss_mode_t mode           = kMode_SSS_Digest;
    sss_digest_t ctx_digest1  = {0};
    sss_digest_t ctx_digest2  = {0};

    SE05x_CryptoObjectID_t cryptoObjectId1 = __LINE__;
    SE05x_CryptoObjectID_t cryptoObjectId2 = __LINE__;

    uint8_t input1[] = "HelloWorld1";
    size_t inputLen1 = strlen((const char *)input1);
    uint8_t input2[] = "HelloWorld2";
    size_t inputLen2 = strlen((const char *)input1);

    uint8_t digest1[MD_LEN_BYTES] = {0};
    size_t digestLen1             = sizeof(digest1);
    uint8_t digest2[MD_LEN_BYTES] = {0};
    size_t digestLen2             = sizeof(digest2);

    /* clang-format off */
    uint8_t expectedVal1[MD_LEN_BYTES] = {
        0x90, 0xb4, 0x6d, 0xd6, 0xfa, 0xd0, 0xa8, 0xdb,
        0x49, 0x69, 0x45, 0xa6, 0xbe, 0x27, 0xd9, 0x5f,
        0xbb, 0x78, 0x60, 0x48, 0x22, 0x35, 0x69, 0x70,
        0x56, 0xb8, 0x9b, 0x1d, 0x07, 0x83, 0x68, 0x5e };
    uint8_t expectedVal2[MD_LEN_BYTES] = {
        0xd8, 0xed, 0x22, 0x5a, 0xfc, 0x4b, 0xb0, 0x9b,
        0x47, 0xef, 0xdb, 0x9e, 0xd4, 0x51, 0x7f, 0x2f,
        0x87, 0x4e, 0x3f, 0x61, 0x00, 0xa3, 0x6d, 0x4f,
        0xdd, 0x4d, 0x90, 0xb8, 0x7b, 0x70, 0x72, 0x45 };
    /* clang-format on */

    LOG_I("Running Multiple Digest Crypto Example se05x_MultipleDigestCryptoObj.c");

    status = sss_digest_context_init(&ctx_digest1, &pCtx->session, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_digest_context_init(&ctx_digest2, &pCtx->session, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Create 2 crypto objects and call digest init */
    LOG_I("Create digest crypto object with id - %d !!!", cryptoObjectId1);
    status = ex_se05x_create_crypto_obj(pCtx, cryptoObjectId1);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    ((sss_se05x_digest_t *)&ctx_digest1)->cryptoObjectId = cryptoObjectId1;

    status = sss_digest_init(&ctx_digest1);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Create digest crypto object with id - %d !!!", cryptoObjectId2);
    status = ex_se05x_create_crypto_obj(pCtx, cryptoObjectId2);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    ((sss_se05x_digest_t *)&ctx_digest2)->cryptoObjectId = cryptoObjectId2;

    status = sss_digest_init(&ctx_digest2);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Call update function with input data for both the crypto objects */
    LOG_I("Calling Update function for crypto objectId1 !!!");
    status = sss_digest_update(&ctx_digest1, input1, 2);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Calling Update function for crypto objectId2 !!!");
    status = sss_digest_update(&ctx_digest2, input2, 2);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Calling Update function for crypto objectId1 !!!");
    status = sss_digest_update(&ctx_digest1, input1 + 2, 2);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Calling Update function for crypto objectId2 !!!");
    status = sss_digest_update(&ctx_digest2, input2 + 2, 2);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Calling Update function for crypto objectId1 !!!");
    status = sss_digest_update(&ctx_digest1, input1 + 4, inputLen1 - 4);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Calling Update function for crypto objectId2 !!!");
    status = sss_digest_update(&ctx_digest2, input2 + 4, inputLen2 - 4);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Call digest finish for both crypto objects */
    status = sss_digest_finish(&ctx_digest1, digest1, &digestLen1);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Message Digest (input1) successful !!!");
    LOG_MAU8_I("digest", digest1, digestLen1);

    status = sss_digest_finish(&ctx_digest2, digest2, &digestLen2);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Message Digest (input2) successful !!!");
    LOG_MAU8_I("digest", digest2, digestLen2);

    /* Compare expected output with both crypto objects */
    if (0 != memcmp(digest1, expectedVal1, MD_LEN_BYTES)) {
        status = kStatus_SSS_Fail;
    }
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    if (0 != memcmp(digest2, expectedVal2, MD_LEN_BYTES)) {
        status = kStatus_SSS_Fail;
    }
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = kStatus_SSS_Success;
cleanup:
    if (ctx_digest1.session != NULL) {
        sss_digest_context_free(&ctx_digest1);
    }
    if (ctx_digest2.session != NULL) {
        sss_digest_context_free(&ctx_digest2);
    }
    return status;
}

#endif