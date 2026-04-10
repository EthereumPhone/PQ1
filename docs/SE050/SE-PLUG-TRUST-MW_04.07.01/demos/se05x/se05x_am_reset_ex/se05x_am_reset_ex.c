/* Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxLog_App.h>
#include "nxEnsure.h"

static ex_sss_boot_ctx_t gex_sss_boot_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status           = kStatus_SSS_Success;
    sss_algorithm_t algorithm     = kAlgorithm_SSS_SHA256;
    sss_mode_t mode               = kMode_SSS_Digest;
    uint8_t input[]               = "HelloWorld";
    size_t inputLen               = strlen((const char *)input);
    uint8_t digest[32]            = {0};
    size_t digestLen              = sizeof(digest);
    sss_digest_t ctx_digest       = {0};
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    Se05xSession_t *pSe05xSession = &pSession->s_ctx;

    status = sss_digest_context_init(&ctx_digest, &pCtx->session, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Do Digest");
    status = sss_digest_one_go(&ctx_digest, input, inputLen, digest, &digestLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Send secure element reset command \n\n");
    if (SM_AmResetI2C(pSe05xSession->conn_ctx) != 0) {
        LOG_E("SM_AmResetI2C failed");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    status = sss_digest_context_init(&ctx_digest, &pCtx->session, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Do Digest");
    status = sss_digest_one_go(&ctx_digest, input, inputLen, digest, &digestLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("Access Manager reset Example Success !!!...");
    }
    else {
        LOG_E("Access Manager reset Example Failed !!!...");
    }
    if (ctx_digest.session != NULL) {
        sss_digest_context_free(&ctx_digest);
    }
    return status;
}
