/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <fsl_sss_lpc55s_apis.h>
#include <nxLog_App.h>
#include <nxEnsure.h>
#include <ex_sss_auth.h>
#include <smCom.h>
#include "se05x_bind.h"
#include "memory.h"

/*******************************************************************************
 * Global variables
 ******************************************************************************/
static ex_sss_boot_ctx_t gex_sss_tp_keys_boot_ctx;
sss_session_t *pBaseSession;

/*******************************************************************************
 * Defines
 ******************************************************************************/

#define PCONTEXT (&gex_sss_tp_keys_boot_ctx)
#define HAVE_KSDK
#include "ex_sss_main_inc_ksdk.h"

/* Platform SCP03 Key Version no */
#define PF_KEY_VERSION_NO 0x0B
#define SCP03_MAX_AUTH_KEY_SIZE 52

#define NON_SECURE_START 0x00070000
#define AUTH_KEY_SIZE 16
typedef void (*funcptr_ns)(void) __attribute__((cmse_nonsecure_call));

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/* Open session with applet selected */
static sss_status_t select_applet(ex_sss_boot_ctx_t *pCtx);

/* Test applet by optaining some random data */
static sss_status_t test_random(ex_sss_boot_ctx_t *pCtx);

/* Platform SCP03 prepare host */
sss_status_t s_platform_prepare_host(sss_session_t *pHostSession,
    sss_key_store_t *pHostKs,
    SE_Connect_Ctx_t *se05x_open_ctx,
    uint8_t *ENC_KEY,
    uint8_t *MAC_KEY,
    uint8_t *DEK_KEY,
    size_t key_length);

/* Platform SCP03 Allocate key object */
sss_status_t s_alloc_Scp03key_Host(sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId);

/*******************************************************************************
 * Functions
 ******************************************************************************/
int main()
{
    const char *portName = NULL;
    funcptr_ns ResetHandler_ns;

    ex_sss_main_ksdk_bm();

    memset((PCONTEXT), 0, sizeof(*(PCONTEXT)));
    pBaseSession = &((PCONTEXT)->session);

    (PCONTEXT)->se05x_open_ctx.skip_select_applet = 1;

    /** Prepare Host for SCP03 connection, KCs will be set in ex_sss_entry **/
    SE05x_Connect_Ctx_t *pConnectCtx = &(PCONTEXT)->se05x_open_ctx;
    // Hardcode the connection to T1oI2C
    pConnectCtx->connType = kType_SE_Conn_Type_T1oI2C;
    pConnectCtx->portName = portName;
    // Auth type is Platform SCP03
    pConnectCtx->auth.authType              = kSSS_AuthType_SCP03;
    pConnectCtx->auth.ctx.scp03.pStatic_ctx = &(PCONTEXT)->ex_se05x_auth.scp03.ex_static;
    pConnectCtx->auth.ctx.scp03.pDyn_ctx    = &(PCONTEXT)->ex_se05x_auth.scp03.ex_dyn;
    pConnectCtx->auth.ctx.scp03.pStatic_ctx->key_len = AUTH_KEY_SIZE;

    sss_status_t status =
        sss_host_session_open(&(PCONTEXT)->host_session, kType_SSS_mbedTLS, 0, kSSS_ConnectionType_Plain, NULL);
    if (kStatus_SSS_Success != status) {
        LOG_E("Failed to open Host Session");
        goto cleanup;
    }
    status = sss_host_key_store_context_init(&(PCONTEXT)->host_ks, &(PCONTEXT)->host_session);
    if (kStatus_SSS_Success != status) {
        LOG_E("Host: sss_key_store_context_init failed");
        goto cleanup;
    }
    status = sss_host_key_store_allocate(&(PCONTEXT)->host_ks, __LINE__);
    if (kStatus_SSS_Success != status) {
        LOG_E("Host: sss_key_store_allocate failed");
        goto cleanup;
    }

    status = ex_sss_entry((PCONTEXT));
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_entry Failed");
        goto cleanup;
    }

    /* Set non-secure main stack (MSP_NS) */
    __TZ_set_MSP_NS(*((uint32_t *)(NON_SECURE_START)));

    /* Set non-secure vector table */
    SCB_NS->VTOR = NON_SECURE_START;

    /* Get non-secure reset handler */
    ResetHandler_ns = (funcptr_ns)(*((uint32_t *)((NON_SECURE_START) + 4U)));

    /* Call non-secure application */
    LOG_I("Entering normal world see you there.\r\n");
    /* Jump to normal world */
    ResetHandler_ns();
    while (1) {
        /* This point should never be reached */
    }

cleanup:
    LOG_I("ex_sss Finished");
    ex_sss_session_close((PCONTEXT));
    int ret;
    if (kStatus_SSS_Success == status) {
        ret = 0;
        ex_sss_main_ksdk_success();
    }
    else {
        LOG_E("!ERROR! ret != 0.");
        ret = 1;
        ex_sss_main_ksdk_failure();
    }
    return ret;
}

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sbl_nvm_t nvmCtx    = {0};
    /* Prepare the Host with the SCP03 keycodes prepared by the SBL */
    memory_init();
    memory_read(BL_DATA_START, (void *)&nvmCtx, sizeof(sbl_nvm_t));
    ENSURE_OR_GO_CLEANUP(nvmCtx.marker == BL_DATA_MARKER);

    status = s_platform_prepare_host(&pCtx->host_session,
        &pCtx->host_ks,
        &pCtx->se05x_open_ctx,
        nvmCtx.keyCodeENC,
        nvmCtx.keyCodeMAC,
        nvmCtx.keyCodeDEK,
        PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Open the SCP03 session with the applet selected */
    status = select_applet(pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Test RNG */
    status = test_random(pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Random test was successful from secure application");

cleanup:
    return status;
}

static sss_status_t select_applet(ex_sss_boot_ctx_t *pCtx)
{
    sss_session_t *pSession                 = &pCtx->session;
    pCtx->se05x_open_ctx.skip_select_applet = 0;
    pCtx->se05x_open_ctx.connType           = kType_SE_Conn_Type_T1oI2C;
    sss_status_t status =
        sss_session_open(pSession, kType_SSS_SE_SE05x, 0, kSSS_ConnectionType_Encrypted, &pCtx->se05x_open_ctx);
    if (status == kStatus_SSS_Success) {
        LOG_I("Applet selection successful!");
    }
    else {
        LOG_E("Applet selection failed!");
    }
    return status;
}

static sss_status_t test_random(ex_sss_boot_ctx_t *pCtx)
{
    sss_rng_context_t rng;
    uint8_t rndData[256] = {0};

    sss_status_t status = sss_rng_context_init(&rng, &pCtx->session);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);
    status = sss_rng_get_random(&rng, rndData, 32);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_rng_context_free(&rng);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:
    return status;
}

sss_status_t s_platform_prepare_host(sss_session_t *pHostSession,
    sss_key_store_t *pHostKs,
    SE_Connect_Ctx_t *se05x_open_ctx,
    uint8_t *ENC_KEY,
    uint8_t *MAC_KEY,
    uint8_t *DEK_KEY,
    size_t key_length)
{
    sss_status_t status = kStatus_SSS_Fail;

    NXSCP03_StaticCtx_t *pStatic_ctx = se05x_open_ctx->auth.ctx.scp03.pStatic_ctx;
    NXSCP03_DynCtx_t *pDyn_ctx       = se05x_open_ctx->auth.ctx.scp03.pDyn_ctx;

    pStatic_ctx->keyVerNo = PF_KEY_VERSION_NO;

    /* Init Allocate ENC Static Key */
    status = s_alloc_Scp03key_Host(&pStatic_ctx->Enc, pHostKs, __LINE__);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Set ENC Static Key */
    status = sss_key_store_set_key(pHostKs, &pStatic_ctx->Enc, ENC_KEY, key_length, key_length * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate MAC Static Key */
    status = s_alloc_Scp03key_Host(&pStatic_ctx->Mac, pHostKs, __LINE__);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Set MAC Static Key */
    status = sss_key_store_set_key(pHostKs, &pStatic_ctx->Mac, MAC_KEY, key_length, key_length * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate DEK Static Key */
    status = s_alloc_Scp03key_Host(&pStatic_ctx->Dek, pHostKs, __LINE__);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Set DEK Static Key */
    status = sss_key_store_set_key(pHostKs, &pStatic_ctx->Dek, DEK_KEY, key_length, key_length * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate ENC Session Key */
    status = s_alloc_Scp03key_Host(&pDyn_ctx->Enc, pHostKs, __LINE__);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate MAC Session Key */
    status = s_alloc_Scp03key_Host(&pDyn_ctx->Mac, pHostKs, __LINE__);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Init Allocate DEK Session Key */
    status = s_alloc_Scp03key_Host(&pDyn_ctx->Rmac, pHostKs, __LINE__);

    return status;
}

sss_status_t s_alloc_Scp03key_Host(sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId)
{
    sss_status_t status = kStatus_SSS_Fail;
    status              = sss_key_object_init(keyObject, pKs);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    status = sss_key_object_allocate_handle(keyObject,
        keyId,
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        SCP03_MAX_AUTH_KEY_SIZE,
        kKeyObject_Mode_Transient);
    return status;
}