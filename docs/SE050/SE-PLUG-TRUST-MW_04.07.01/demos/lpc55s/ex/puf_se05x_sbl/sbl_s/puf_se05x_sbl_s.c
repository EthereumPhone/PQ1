/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include <PlugAndTrust_Pkg_Ver.h>

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <ex_sss_scp03_keys.h>
#include <ex_scp03_puf.h>
#include <fsl_hashcrypt.h>
#include <fsl_puf.h>
#include <fsl_sss_se05x_apis.h>
#include <fsl_sss_lpc55s_apis.h>
#include <nxLog_App.h>
#include <string.h>
#include <nxEnsure.h>

#include <ex_sss_auth.h>
#include <smCom.h>

#include "se05x_bind.h"

#define HAVE_KSDK

#include "ex_sss_main_inc_ksdk.h"

/*******************************************************************************
 * Defines
 ******************************************************************************/

#define PUF_INTRINSIC_KEY_SIZE 16

#define SECURE_START 0x10040000
/* doc:start:k-pub-oem-id */
#define K_PUB_OEM_ID 0xA55A
/* doc:end:k-pub-oem-id */
#define AUTH_KEY_SIZE 16

/* typedef for non-secure callback functions */
typedef void (*funcptr_ns)(void) __attribute__((cmse_nonsecure_call));

static ex_sss_boot_ctx_t gex_sss_tp_keys_boot_ctx;
#define EX_SSS_BOOT_PCONTEXT (&gex_sss_tp_keys_boot_ctx)
#define PCONTEXT EX_SSS_BOOT_PCONTEXT

/* This application wants only ISD selection as the keys are for ISD
 * So applet selection has been skipped 
 */
#define EX_SSS_BOOT_SKIP_SELECT_APPLET 1

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/* Open session with applet selected */
static sss_status_t select_applet(ex_sss_boot_ctx_t *pCtx);

/* Open session with applet deselected to change SCP03 keys */
static sss_status_t deselect_applet(ex_sss_boot_ctx_t *pCtx);

/* Test applet by optaining some random data */
static sss_status_t test_random(ex_sss_boot_ctx_t *pCtx);

void JumpToImage(uint32_t addr);

sss_status_t verify_image(ex_sss_boot_ctx_t *pCtx, uint32_t addr);

/* Reset interrupts that were activated during MW boot */
void reset_interrupts();
static sss_status_t getHostAesKeys(ex_sss_boot_ctx_t *pCtx, uint8_t *key, size_t keyLen);

/*******************************************************************************
 * Global variables
 ******************************************************************************/

/*******************************************************************************
 * Functions
 ******************************************************************************/
int main(int argc, const char *argv[])
{
    int ret;
    sss_status_t status = kStatus_SSS_Fail;

    ex_sss_main_ksdk_bm();

    LOG_I(PLUGANDTRUST_PROD_NAME_VER_FULL);

#ifdef EX_SSS_BOOT_PCONTEXT
    memset((EX_SSS_BOOT_PCONTEXT), 0, sizeof(*(EX_SSS_BOOT_PCONTEXT)));
#endif // EX_SSS_BOOT_PCONTEXT

#if defined(EX_SSS_BOOT_SKIP_SELECT_APPLET) && (EX_SSS_BOOT_SKIP_SELECT_APPLET == 1)
    (PCONTEXT)->se05x_open_ctx.skip_select_applet = 1;
#endif

    /* Prepare Host for SCP03 connection, KCs will be set in ex_sss_entry */
    SE05x_Connect_Ctx_t *pConnectCtx = &(PCONTEXT)->se05x_open_ctx;
    pConnectCtx->connType            = kType_SE_Conn_Type_T1oI2C;
    pConnectCtx->portName            = NULL;
    /* Auth type is Platform SCP03 */
    pConnectCtx->auth.authType              = kSSS_AuthType_SCP03;
    pConnectCtx->auth.ctx.scp03.pStatic_ctx = &(PCONTEXT)->ex_se05x_auth.scp03.ex_static;
    pConnectCtx->auth.ctx.scp03.pDyn_ctx    = &(PCONTEXT)->ex_se05x_auth.scp03.ex_dyn;
    pConnectCtx->auth.ctx.scp03.pStatic_ctx->key_len = AUTH_KEY_SIZE;

    status = sss_host_session_open(&(PCONTEXT)->host_session, kType_SSS_mbedTLS, 0, kSSS_ConnectionType_Plain, NULL);
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

    /* Main entry for SBL code */
    status = ex_sss_entry((PCONTEXT));
    LOG_I("ex_sss Finished");
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_entry Failed");
        goto cleanup;
    }

    goto cleanup;

cleanup:
#ifdef EX_SSS_BOOT_PCONTEXT
    ex_sss_session_close((EX_SSS_BOOT_PCONTEXT));
#endif
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
    puf_config_t conf;
    PUF_GetDefaultConfig(&conf);
    sbl_nvm_t nvmCtx = {0};

    /* Default PUF KCs for SE05x dev kit on this LPC (from ex_scp03_puf.h) */
    uint8_t defaultKeyCodeENC[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)] = KEY_CODE_ENC;
    uint8_t defaultKeyCodeMAC[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)] = KEY_CODE_MAC;
    uint8_t defaultKeyCodeDEK[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)] = KEY_CODE_DEK;

    /* Key codes for PUF Index 1 */
    uint8_t newKeyCodeENC[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)] = {0};
    uint8_t newKeyCodeMAC[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)] = {0};
    uint8_t newKeyCodeDEK[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)] = {0};

    /* Read from SBL Flash and check if it is initialized */
    status = sbl_nvm_init();
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sbl_nvm_read(&nvmCtx);
    if (status == kStatus_SSS_Success) {
        /* SE05X Binding already done, load KCs and open session! */
        status = s_platform_prepare_host(&pCtx->host_session,
            &pCtx->host_ks,
            &pCtx->se05x_open_ctx,
            nvmCtx.keyCodeENC,
            nvmCtx.keyCodeMAC,
            nvmCtx.keyCodeDEK,
            PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = select_applet(pCtx);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        /* Test RNG */
        status = test_random(pCtx);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_I("Random test was successful, with KCs loaded from Flash!");
    }
    else {
        /* No Binding yet, create Keys, KCs,, etc. and insert them! */

        /* New key material
         * These will be the static platform SCP03 keys
         * which will be provisioned on the SE and in PUF
         * For testing purposes they are hardcoded here, below is the funcionality to generate then in PUF 
         */
        /* doc:start:new-scp-keys */
        uint8_t newScpKeyENC[PUF_INTRINSIC_KEY_SIZE] = {0};
        uint8_t newScpKeyMAC[PUF_INTRINSIC_KEY_SIZE] = {0};
        uint8_t newScpKeyDEK[PUF_INTRINSIC_KEY_SIZE] = {0};

        status = getHostAesKeys(pCtx, newScpKeyENC, PUF_INTRINSIC_KEY_SIZE);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        // LOG_MAU8_W("Random ENC Key", newScpKeyENC, PUF_INTRINSIC_KEY_SIZE);

        status = getHostAesKeys(pCtx, newScpKeyMAC, PUF_INTRINSIC_KEY_SIZE);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        // LOG_MAU8_W("Random MAC Key", newScpKeyMAC, PUF_INTRINSIC_KEY_SIZE);

        status = getHostAesKeys(pCtx, newScpKeyDEK, PUF_INTRINSIC_KEY_SIZE);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        // LOG_MAU8_W("Random DEK Key", newScpKeyDEK, PUF_INTRINSIC_KEY_SIZE);

        /* doc:end:new-scp-keys */

        /* Check if default SCP keys are correct */
        status = s_platform_prepare_host(&pCtx->host_session,
            &pCtx->host_ks,
            &pCtx->se05x_open_ctx,
            defaultKeyCodeENC,
            defaultKeyCodeMAC,
            defaultKeyCodeDEK,
            PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = select_applet(pCtx);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = test_random(pCtx);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_I("Random test was successful with default SCP03 keys");

        /* Deselect the applet to prepare for SCP03 Key rotation */
        status = deselect_applet(pCtx);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        /* Rotate Platform SCP03 keys to new keys */
        status = rotate_platformscp_keys(newScpKeyENC, newScpKeyMAC, newScpKeyDEK, pCtx);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        /* Insert the new keyCodes into PUF Index 0 (HW keys index) */
        status = puf_insert_scp03_keys(
            newScpKeyENC, newScpKeyMAC, newScpKeyDEK, newKeyCodeENC, newKeyCodeMAC, newKeyCodeDEK);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_MAU8_I("NewKeyCode_ENC", newKeyCodeENC, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
        LOG_MAU8_I("NewKeyCode_MAC", newKeyCodeMAC, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
        LOG_MAU8_I("NewKeyCode_DEK", newKeyCodeDEK, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));

        /* Prepare the boot context with the new SCP03 keyCodes */
        status = s_platform_prepare_host(&pCtx->host_session,
            &pCtx->host_ks,
            &pCtx->se05x_open_ctx,
            newKeyCodeENC,
            newKeyCodeMAC,
            newKeyCodeDEK,
            PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        /* Select the applet again (this time using new keyCodes) */
        status = select_applet(pCtx);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_I("Session Open successful");
        status = test_random(pCtx);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_I("Random test was successful with new SCP03 keys");

        /* Rotation to new keys was successful, write them to Flash */
        memcpy(nvmCtx.keyCodeENC, newKeyCodeENC, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
        memcpy(nvmCtx.keyCodeMAC, newKeyCodeMAC, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
        nvmCtx.marker = BL_DATA_MARKER;
        sbl_nvm_write(&nvmCtx);
    }

    status = verify_image(pCtx, SECURE_START);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Image verification successful, booting the application now!");

    /* Session close - This must be opened by secure application */
    status = deselect_applet(pCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Binding done, jump to application on Secure Side */
    JumpToImage(SECURE_START);

    while (1) {
        /* This point should never be reached */
    }

cleanup:
    return status;
}

static sss_status_t getHostAesKeys(ex_sss_boot_ctx_t *pCtx, uint8_t *key, size_t keyLen)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    sss_rng_context_t sss_rng_ctx = {0};
    sss_status = sss_rng_context_init(&sss_rng_ctx, &pCtx->host_session);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    sss_status = sss_rng_get_random(&sss_rng_ctx, key, keyLen);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    sss_status = sss_rng_context_free(&sss_rng_ctx);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

exit:
    return sss_status;
}

void JumpToImage(uint32_t addr)
{
    uint32_t *vectorTable = (uint32_t *)addr;
    uint32_t sp           = vectorTable[0];
    uint32_t pc           = vectorTable[1];

    typedef void (*app_entry_t)(void);

    uint32_t s_stackPointer     = 0;
    uint32_t s_applicationEntry = 0;
    app_entry_t s_application   = 0;

    s_stackPointer     = sp;
    s_applicationEntry = pc;
    s_application      = (app_entry_t)s_applicationEntry;

    reset_interrupts();

    // Change MSP and PSP
    __set_MSP(s_stackPointer);
    __set_PSP(s_stackPointer);

    SCB->VTOR = addr;

    // Jump to application
    s_application();

    // Should never reach here.
    __NOP();
}

sss_status_t verify_image(ex_sss_boot_ctx_t *pCtx, uint32_t addr)
{
    sss_status_t status      = kStatus_SSS_Fail;
    size_t *image_length_ptr = (size_t *)(addr + 0x20); // offset 0x20
    size_t image_length      = *image_length_ptr;
    size_t data_length       = image_length - 256; // subtract signature length

    /* Digest context */
    sss_digest_t ctx_digest          = {0};
    uint8_t digest[32]               = {0};
    size_t digest_length             = 0;
    sss_algorithm_t digest_algorithm = kAlgorithm_SSS_SHA256;

    /* Signature context */
    sss_asymmetric_t ctx_verify            = {0};
    sss_algorithm_t verification_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
    sss_object_t key_pub;

    ENSURE_OR_GO_CLEANUP(image_length != 0);

    /* First calculate the digest with HOSTCRYPTO over the image */
    status = sss_digest_context_init(&ctx_digest, &pCtx->host_session, digest_algorithm, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_digest_one_go(&ctx_digest, (const uint8_t *)addr, data_length, digest, &digest_length);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_D("Image digest", digest, digest_length);

    /* Perform signature verification over the digest */
    status = sss_key_store_context_init(&pCtx->ks, &pCtx->session);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_object_init(&key_pub, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&key_pub, K_PUB_OEM_ID);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status =
        sss_asymmetric_context_init(&ctx_verify, &pCtx->session, &key_pub, verification_algorithm, kMode_SSS_Verify);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    uint8_t *signature_ptr = (uint8_t *)(addr + data_length); // Pointer to signature in image
    status                 = sss_asymmetric_verify_digest(&ctx_verify, digest, digest_length, signature_ptr, 256);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

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

static sss_status_t deselect_applet(ex_sss_boot_ctx_t *pCtx)
{
    sss_session_t *pSession                 = &pCtx->session;
    pCtx->se05x_open_ctx.skip_select_applet = 1;
    pCtx->se05x_open_ctx.connType           = kType_SE_Conn_Type_T1oI2C;
    sss_status_t status =
        sss_session_open(pSession, kType_SSS_SE_SE05x, 0, kSSS_ConnectionType_Encrypted, &pCtx->se05x_open_ctx);
    if (status == kStatus_SSS_Success) {
        LOG_I("Applet deselection successful!");
    }
    else {
        LOG_E("Applet deselection failed!");
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

void reset_interrupts()
{
    SysTick->CTRL = (uint32_t)0x0U; /* Disable SysTick IRQ and SysTick Timer */
}
