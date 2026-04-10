/*
 *
 * Copyright 2021 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include "sm_types.h"
#include "sm_apdu.h"
#include "tst_sm_util.h"
#include "sm_printf.h"
#include "scp.h"
#include "ax_util.h"
#include "app_boot.h"

#include <ex_sss_boot.h>
#include <fsl_sss_se05x_types.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <sm_const.h>
#include <stdio.h>
#include <nxEnsure.h>

#if defined(T1oI2C)
#include "smComT1oI2C.h"
#include "phNxpEse_Internal.h"
#endif

#include "fsl_sss_se05x_apis.h"
#include "se05x_tlv.h"
#include "nxScp03_Const.h"

static ex_sss_boot_ctx_t gex_sss_demo_boot_ctx;

#if (SSS_HAVE_SE05X_AUTH_PLATFSCP03)
#define SSS_EX_SE05x_AUTH_MECH kSSS_AuthType_SCP03
#define SSS_EX_CONNECTION_TYPE kSSS_ConnectionType_Encrypted
#endif

#include "ex_sss_scp03_keys.h"
#define RESUME_SCP03_FILE_PATH EX_SSS_SCP03_FILE_DIR "resume_scp.txt"

// WARNING: Simply writing the session keys to the file system is not a secure implementation.
// it must not be used in products.
static U8 writeStateToFile(char *szFilename,
    NXSCP03_DynCtx_t *DynCtx,
    uint8_t *enc,
    size_t enc_len,
    uint8_t *mac,
    size_t mac_len,
    uint8_t *rmac,
    size_t rmac_len);

static U8 readStateFromFile(char *szFilename,
    NXSCP03_DynCtx_t *DynCtx,
    uint8_t *enc,
    size_t enc_len,
    uint8_t *mac,
    size_t mac_len,
    uint8_t *rmac,
    size_t rmac_len);

static sss_status_t createAndStoreHostAesKey(sss_object_t *pHostObject, uint8_t *key, size_t size);

const char *boot_mode = NULL;

sss_status_t rsa_ex(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status;
#if !SSS_HAVE_FIPS
    uint8_t digest[32] = {0};
    size_t digestLen;
    uint8_t signature[512] = {0};
    size_t signatureLen;
    sss_algorithm_t algorithm;
    sss_mode_t mode;
    size_t val     = 0;
    mode           = kMode_SSS_Sign;
    digestLen      = sizeof(digest);
    signatureLen   = sizeof(signature);
    algorithm      = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
    size_t keylen  = 1024;
    uint32_t keyId = MAKE_TEST_ID(__LINE__);
    /* asymmetric Sign */
#endif
    sss_object_t key;
    sss_asymmetric_t ctx_asymm = {0};

    LOG_I("Running RSA Example");

    status = sss_key_object_init(&key, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

#if SSS_HAVE_FIPS
    ENSURE_OR_GO_CLEANUP(status != kStatus_SSS_Success);
    status = kStatus_SSS_Success;
    goto cleanup;
#else

    for (; val < sizeof(digest); ++val)
        digest[val] = (uint8_t)val;

    status = sss_key_object_allocate_handle(
        &key, keyId, kSSS_KeyPart_Pair, kSSS_CipherType_RSA, (keylen / 8), kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_erase_key(&pCtx->ks, &key);
    LOG_I("Delete key succeeds only if key exists, ignore error message if any");
    status = sss_key_store_generate_key(&pCtx->ks, &key, keylen, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_asymmetric_context_init(&ctx_asymm, &pCtx->session, &key, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Do Signing");
    LOG_MAU8_I("digest", digest, digestLen);

    status = sss_asymmetric_sign_digest(&ctx_asymm, digest, digestLen, signature, &signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Signing successful !!!");
    LOG_MAU8_I("signature", signature, signatureLen);

    LOG_I("Do Verification");
    status = sss_asymmetric_verify_digest(&ctx_asymm, digest, digestLen, signature, signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Verification successful !!!");
#endif
cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_RSA Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_RSA Example Failed !!!...");
    }
    if (ctx_asymm.session != NULL) {
        sss_asymmetric_context_free(&ctx_asymm);
    }

    sss_key_object_free(&key);

    return status;
}

sss_status_t exBoot_SKIP_EXAMPLE()
{
    PRINTF("***** WARNING: se05x_scp03_boot example is skipped *****\r\n");
    return kStatus_SSS_Success;
}

sss_status_t exBoot_BOOTLOADER_ROLE()
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    char *portName;
    uint8_t enc_key[16]  = {0};
    size_t enc_len       = sizeof(enc_key);
    size_t enc_bit_len   = enc_len * 8;
    uint8_t mac_key[16]  = {0};
    size_t mac_len       = sizeof(mac_key);
    size_t mac_bit_len   = mac_len * 8;
    uint8_t rmac_key[16] = {0};
    size_t rmac_len      = sizeof(rmac_key);
    size_t rmac_bit_len  = rmac_len * 8;

#if AX_EMBEDDED
    portName = NULL;
    ex_sss_boot_direct();
#else
    sss_status = ex_sss_boot_connectstring(0, NULL, &portName);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);
#endif // AX_EMBEDDED
    gex_sss_demo_boot_ctx.se05x_open_ctx.skip_select_applet = 0;

    sss_status = ex_sss_boot_open(&gex_sss_demo_boot_ctx, portName);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);

    sss_se05x_session_t *pse05xSession = (sss_se05x_session_t *)&gex_sss_demo_boot_ctx.session;
    pSe05xSession_t se05xSession       = (pSe05xSession_t)(&pse05xSession->s_ctx);
    NXSCP03_DynCtx_t *pDynCtx          = se05xSession->pdynScp03Ctx;

    /* Retrive the session keys*/
    sss_status = sss_key_store_get_key(pDynCtx->Enc.keyStore, &pDynCtx->Enc, enc_key, &enc_len, &enc_bit_len);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);
    sss_status = sss_key_store_get_key(pDynCtx->Mac.keyStore, &pDynCtx->Mac, mac_key, &mac_len, &mac_bit_len);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);
    sss_status = sss_key_store_get_key(pDynCtx->Rmac.keyStore, &pDynCtx->Rmac, rmac_key, &rmac_len, &rmac_bit_len);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);

    /* Store the session keys*/
    // WARNING: Simply writing the session keys to the file system is not a secure implementation.
    // it must not be used in products.
    writeStateToFile(RESUME_SCP03_FILE_PATH, pDynCtx, enc_key, enc_len, mac_key, mac_len, rmac_key, rmac_len);
cleanup:
    return sss_status;
}

sss_status_t exBoot_HOST_OS_RESUME()
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    char *portName;
    uint8_t enc_key[16]         = {0};
    size_t enc_len              = sizeof(enc_key);
    size_t enc_bit_len          = enc_len * 8;
    uint8_t mac_key[16]         = {0};
    size_t mac_len              = sizeof(mac_key);
    size_t mac_bit_len          = mac_len * 8;
    uint8_t rmac_key[16]        = {0};
    size_t rmac_len             = sizeof(rmac_key);
    size_t rmac_bit_len         = rmac_len * 8;
    SE_Connect_Ctx_t connectCtx = {0};
    NXSCP03_DynCtx_t dynCtx;
    sss_type_t hostsubsystem = kType_SSS_SubSystem_NONE;

#if AX_EMBEDDED
    portName = NULL;
    ex_sss_boot_direct();
#else
    sss_status = ex_sss_boot_connectstring(0, NULL, &portName);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);
#endif // AX_EMBEDDED

    /* Read the session keys from file*/
    readStateFromFile(RESUME_SCP03_FILE_PATH, &dynCtx, enc_key, enc_len, mac_key, mac_len, rmac_key, rmac_len);

    memset(&gex_sss_demo_boot_ctx, 0, sizeof(gex_sss_demo_boot_ctx));
    memset(&gex_sss_demo_boot_ctx.session, 0, sizeof(gex_sss_demo_boot_ctx.session));
    sss_se05x_session_t *pse05xSession = (sss_se05x_session_t *)&gex_sss_demo_boot_ctx.session;
    pSe05xSession_t se05xSession       = (pSe05xSession_t)(&pse05xSession->s_ctx);

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    hostsubsystem = kType_SSS_mbedTLS;
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    hostsubsystem = kType_SSS_OpenSSL;
#elif SSS_HAVE_HOSTCRYPTO_USER
    hostsubsystem = kType_SSS_Software;
#endif

    sss_status =
        sss_host_session_open(&gex_sss_demo_boot_ctx.host_session, hostsubsystem, 0, kSSS_ConnectionType_Plain, NULL);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_session_open failed");
        goto cleanup;
    }
    else {
        LOG_I("sss_host_session_open Successful");
    }
    sss_status = sss_host_key_store_context_init(&gex_sss_demo_boot_ctx.host_ks, &gex_sss_demo_boot_ctx.host_session);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_key_store_context_init failed");
        goto cleanup;
    }
    else {
        LOG_I("sss_host_key_store_context_init Successful");
    }
    sss_status = sss_host_key_store_allocate(&gex_sss_demo_boot_ctx.host_ks, __LINE__);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_host_key_store_allocate failed");
        goto cleanup;
    }
    else {
        LOG_I("sss_host_key_store_allocate Successful");
    }

    /* Note: In the session open for the session resume, the application should not select the applet.
    Else all the applied session keys will be invalid and have to recreate the platformscp session*/
    connectCtx.skip_select_applet = 1;
    connectCtx.sessionResume      = 1;
    connectCtx.auth.authType      = kSSS_AuthType_None;
    connectCtx.portName           = portName;
#if defined(SMCOM_JRCP_V2)
    connectCtx.connType = kType_SE_Conn_Type_JRCP_V2;
#else
    connectCtx.connType = kType_SE_Conn_Type_T1oI2C;
#endif
    sss_status =
        sss_session_open(&gex_sss_demo_boot_ctx.session, kType_SSS_SE_SE05x, 0, kSSS_ConnectionType_Plain, &connectCtx);
    if (kStatus_SSS_Success != sss_status) {
        LOG_E("sss_session_open failed");
        goto cleanup;
    }
    else {
        LOG_W("Successful");
    }

    sss_object_t *pHostObject = NULL;
    pHostObject               = &dynCtx.Enc;

    /* Set the session keys*/
    sss_status = createAndStoreHostAesKey(pHostObject, enc_key, enc_len);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);

    pHostObject = &dynCtx.Mac;
    sss_status  = createAndStoreHostAesKey(pHostObject, mac_key, mac_len);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);

    pHostObject = &dynCtx.Rmac;
    sss_status  = createAndStoreHostAesKey(pHostObject, rmac_key, rmac_len);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);

    dynCtx.SecurityLevel       = (C_MAC | C_ENC | R_MAC | R_ENC);
    dynCtx.authType            = kSSS_AuthType_SCP03;
    se05xSession->pdynScp03Ctx = &dynCtx;
    se05xSession->fp_Transform = &se05x_Transform_scp;
    se05xSession->fp_DeCrypt   = &se05x_DeCrypt;
    se05xSession->hasSession   = 0;
    se05xSession->authType     = kSSS_AuthType_SCP03;

    /* Continue with OS*/
    sss_status = ex_sss_key_store_and_object_init(&gex_sss_demo_boot_ctx);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);

    sss_status = rsa_ex(&gex_sss_demo_boot_ctx);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);

cleanup:
    return sss_status;
}

sss_status_t exBoot_SIMULATED_CYCLE()
{
    sss_status_t sss_status = kStatus_SSS_Fail;

    /* BOOT LOADER, Session opens with platformSCP and store in file system*/
    sss_status = exBoot_BOOTLOADER_ROLE();
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);

    /* HOST OS RESUME,  Session keys are read from file system and continue with application*/
    sss_status = exBoot_HOST_OS_RESUME();
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == sss_status);

cleanup:
    return sss_status;
}

// WARNING: Simply writing the session keys to the file system is not a secure implementation.
// it must not be used in products.
static U8 writeStateToFile(char *szFilename,
    NXSCP03_DynCtx_t *DynCtx,
    uint8_t *enc,
    size_t enc_len,
    uint8_t *mac,
    size_t mac_len,
    uint8_t *rmac,
    size_t rmac_len)
{
    U8 result = 1;
#ifdef FTR_FILE_SYSTEM
    FILE *fHandle = NULL;

    fHandle = fopen(szFilename, "wb");

    if (fHandle == NULL) {
        sm_printf(DBGOUT, "Failed to open file %s for writing\r\n", szFilename);
        return 0;
    }

    LOG_W(
        "Simply writing the session keys to the file system is not a secure implementation. It must not be used in "
        "products !!!...");
    fwrite((const void *)enc, enc_len, 1, fHandle);
    fwrite((const void *)mac, mac_len, 1, fHandle);
    fwrite((const void *)rmac, rmac_len, 1, fHandle);
    fwrite((const void *)DynCtx->MCV, 16, 1, fHandle);
    fwrite((const void *)DynCtx->cCounter, 16, 1, fHandle);
    fclose(fHandle);
#endif
    return result;
}

static U8 readStateFromFile(char *szFilename,
    NXSCP03_DynCtx_t *DynCtx,
    uint8_t *enc,
    size_t enc_len,
    uint8_t *mac,
    size_t mac_len,
    uint8_t *rmac,
    size_t rmac_len)
{
    U8 result = 1;
#ifdef FTR_FILE_SYSTEM
    FILE *fHandle = NULL;

    fHandle = fopen(szFilename, "rb");

    if (fHandle == NULL) {
        sm_printf(DBGOUT, "Failed to open file %s for reading", szFilename);
        return 0;
    }

    fread((void *)enc, enc_len, 1, fHandle);
    fread((void *)mac, mac_len, 1, fHandle);
    fread((void *)rmac, rmac_len, 1, fHandle);
    fread((void *)DynCtx->MCV, 16, 1, fHandle);
    fread((void *)DynCtx->cCounter, 16, 1, fHandle);
    fclose(fHandle);
#endif
    return result;
}

static sss_status_t createAndStoreHostAesKey(sss_object_t *pHostObject, uint8_t *key, size_t size)
{
    sss_status_t sss_status = kStatus_SSS_Fail;

    sss_status = sss_host_key_object_init(pHostObject, &gex_sss_demo_boot_ctx.host_ks);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == sss_status);

    sss_status = sss_host_key_object_allocate_handle(
        pHostObject, __LINE__, kSSS_KeyPart_Default, kSSS_CipherType_AES, 16, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == sss_status);

    sss_status = sss_key_store_set_key(pHostObject->keyStore, pHostObject, key, size, size * 8, NULL, 0);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == sss_status);

exit:
    return sss_status;
}

void printUsage()
{
    LOG_E("Unsupported Operation. Choose from: SKIP_EXAMPLE, SIMULATED_CYCLE, BOOTLOADER_ROLE or HOST_OS_RESUME");
    LOG_I("SKIP_EXAMPLE: Skip boot example");
    LOG_I("SIMULATED_CYCLE: Do full boot cycle (Bootloader/OS combined)");
    LOG_I("BOOTLOADER_ROLE: Mimick behaviour of bootloader only (store session state on filesystem)");
    LOG_I("HOST_OS_RESUME: Mimick behaviour of Host OS only (retrieve session state from filesystem)");
}

int main(int argc, const char *argv[])
{
    int ret                 = 0;
    sss_status_t sss_status = kStatus_SSS_Fail;

    if (argc >= 2) {
        boot_mode = argv[1];
        if (0 == strcmp(boot_mode, "SKIP_EXAMPLE")) {
            sss_status = exBoot_SKIP_EXAMPLE();
        }
        else if (0 == strcmp(boot_mode, "SIMULATED_CYCLE")) {
            sss_status = exBoot_SIMULATED_CYCLE();
        }
        else if (0 == strcmp(boot_mode, "BOOTLOADER_ROLE")) {
            sss_status = exBoot_BOOTLOADER_ROLE();
        }
        else if (0 == strcmp(boot_mode, "HOST_OS_RESUME")) {
            sss_status = exBoot_HOST_OS_RESUME();
        }
        else {
            printUsage();
        }
    }
    else {
        printUsage();
    }

exit:
    if (kStatus_SSS_Success != sss_status) {
        ret = -1;
    }
    return ret;
}