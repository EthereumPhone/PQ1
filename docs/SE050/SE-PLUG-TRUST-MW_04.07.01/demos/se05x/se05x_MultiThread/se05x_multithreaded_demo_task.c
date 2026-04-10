/* Copyright 2020,2025 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 * */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <stdio.h>
#include <nxLog_App.h>
#include <string.h>

#include <sm_timer.h>
#include "se05x_multithreaded_demo.h"
#include "se05x_APDU.h"

#if defined(USE_RTOS) && (USE_RTOS == 1)
#include "FreeRTOS.h"
#endif

#define USER1 0x00
#define USER2 0x10
#define KEY_BIT_LENGTH 256

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
demoCtx_t guser_session_1;
demoCtx_t guser_session_2;
demoCtx_t gbaseSession;
sss_tunnel_t gtunnel_ctx;
extern const char *portName;

uint8_t task1_status = false;
uint8_t task2_status = false;

#if defined(USE_RTOS) && (USE_RTOS == 1)
uint8_t setup_done = false;
#endif

sss_status_t userSessionOpen(demoCtx_t *Testctx, uint32_t userId);
sss_status_t baseSessionOpen(demoCtx_t *Testctx);
void *Sign_Verify_eccsecp256r1_sha224_guser1(void *ptr);
void *Sign_Verify_eccsecp256r1_sha512_user2(void *ptr);
/*******************************************************************************
 * Code
 ******************************************************************************/

void setup_se05x(void)
{
    sss_status_t status = kStatus_SSS_Fail;
    memset((void *)&guser_session_1, 0, sizeof(guser_session_1));
    memset((void *)&guser_session_2, 0, sizeof(guser_session_2));
    sss_se05x_session_t *pCtx = (sss_se05x_session_t *)&guser_session_1.session;

    status = baseSessionOpen(&gbaseSession);
    if (kStatus_SSS_Success != status) {
        LOG_I("baseSessionOpen Failed");
        goto exit;
    }

    status = sss_tunnel_context_init(&gtunnel_ctx, &gbaseSession.session /* session */);
    if (kStatus_SSS_Success != status) {
        LOG_I("sss_tunnel_context_init Failed");
        goto exit;
    }

    status = userSessionOpen(&guser_session_1, USER1);
    if (kStatus_SSS_Success != status) {
        LOG_I("userSessionOpen 1 Failed");
        goto exit;
    }

    status = userSessionOpen(&guser_session_2, USER2);
    if (kStatus_SSS_Success != status) {
        LOG_I("userSessionOpen 2 Failed");
        goto exit;
    }

    Se05x_API_DeleteAll_Iterative(&(pCtx->s_ctx));

exit:
#if defined(USE_RTOS) && (USE_RTOS == 1)
    setup_done = true;
    vTaskDelete(NULL);
#else
    if (kStatus_SSS_Success != status) {
        while (1)
            ; /*Loop Forever */
    }
#endif

    return;
}

void cleanup_se05x()
{
#if defined(USE_RTOS) && (USE_RTOS == 1)
    while (!(task1_status && task2_status)) {
        sm_sleep(2);
    }
#endif
    sss_session_close(&guser_session_1.session);
    sss_session_close(&guser_session_2.session);
    sss_session_close(&gbaseSession.session);
    sss_tunnel_context_free(&gtunnel_ctx);

    if ((task1_status == task2_status) == 1) {
        LOG_I("SE05x Multithreaded Example Success");
    }

    LOG_I("ex_sss Finished");
#if defined(USE_RTOS) && (USE_RTOS == 1)
    vTaskDelete(NULL);
#endif
}

#if defined(USE_RTOS) && (USE_RTOS == 1)
void Sign_Verify_eccsecp256r1_sha224_guser1_rtos(void *ptr)
{
    while (!setup_done) {
        sm_sleep(2);
    }

    Sign_Verify_eccsecp256r1_sha224_guser1(ptr);
    vTaskDelete(NULL);
}

void Sign_Verify_eccsecp256r1_sha512_user2_rtos(void *ptr)
{
    while (!setup_done) {
        sm_sleep(2);
    }
    Sign_Verify_eccsecp256r1_sha512_user2(ptr);
    vTaskDelete(NULL);
}
#endif

void *Sign_Verify_eccsecp256r1_sha224_guser1(void *ptr)
{
    sss_status_t status;
    uint8_t digest[28]                = "Hello World";
    size_t digestLen                  = sizeof(digest);
    uint8_t signature[KEY_BIT_LENGTH] = {0};
    size_t signatureLen               = sizeof(signature);
    uint8_t pbKey[100]                = {0};
    size_t pbKeyBitLen                = 0;
    size_t pbKeyByteLen               = sizeof(pbKey);
    sss_asymmetric_t asymVerifyCtx;
    sss_algorithm_t algorithm;
    sss_mode_t mode;
    uint32_t keyId   = MAKE_TEST_ID(__LINE__);
    size_t keylen    = KEY_BIT_LENGTH / 8;
    uint32_t pbkeyId = MAKE_TEST_ID(__LINE__);

    demoCtx_t *pCtx = (demoCtx_t *)ptr;

    algorithm = kAlgorithm_SSS_SHA224;
    mode      = kMode_SSS_Sign;

    status = sss_key_object_allocate_handle(
        &pCtx->key, keyId, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, keylen, kKeyObject_Mode_Persistent);
    if (kStatus_SSS_Success != status) {
        LOG_I("key_object_allocate_handle Failed user 1!!!");
        task1_status = 0x10;
        goto exit;
    }

    status = sss_asymmetric_context_init(&pCtx->asymm, &pCtx->session, &pCtx->key, algorithm, mode);
    if (kStatus_SSS_Success != status) {
        LOG_I("Asymmetric Init Context Failed user 1!!!");
        task1_status = 0x10;
        goto exit;
    }

    status = sss_key_store_generate_key(&pCtx->ks, &pCtx->key, KEY_BIT_LENGTH, 0);
    if (kStatus_SSS_Success != status) {
        LOG_I("Key Store Generate Key Failed user 1!!!");
        task1_status = 0x10;
        goto exit;
    }
    else {
        LOG_I("Key Store Generate Key success user 1!!!");
    }

    sm_sleep(2);
    status = sss_asymmetric_sign_digest(&pCtx->asymm, digest, digestLen, signature, &signatureLen);
    if (kStatus_SSS_Success != status) {
        LOG_I("Signing Failed user 1!!!");
        task1_status = 0x10;
        goto exit;
    }
    else {
        LOG_I("sss_asymmetric_sign_digest success user 1");
    }
    sm_sleep(2);
    status = sss_key_store_get_key(&pCtx->ks, &pCtx->key, pbKey, &pbKeyByteLen, &pbKeyBitLen);
    if (kStatus_SSS_Success != status) {
        LOG_I(" Get Public Key Failed user 1!!!");
        task1_status = 0x10;
        goto exit;
    }

    status = sss_key_object_init(&pCtx->public_key, &pCtx->ks);
    if (kStatus_SSS_Success != status) {
        LOG_I("sss_key_object_init for derived key Failed user 1");
        task1_status = 0x10;
        goto exit;
    }

    status = sss_key_object_allocate_handle(&pCtx->public_key,
        pbkeyId,
        kSSS_KeyPart_Public,
        kSSS_CipherType_EC_NIST_P,
        pbKeyByteLen,
        kKeyObject_Mode_Persistent);
    if (kStatus_SSS_Success != status) {
        LOG_I("sss_key_object_allocate_handle Failed user 1");
        task1_status = 0x10;
        goto exit;
    }

    status = sss_key_store_set_key(&pCtx->ks, &pCtx->public_key, pbKey, pbKeyByteLen, KEY_BIT_LENGTH, NULL, 0);
    if (kStatus_SSS_Success != status) {
        LOG_I("sss_key_store_set_key Failed user 1!!!");
        task1_status = 0x10;
        goto exit;
    }
    else {
        LOG_I("Set public key success user 1");
    }
    sm_sleep(2);
    status =
        sss_asymmetric_context_init(&asymVerifyCtx, &pCtx->session, &pCtx->public_key, algorithm, kMode_SSS_Verify);
    if (status != kStatus_SSS_Success) {
        LOG_I("sss_asymmetric_context_init Failed user 1!!!");
        task1_status = 0x10;
        goto exit;
    }

    status = sss_asymmetric_verify_digest(&asymVerifyCtx, digest, digestLen, signature, signatureLen);
    if (kStatus_SSS_Success != status) {
        LOG_I("Verification Failed user 1!!!");
        task1_status = 0x10;
        goto exit;
    }
    else {
        LOG_I("sss_asymmetric_verify_digest success user 1");
    }
    sss_asymmetric_context_free(&asymVerifyCtx);
    LOG_I("Done User 1");
    task1_status = 1;

exit:
    return NULL;
}

void *Sign_Verify_eccsecp256r1_sha512_user2(void *ptr)
{
    sss_status_t status;
    uint8_t digest[64]                = "Hello World";
    size_t digestLen                  = sizeof(digest);
    uint8_t signature[KEY_BIT_LENGTH] = {0};
    size_t signatureLen               = sizeof(signature);
    uint8_t pbKey[100]                = {0};
    size_t pbKeyBitLen                = 0;
    size_t pbKeyByteLen               = sizeof(pbKey);
    sss_asymmetric_t asymVerifyCtx;
    sss_algorithm_t algorithm;
    sss_mode_t mode;
    uint32_t keyId   = MAKE_TEST_ID(__LINE__);
    size_t keylen    = KEY_BIT_LENGTH / 8;
    uint32_t pbkeyId = MAKE_TEST_ID(__LINE__);

    demoCtx_t *pCtx = (demoCtx_t *)ptr;

    algorithm = kAlgorithm_SSS_SHA512;
    mode      = kMode_SSS_Sign;

    status = sss_key_object_allocate_handle(
        &pCtx->key, keyId, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, keylen, kKeyObject_Mode_Persistent);
    if (kStatus_SSS_Success != status) {
        LOG_I("key_object_allocate_handle Failed user 2!!!");
        task2_status = 0x10;
        goto exit;
    }

    status = sss_asymmetric_context_init(&pCtx->asymm, &pCtx->session, &pCtx->key, algorithm, mode);
    if (kStatus_SSS_Success != status) {
        LOG_I("Asymmetric Init Context Failed user 2!!!");
        task2_status = 0x10;
        goto exit;
    }

    status = sss_key_store_generate_key(&pCtx->ks, &pCtx->key, KEY_BIT_LENGTH, 0);
    if (kStatus_SSS_Success != status) {
        LOG_I("Key Store Generate Key Failed user 2!!!");
        task2_status = 0x10;
        goto exit;
    }
    else {
        LOG_I("Key Store Generate Key success user 2!!!");
    }
    sm_sleep(2);
    status = sss_asymmetric_sign_digest(&pCtx->asymm, digest, digestLen, signature, &signatureLen);
    if (kStatus_SSS_Success != status) {
        LOG_I("Signing Failed user 2!!!");
        task2_status = 0x10;
        goto exit;
    }
    else {
        LOG_I("sss_asymmetric_sign_digest success user 2");
    }

    sm_sleep(2);
    status = sss_key_store_get_key(&pCtx->ks, &pCtx->key, pbKey, &pbKeyByteLen, &pbKeyBitLen);
    if (kStatus_SSS_Success != status) {
        LOG_I(" Get Public Key Failed user 2!!!");
        task2_status = 0x10;
        goto exit;
    }

    status = sss_key_object_init(&pCtx->public_key, &pCtx->ks);
    if (kStatus_SSS_Success != status) {
        LOG_I("sss_key_object_init for derived key Failed user 2");
        task2_status = 0x10;
        goto exit;
    }

    status = sss_key_object_allocate_handle(&pCtx->public_key,
        pbkeyId,
        kSSS_KeyPart_Public,
        kSSS_CipherType_EC_NIST_P,
        pbKeyByteLen,
        kKeyObject_Mode_Persistent);
    if (kStatus_SSS_Success != status) {
        LOG_I("sss_key_object_allocate_handle Failed user 2");
        task2_status = 0x10;
        goto exit;
    }

    status = sss_key_store_set_key(&pCtx->ks, &pCtx->public_key, pbKey, pbKeyByteLen, KEY_BIT_LENGTH, NULL, 0);
    if (kStatus_SSS_Success != status) {
        LOG_I(" sss_key_store_set_key Failed user 2!!!");
        task2_status = 0x10;
        goto exit;
    }
    else {
        LOG_I("Set public key success user 2");
    }
    sm_sleep(2);

    status =
        sss_asymmetric_context_init(&asymVerifyCtx, &pCtx->session, &pCtx->public_key, algorithm, kMode_SSS_Verify);
    if (status != kStatus_SSS_Success) {
        LOG_I("sss_asymmetric_context_init Failed user2!!!");
        task2_status = 0x10;
        goto exit;
    }

    status = sss_asymmetric_verify_digest(&asymVerifyCtx, digest, digestLen, signature, signatureLen);
    if (kStatus_SSS_Success != status) {
        LOG_I("Verification Failed!!!");
        task2_status = 0x10;
        goto exit;
    }
    else {
        LOG_I("sss_asymmetric_verify_digest success user 2");
    }
    sss_asymmetric_context_free(&asymVerifyCtx);

    LOG_I("Done User 2");
    task2_status = 1;

exit:
    return NULL;
}

sss_status_t baseSessionOpen(demoCtx_t *Testctx)
{
    sss_status_t status               = kStatus_SSS_Success;
    sss_type_t subsystem              = kType_SSS_SE_SE05x;
    sss_connection_type_t connectType = kSSS_ConnectionType_Plain;

#if SSS_HAVE_APPLET_SE05X_IOT
#if (defined(RJCT_VCOM) && (RJCT_VCOM == 1)) || (defined(SMCOM_JRCP_V1) && (SMCOM_JRCP_V1 == 1)) || \
    (defined(SMCOM_JRCP_V2) && (SMCOM_JRCP_V2 == 1)) || (defined(SCI2C) && (SCI2C == 1)) ||         \
    (defined(T1oI2C) && (T1oI2C == 1)) || defined(SMCOM_THREAD)
    SE_Connect_Ctx_t *pSessionCtxt = &Testctx->se05x_AuthCtx;
#endif
#endif /* SSS_HAVE_APPLET_SE05X_IOT */

#if defined(SMCOM_JRCP_V1)
    pSessionCtxt->connType = kType_SE_Conn_Type_JRCP_V1;
    pSessionCtxt->portName = portName;
#endif
#if defined(SMCOM_JRCP_V2)
    pSessionCtxt->connType = kType_SE_Conn_Type_JRCP_V2;
    pSessionCtxt->portName = portName;
#endif
#if defined(RJCT_VCOM)
    pSessionCtxt->connType = kType_SE_Conn_Type_VCOM;
    pSessionCtxt->portName = portName;
#endif
#if defined(SCI2C)
    pSessionCtxt->connType = kType_SE_Conn_Type_SCII2C;
    pSessionCtxt->portName = NULL;
#endif
#if defined(T1oI2C)
    pSessionCtxt->connType = kType_SE_Conn_Type_T1oI2C;
    pSessionCtxt->portName = NULL;
#endif

    if (subsystem == kType_SSS_SE_SE05x) {
#if (SSS_HAVE_SE05X_AUTH_NONE) || (SSS_HAVE_SE05X_AUTH_USERID) || (SSS_HAVE_SE05X_AUTH_ECKEY) || \
    (SSS_HAVE_SE05X_AUTH_AESKEY)
        pSessionCtxt->auth.authType = kSSS_AuthType_None;
        connectType                 = kSSS_ConnectionType_Plain;
#elif (SSS_HAVE_SE05X_AUTH_PLATFSCP03) || (SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03) || \
    (SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03) || (SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03)
        pSessionCtxt->auth.authType = kSSS_AuthType_SCP03;
        //status = HostCrypto_CheckAuthMech_StoreAuthObj(pSessionCtxt);
        status = ex_sss_se05x_prepare_host_keys(
            &Testctx->hostSession, &Testctx->hostKs, pSessionCtxt, &Testctx->tst_se05x_auth, __LINE__);
        if (status != kStatus_SSS_Success) {
            printf("Storing Auth SCPO3 object keys failed...");
            return status;
        }
        connectType = kSSS_ConnectionType_Encrypted;
#endif
    }

    status = sss_session_open(&Testctx->session, subsystem, 0, connectType, pSessionCtxt);

    if (kStatus_SSS_Success != status) {
        LOG_I("Open Session Failed!!!");
        return status;
    }

    status = sss_key_store_context_init(&Testctx->ks, &Testctx->session);
    if (kStatus_SSS_Success != status) {
        LOG_I("sss_key_store_context_init Failed!!!");
        return status;
    }

    status = sss_key_object_init(&Testctx->key, &Testctx->ks);
    if (kStatus_SSS_Success != status) {
        LOG_I("sss_key_object_init Failed!!!");
        return status;
    }
    return status;
}

sss_status_t userSessionOpen(demoCtx_t *Testctx, uint32_t userId)
{
    AX_UNUSED_ARG(userId);
    sss_status_t status                = kStatus_SSS_Success;
    SE_Connect_Ctx_t *pUserConnectCtxt = &Testctx->se05x_ChannelCtx;
    pUserConnectCtxt->connType         = kType_SE_Conn_Type_Channel;
    Testctx->tunnel_ctx                = &gtunnel_ctx;
    pUserConnectCtxt->tunnelCtx        = Testctx->tunnel_ctx;
    sss_connection_type_t connectType  = kSSS_ConnectionType_Plain;

#if (SSS_HAVE_SE05X_AUTH_NONE) || (SSS_HAVE_SE05X_AUTH_PLATFSCP03)
    connectType                     = kSSS_ConnectionType_Plain;
    pUserConnectCtxt->auth.authType = kSSS_AuthType_None;
    status = sss_session_open(&Testctx->session, kType_SSS_SE_SE05x, 0, connectType, pUserConnectCtxt);

#elif (SSS_HAVE_SE05X_AUTH_USERID) || (SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03)
    connectType                     = kSSS_ConnectionType_Password;
    pUserConnectCtxt->auth.authType = kSSS_AuthType_ID;
    status                          = ex_sss_se05x_prepare_host_keys(&Testctx->hostSession,
        &Testctx->hostKs,
        pUserConnectCtxt,
        &Testctx->tst_se05x_auth,
        kEX_SSS_ObjID_UserID_Auth + userId);
    if (status != kStatus_SSS_Success) {
        printf("Storing Auth UserID object failed...");
        return status;
    }
    status = sss_session_open(
        &Testctx->session, kType_SSS_SE_SE05x, kEX_SSS_ObjID_UserID_Auth + userId, connectType, pUserConnectCtxt);

#elif (SSS_HAVE_SE05X_AUTH_AESKEY) || (SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03)
    connectType                     = kSSS_ConnectionType_Encrypted;
    pUserConnectCtxt->auth.authType = kSSS_AuthType_AESKey;
    status                          = ex_sss_se05x_prepare_host_keys(&Testctx->hostSession,
        &Testctx->hostKs,
        pUserConnectCtxt,
        &Testctx->tst_se05x_auth,
        kEX_SSS_ObjID_APPLETSCP03_Auth + userId);
    if (status != kStatus_SSS_Success) {
        printf("Storing Auth AESKey object failed...");
        return status;
    }
    status = sss_session_open(
        &Testctx->session, kType_SSS_SE_SE05x, kEX_SSS_ObjID_APPLETSCP03_Auth + userId, connectType, pUserConnectCtxt);

#elif (SSS_HAVE_SE05X_AUTH_ECKEY) || (SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03)
    connectType                     = kSSS_ConnectionType_Encrypted;
    pUserConnectCtxt->auth.authType = kSSS_AuthType_ECKey;
    status                          = ex_sss_se05x_prepare_host_keys(&Testctx->hostSession,
        &Testctx->hostKs,
        pUserConnectCtxt,
        &Testctx->tst_se05x_auth,
        kEX_SSS_objID_ECKEY_Auth + userId);
    if (status != kStatus_SSS_Success) {
        printf("Storing Auth UserID object failed...");
        return status;
    }
    status = sss_session_open(
        &Testctx->session, kType_SSS_SE_SE05x, kEX_SSS_objID_ECKEY_Auth + userId, connectType, pUserConnectCtxt);

#else
    LOG_W("Invalid Auth Type!!!")
#endif

    if (kStatus_SSS_Success != status) {
        LOG_I("Open Session Failed!!!");
        return status;
    }

    status = sss_key_store_context_init(&Testctx->ks, &Testctx->session);
    if (kStatus_SSS_Success != status) {
        LOG_I("sss_key_store_context_init Failed!!!");
        return status;
    }

    status = sss_key_object_init(&Testctx->key, &Testctx->ks);
    if (kStatus_SSS_Success != status) {
        LOG_I("sss_key_object_init Failed!!!");
        return status;
    }
    return status;
}
