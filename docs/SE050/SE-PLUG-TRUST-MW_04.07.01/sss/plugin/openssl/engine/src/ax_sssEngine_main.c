/**
 * @file ax_sssEngine_main.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Engine for NXP Embedded Secure Element over SSS API's
 *
 * The following operations are supported by this engine:
 * - Random number generation
 * - ECC sign
 * - ECC verify
 * - ECDH compute_key
 *
 * When dealing with an EC key argument whose a public key is used:
 * - In case the key is a 'reference key' -> use the referenced public key
 * - In case the above does not apply; at compile time one can choose between two
 *   strategies:
 *   (1) return a fail
 *   (2) delegate the operation to the OpenSSL SW implementation
 *
 * When dealing with an EC key argument whose private key is used:
 * - In case the key is a 'reference key' -> use the referenced private key
 * - In case the above does not apply; at compile time one can choose between two
 *   strategies:
 *   (1) return a fail
 *   (2) delegate the operation to the OpenSSL SW implementation
 *
 * @note
 *   Compatible with:
 *   - OpenSSL 1.0.2
 *   - OpenSSL 1.1.0
 *
 */

/*
 * This file contains source code form OpenSSL distribution that is covered
 * by the LICENSE-OpenSSL file to be found in the root of this source code
 * distribution tree.
 */

#include <openssl/bn.h>

#include "ax_embSeEngine.h"
// #include <openssl/conf.h>
#include <stdlib.h>
#ifdef __gnu_linux__
#include <malloc.h>
#endif
#include <nxEnsure.h>
#include <nxLog_App.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "ax_embSeEngine_Internal.h"

#if SSS_HAVE_APPLET_SE05X_IOT
#include <se05x_APDU.h>
#endif
#include <ex_sss.h>

#include "ex_sss_ports.h"
#include "sm_printf.h"

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
#ifdef OPENSSL_NO_DYNAMIC_ENGINE
#undef OPENSSL_NO_DYNAMIC_ENGINE
#endif
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
#if SSS_HAVE_ECC || (SSS_HAVE_APPLET_NONE && (SSS_HAVE_HOSTCRYPTO_OPENSSL || SSS_HAVE_HOSTCRYPTO_MBEDTLS))
int setup_ec_key_method(void);
int setup_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pkey_meth, const int **nid_list, int nid);
#endif
#if SSS_HAVE_RSA || (SSS_HAVE_APPLET_NONE && (SSS_HAVE_HOSTCRYPTO_OPENSSL || SSS_HAVE_HOSTCRYPTO_MBEDTLS))
int setup_rsa_key_method(void);
#endif
#endif

/* Logging related defines */
#define EMBSE_MAX_PRINT_BUF_SIZE (511)

ex_sss_boot_ctx_t gOpenSSLEngineCtx;
ex_sss_boot_ctx_t *gpCtx = &gOpenSSLEngineCtx;

// Adjust to the required default log level.
static int EMBSE_LogControl = (LOG_ERR_ON | LOG_DBG_ON | LOG_FLOW_ON); // Full log
// static int EMBSE_LogControl = (LOG_ERR_ON);  // Only Errors

// Locally used utility functions
static sss_status_t engineSessionOpen();

/* engine name */
static const char *embSe_id = OPENSSL_ENGINE_EMBSE_ID;
static const char *embSe_name = "se hardware engine support";

const int Version1 = 1; //-> Release Version1.Version2.Version3
const int Version2 = 0;
const int Version3 = 5;

#ifdef AX_ENGINE_SUPPORTS_RAND
extern RAND_METHOD EmbSe_RAND;
#endif

#if SSS_HAVE_ECC || (SSS_HAVE_APPLET_NONE && (SSS_HAVE_HOSTCRYPTO_OPENSSL || SSS_HAVE_HOSTCRYPTO_MBEDTLS))
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
extern ECDSA_METHOD EmbSe_ECDSA;
extern ECDH_METHOD EmbSe_ECDH;
#else
extern EC_KEY_METHOD *EmbSe_EC;
#endif
#endif

#if SSS_HAVE_RSA || (SSS_HAVE_APPLET_NONE && (SSS_HAVE_HOSTCRYPTO_OPENSSL || SSS_HAVE_HOSTCRYPTO_MBEDTLS))
#if !(SSS_HAVE_A71XX)
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
extern RSA_METHOD EmbSe_RSA;
#else
extern RSA_METHOD *EmbSe_RSA;
#endif
extern const RSA_METHOD *EmbSe_default_RSA;
#endif
#endif

#ifndef OPENSSL_NO_HW

/* The definitions for control commands specific to this engine */
#define EMBSE_LOG_LEVEL ENGINE_CMD_BASE
#define EMBSE_CMD_OPEN_LINK (ENGINE_CMD_BASE + 1)
#define EMBSE_CMD_CLOSE_LINK (ENGINE_CMD_BASE + 2)
#define EMBSE_CMD_LOAD (ENGINE_CMD_BASE + 3)
#define EMBSE_CMD_MODULE_PATH (ENGINE_CMD_BASE + 4)
static const ENGINE_CMD_DEFN embSe_cmd_defns[] = {
    {EMBSE_LOG_LEVEL,
        "LOG_LEVEL",
        "Specifies the Log level (Error=0x04; Debug=0x02; Flow=0x01; Or'd combinations possible)",
        ENGINE_CMD_FLAG_NUMERIC},
    {EMBSE_CMD_OPEN_LINK, "OPEN_LINK", "Open link to SE - engine already loaded", ENGINE_CMD_FLAG_NO_INPUT},
    {EMBSE_CMD_CLOSE_LINK, "CLOSE_LINK", "Close link to SE - engine remains loaded", ENGINE_CMD_FLAG_NO_INPUT},
    {EMBSE_CMD_LOAD, "LOAD", "LOAD", ENGINE_CMD_FLAG_STRING},
    {EMBSE_CMD_MODULE_PATH, "MODULE_PATH", "MODULE_PATH", ENGINE_CMD_FLAG_STRING},

    {0, NULL, NULL, 0}};

/* Engine API's for initialization and cleanup */
static int EmbSe_Destroy(ENGINE *e)
{
    AX_UNUSED_ARG(e);
    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Destroy(): Entry\n");
    return 1;
}

/****** ENGINE API's *******/
static int EmbSe_Init(ENGINE *e)
{
    sss_status_t status;

    AX_UNUSED_ARG(e);
    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Init(): Entry\n");

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL);
#endif

    status = engineSessionOpen();
    if (status != kStatus_SSS_Success) {
        EmbSe_Print(LOG_FLOW_ON, "EmbSe_Init(): Failed to initialize\n");
        return -1;
    }
    EmbSe_Print(LOG_FLOW_ON, "Version: %d.%d.%d\n", Version1, Version2, Version3);
#ifdef __gnu_linux__
    mallopt(M_MMAP_THRESHOLD, 125);
#endif
    /* Engine is ready to use */
    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Init(): Exit\n");
    return 1;
}

static int EmbSe_Finish(ENGINE *e)
{
    AX_UNUSED_ARG(e);
    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Finish(): Entry\n");
    sss_key_store_context_free(&gpCtx->ks);
    sss_session_close(&gpCtx->session);
    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Finish(): Exit\n");
    return 1;
}

static int EmbSe_Ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    AX_UNUSED_ARG(e);
    AX_UNUSED_ARG(p);
    AX_UNUSED_ARG(f);
    /* Values of String Variables are received in p, while values of Numeric ones are in i */
    switch (cmd) {
    case EMBSE_LOG_LEVEL:
        EmbSe_Print(LOG_FLOW_ON, "Control Command EMBSE_LOG_LEVEL; requested log level = %ld\n", i);
        if (i < 0x08) {
            EMBSE_LogControl = i & 0x07;
        }
        else {
            EmbSe_Print(LOG_DBG_ON, "Invalid Control Command value for EMBSE_LOG_LEVEL\n");
        }
        return 1;
    case EMBSE_CMD_OPEN_LINK:
        EmbSe_Print(LOG_FLOW_ON, "Control Command EMBSE_CMD_OPEN_LINK (Entry)\n");
        EmbSe_Init(e);
        EmbSe_Print(LOG_FLOW_ON, "Control Command EMBSE_CMD_OPEN_LINK (Exit)\n");
        return 1;
    case EMBSE_CMD_CLOSE_LINK:
        EmbSe_Print(LOG_FLOW_ON, "Control Command EMBSE_CMD_CLOSE_LINK (Entry)\n");
        EmbSe_Finish(e);
        EmbSe_Print(LOG_FLOW_ON, "Control Command EMBSE_CMD_CLOSE_LINK (Exit)\n");
        return 1;
    case EMBSE_CMD_LOAD:
    case EMBSE_CMD_MODULE_PATH:
        return 1;
    default:
        EmbSe_Print(LOG_ERR_ON, "Control command %d not implemented.\n", cmd);
        return 0;
    }
}

/* This internal function is used by ENGINE_e2se() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE *e)
{
#if SSS_HAVE_RSA || (SSS_HAVE_APPLET_NONE && (SSS_HAVE_HOSTCRYPTO_OPENSSL || SSS_HAVE_HOSTCRYPTO_MBEDTLS))
#if !(SSS_HAVE_A71XX)
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    EmbSe_default_RSA = RSA_PKCS1_SSLeay();
    if (EmbSe_default_RSA != NULL) {
        EmbSe_RSA.bn_mod_exp = EmbSe_default_RSA->bn_mod_exp;
        EmbSe_RSA.rsa_mod_exp = EmbSe_default_RSA->rsa_mod_exp;
        EmbSe_RSA.init = EmbSe_default_RSA->init;
        EmbSe_RSA.rsa_keygen = EmbSe_default_RSA->rsa_keygen;
    }
#else
    EmbSe_default_RSA = RSA_PKCS1_OpenSSL();
#endif
#endif
#endif

    if (0 || !ENGINE_set_id(e, embSe_id) || !ENGINE_set_name(e, embSe_name) ||
        !ENGINE_set_destroy_function(e, &EmbSe_Destroy) || !ENGINE_set_init_function(e, &EmbSe_Init) ||
        !ENGINE_set_finish_function(e, &EmbSe_Finish) || !ENGINE_set_ctrl_function(e, &EmbSe_Ctrl) ||
        !ENGINE_set_cmd_defns(e, &embSe_cmd_defns[0])
#ifdef AX_ENGINE_SUPPORTS_RAND
        || !ENGINE_set_RAND(e, &EmbSe_RAND)
#endif

#if SSS_HAVE_RSA || (SSS_HAVE_APPLET_NONE && (SSS_HAVE_HOSTCRYPTO_OPENSSL || SSS_HAVE_HOSTCRYPTO_MBEDTLS))
#if !(SSS_HAVE_A71XX)
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        || !ENGINE_set_RSA(e, &EmbSe_RSA)
#else
        || !setup_rsa_key_method() || !ENGINE_set_RSA(e, EmbSe_RSA)
#endif
#endif
#endif

#if SSS_HAVE_ECC || (SSS_HAVE_APPLET_NONE && (SSS_HAVE_HOSTCRYPTO_OPENSSL || SSS_HAVE_HOSTCRYPTO_MBEDTLS))
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        || !ENGINE_set_ECDSA(e, &EmbSe_ECDSA) || !ENGINE_set_ECDH(e, &EmbSe_ECDH)
#else
        || !setup_ec_key_method() || !setup_load_priv_key_method(e) || !ENGINE_set_EC(e, EmbSe_EC) ||
        !ENGINE_set_pkey_meths(e, setup_pkey_methods)
#endif
#endif
    ) {
        return 0;
    }

    return 1;
}

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *EngineEmbSe(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret) {
        return NULL;
    }
    if (!bind_helper(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void EngineEmbSe_Load(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = EngineEmbSe();
    if (!toadd) {
        return;
    }
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
    EmbSe_Print(LOG_FLOW_ON, "EngineEmbSe_Load succeeded!\n");
}
#else
/* This stuff is needed if this ENGINE is being compiled into a self-contained
 * shared-library. */
static int bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, embSe_id) != 0)) {
        return 0;
    }
    if (!bind_helper(e)) {
        return 0;
    }
    return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)

#endif /* OPENSSL_NO_DYNAMIC_ENGINE */

#else /* !OPENSSL_NO_HW */
#error "********** DO NOT BUILD OPENSSSL ENGINE WITH OPENSSL_NO_HW DEFINED **********"
#endif /* !OPENSSL_NO_HW */

// EmbSe RSA API's
/* Size of an SSL signature: MD5+SHA1 */
#define SSL_SIG_LENGTH 36

/*  Support functions */
/**********************/

static sss_status_t engineSessionOpen()
{
    sss_status_t status = kStatus_SSS_Fail;
    char *portName;

    status = ex_sss_boot_connectstring(0, NULL, &portName);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = ex_sss_boot_open(&gOpenSSLEngineCtx, portName);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = ex_sss_key_store_and_object_init(&gOpenSSLEngineCtx);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

cleanup:
#if defined(_MSC_VER)
    if (portName) {
        char *dummy_portName = NULL;
        size_t dummy_sz = 0;
        _dupenv_s(&dummy_portName, &dummy_sz, EX_SSS_BOOT_SSS_PORT);
        if (NULL != dummy_portName) {
            free(dummy_portName);
            free(portName);
        }
    }
#endif // _MSC_VER

    return status;
}

void EmbSe_Print(int flag, const char *format, ...)
{
    unsigned char buffer[EMBSE_MAX_PRINT_BUF_SIZE + 1];
    int active = 0;
    va_list vArgs;

    if ((flag & EMBSE_LogControl & LOG_FLOW_MASK) == LOG_FLOW_ON) {
        active = 1;
        printf("ssse-flw: ");
    }
    else if ((flag & EMBSE_LogControl & LOG_DBG_MASK) == LOG_DBG_ON) {
        active = 1;
        printf("ssse-dbg: ");
    }
    else if ((flag & EMBSE_LogControl & LOG_ERR_MASK) == LOG_ERR_ON) {
        active = 1;
        printf("ssse-err: ");
    }

    if (active == 1) {
        va_start(vArgs, format);
        if (vsnprintf((char *)buffer, EMBSE_MAX_PRINT_BUF_SIZE, (char const *)format, vArgs) < 0) {
            return;
        }
        va_end(vArgs);
        printf("%s", buffer);
    }
    return;
}

void EmbSe_PrintPayload(int flag, const U8 *pPayload, U16 nLength, const char *title)
{
    U16 i;
    int active = 0;

    if ((flag & EMBSE_LogControl & LOG_FLOW_MASK) == LOG_FLOW_ON) {
        active = 1;
        printf("ssse-flw: %s", title);
    }
    else if ((flag & EMBSE_LogControl & LOG_DBG_MASK) == LOG_DBG_ON) {
        active = 1;
        printf("ssse-dbg: %s", title);
    }
    else if ((flag & EMBSE_LogControl & LOG_ERR_MASK) == LOG_ERR_ON) {
        active = 1;
        printf("ssse-err: %s", title);
    }

    if (active == 1) {
        for (i = 0; i < nLength; i++) {
            if (i % 16 == 0) {
                printf("\n");
            }
            printf("%02X ", pPayload[i]);
        }
        printf("\n");
    }
}
