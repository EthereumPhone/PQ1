
/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2022-2025 NXP
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * OpenSSL Provider for NXP Embedded Secure Element over SSS API's
 *
 * The following operations are supported by this provider:
 * - Random number generation
 * - ECC sign
 * - ECC verify
 * - ECDH compute_key
 * - ECC CSR
 * - RSA sign
 * - RSA verify
 * - RSA encrypt
 * - RSA decrypt
 * - RSA CSR
 */

/* ********************** Include files ********************** */
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "ex_sss_ports.h"
#include "sssProvider_main.h"
#include <string.h>

/* ********************** Constants ************************** */
#define SSS_PROVIDER_NAME "NXP Provider"
#define SSS_PROVIDER_VERSION "1.1.3"
#define SSSPROV_MAX_PRINT_BUF_SIZE (511)

/* ********************** Global variables ************************** */

// Adjust to the required default log level.
// static int SSSPROV_LogControl = (LOG_ERR_ON | LOG_DBG_ON | LOG_FLOW_ON); //
// Full log
static int SSSPROV_LogControl = (LOG_ERR_ON | LOG_FLOW_ON); // Only Errors and flow logs

// SE boot context
ex_sss_boot_ctx_t gProvider_boot_ctx;

/* ********************** Private funtions ******************* */

static const OSSL_PARAM *sss_gettable_params(void *provctx)
{
    static const OSSL_PARAM param_types[] = {OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_END};
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(provctx);
    return param_types;
}

static int sss_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(provctx);

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SSS_PROVIDER_NAME))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SSS_PROVIDER_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SSS_PROVIDER_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

extern int sss_get_capabilities(const OSSL_PROVIDER *prov, const char *capability, OSSL_CALLBACK *cb, void *arg);

extern const OSSL_DISPATCH sss_rand_functions[];
static const OSSL_ALGORITHM sss_rands[] = {
    {"CTR-DRBG", "provider=nxp_prov,fips=yes,nxp_prov.rand=yes", sss_rand_functions}, {NULL, NULL, NULL}};

#if SSS_HAVE_ECC
extern OSSL_DISPATCH sss_ec_keymgmt_functions[];
#endif //#if SSS_HAVE_ECC

#if SSS_HAVE_RSA
extern OSSL_DISPATCH sss_rsa_keymgmt_dispatch[];
#endif //#if SSS_HAVE_RSA

static const OSSL_ALGORITHM sss_keymgmts[] = {
#if SSS_HAVE_ECC
    {"EC:id-ecPublicKey",
        "provider=nxp_prov,fips=yes,nxp_prov.keymgmt=yes,nxp_prov.keymgmt.ec=yes",
        sss_ec_keymgmt_functions},
#endif //#if SSS_HAVE_ECC
#if SSS_HAVE_RSA
    {"RSA:RSASSA",
        "provider=nxp_prov,fips=yes,nxp_prov.keymgmt=yes,nxp_prov.keymgmt.rsa=yes",
        sss_rsa_keymgmt_dispatch},
#endif //#if SSS_HAVE_RSA
    {NULL, NULL, NULL}};

#if SSS_HAVE_RSA
extern const OSSL_DISPATCH sss_rsa_enc_functions[];
static const OSSL_ALGORITHM sss_rsa_enc[] = {
    {"RSAENC-SE05X", "provider=nxp_prov,fips=yes,nxp_prov.asym_cipher=yes", sss_rsa_enc_functions}, {NULL, NULL, NULL}};
#endif //#if SSS_HAVE_RSA

#if SSS_HAVE_ECC
extern const OSSL_DISPATCH sss_ecdsa_signature_functions[];
#endif //#if SSS_HAVE_ECC

#if SSS_HAVE_RSA
extern const OSSL_DISPATCH sss_rsa_signature_functions[];
#endif //#if SSS_HAVE_RSA

static const OSSL_ALGORITHM sss_signatures[] = {
#if SSS_HAVE_ECC
    {"ECDSA",
        "provider=nxp_prov,fips=yes,nxp_prov.signature=yes,nxp_prov.signature.ecdsa=yes",
        sss_ecdsa_signature_functions},
#endif //#if SSS_HAVE_ECC
#if SSS_HAVE_RSA
    {"RSA",
        "provider=nxp_prov,fips=yes,nxp_prov.signature=yes,nxp_prov.signature.rsa=yes",
        sss_rsa_signature_functions},
#endif
    {NULL, NULL, NULL}};

#if SSS_HAVE_ECC
extern const OSSL_DISPATCH sss_ecdh_keyexch_functions[];
#endif //#if SSS_HAVE_ECC

static const OSSL_ALGORITHM sss_keyexchs[] = {
#if SSS_HAVE_ECC
    {"ECDH", "provider=nxp_prov,fips=yes,nxp_prov.keyexch=yes", sss_ecdh_keyexch_functions},
#endif
    {NULL, NULL, NULL}};

extern const OSSL_DISPATCH sss_store_object_functions[];
extern const OSSL_DISPATCH sss_file_store_object_functions[];
static const OSSL_ALGORITHM sss_store[] = {
    {"nxp", "provider=nxp_prov,fips=yes,nxp_prov.store=yes,nxp_prov.store.nxp=yes", sss_store_object_functions},
    {"file", "provider=nxp_prov,fips=yes,nxp_prov.store=yes,nxp_prov.store.file=yes", sss_file_store_object_functions},
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM *sss_query_operation(void *provctx, int operation_id, int *no_cache)
{
    *no_cache = 0;
    (void)(provctx);
    switch (operation_id) {
#ifndef SSS_PROV_DISABLE_SE05X_RNG
    case OSSL_OP_RAND:
        return sss_rands;
#endif
    case OSSL_OP_KEYMGMT:
        return sss_keymgmts;
    case OSSL_OP_SIGNATURE:
        return sss_signatures;
    case OSSL_OP_STORE:
        return sss_store;
    case OSSL_OP_KEYEXCH:
        return sss_keyexchs;
#if SSS_HAVE_RSA
    case OSSL_OP_ASYM_CIPHER:
        return sss_rsa_enc;
#endif //#if SSS_HAVE_RSA
    default:
        return NULL;
    }
}

static void sss_teardown(void *provctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    ex_sss_session_close(&gProvider_boot_ctx);
    if (provctx != NULL) {
        OPENSSL_free(provctx);
    }
    return;
}

static const OSSL_DISPATCH sss_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))sss_query_operation},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))sss_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))sss_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))sss_get_params},
    {OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))sss_get_capabilities},
    {0, NULL}};

OPENSSL_EXPORT int OSSL_provider_init(
    const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    sss_status_t status = kStatus_SSS_Fail;
    char *portName;

    // if (NULL == OSSL_PROVIDER_load(NULL, "default")) {
    //    sssProv_Print(LOG_FLOW_ON, "error in OSSL_PROVIDER_load \n");
    //}

    sss_provider_context_t *sssProvCtx = OPENSSL_zalloc(sizeof(sss_provider_context_t));
    if (sssProvCtx == NULL) {
        return 0;
    }
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(in);

    status = ex_sss_boot_connectstring(0, NULL, &portName);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status)

    status = ex_sss_boot_open(&gProvider_boot_ctx, portName);
#if defined(_MSC_VER)
    if (portName) {
        char *dummy_portName = NULL;
        size_t dummy_sz      = 0;
        _dupenv_s(&dummy_portName, &dummy_sz, EX_SSS_BOOT_SSS_PORT);
        if (NULL != dummy_portName) {
            free(dummy_portName);
            free(portName);
        }
    }
#endif // _MSC_VER
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status)

    status = ex_sss_key_store_and_object_init(&gProvider_boot_ctx);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status)

#if SSS_HAVE_HOSTCRYPTO_ANY
    // Open host session
    status = ex_sss_boot_open_host_session(&gProvider_boot_ctx);
    if (kStatus_SSS_Success != status) {
        sssProv_Print(LOG_DBG_ON, "Error in host session open. Some operations may fail \n");
    }
#endif

    sssProvCtx->core              = handle;
    sssProvCtx->p_ex_sss_boot_ctx = &gProvider_boot_ctx;
    *out                          = sss_dispatch_table;
    *provctx                      = sssProvCtx;

    return 1;
cleanup:
    if (sssProvCtx != NULL) {
        OPENSSL_free(sssProvCtx);
    }
    return 0;
}

OPENSSL_EXPORT int sssProvider_init(
    const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    return OSSL_provider_init(handle, in, out, provctx);
}

void sssProv_Print(int flag, const char *format, ...)
{
    unsigned char buffer[SSSPROV_MAX_PRINT_BUF_SIZE + 1];
    int active = 0;
    va_list vArgs;

    if ((flag & SSSPROV_LogControl & LOG_FLOW_MASK) == LOG_FLOW_ON) {
        active = 1;
        printf("sssprov-flw: ");
    }
    else if ((flag & SSSPROV_LogControl & LOG_DBG_MASK) == LOG_DBG_ON) {
        active = 1;
        printf("sssprov-dbg: ");
    }
    else if ((flag & SSSPROV_LogControl & LOG_ERR_MASK) == LOG_ERR_ON) {
        active = 1;
        printf("sssprov-err: ");
    }

    if (active == 1) {
        va_start(vArgs, format);
        if (vsnprintf((char *)buffer, SSSPROV_MAX_PRINT_BUF_SIZE, (char const *)format, vArgs) < 0) {
            printf("vsnprintf error");
            return;
        }
        va_end(vArgs);
        printf("%s", buffer);
    }
    return;
}

int SSS_CMP_STR(const char *s1, const char *s2)
{
    size_t strlength = (strlen(s1) > strlen(s2)) ? strlen(s2) : strlen(s1);
    return strncmp(s1, s2, strlength);
}
