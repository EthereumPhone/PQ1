/**
 * @file sssProvider_rand.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for random generator using SSS API's
 *
 */

/* ********************** Include files ********************** */
#include "sssProvider_main.h"
#include <openssl/core_names.h>

/* ********************** Constants ************************** */
#ifdef SE05X_MAX_BUF_SIZE_RSP
#define MAX_RND_REQUEST SE05X_MAX_BUF_SIZE_RSP
#else
#define MAX_RND_REQUEST 512
#endif

/* ********************** structure definition *************** */
typedef struct
{
    sss_provider_context_t *pProvCtx;
} sss_rand_ctx_st;

/* ********************** Private funtions ******************* */

static void *sss_rand_newctx(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls)
{
    sss_rand_ctx_st *pRandCtx = OPENSSL_zalloc(sizeof(sss_rand_ctx_st));
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(parent);
    (void)(parent_calls);
    if (pRandCtx != NULL) {
        pRandCtx->pProvCtx = provctx;
    }
    return pRandCtx;
}

static void sss_rand_freectx(void *ctx)
{
    sss_rand_ctx_st *randCtx = ctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (randCtx != NULL) {
        OPENSSL_clear_free(randCtx, sizeof(sss_rand_ctx_st));
    }
    return;
}

static int sss_rand_generate(void *ctx,
    unsigned char *out,
    size_t outlen,
    unsigned int strength,
    int prediction_resistance,
    const unsigned char *adin,
    size_t adinlen)
{
    sss_rand_ctx_st *pRandCtx     = (sss_rand_ctx_st *)ctx;
    sss_status_t status           = kStatus_SSS_Fail;
    sss_rng_context_t sss_rng_ctx = {
        0,
    };
    int ret = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(strength);
    (void)(prediction_resistance);
    (void)(adin);
    (void)(adinlen);

    ENSURE_OR_GO_CLEANUP(out != NULL);
    ENSURE_OR_GO_CLEANUP(pRandCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRandCtx->pProvCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRandCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

    status = sss_rng_context_init(&sss_rng_ctx, &pRandCtx->pProvCtx->p_ex_sss_boot_ctx->session);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    sssProv_Print(LOG_FLOW_ON, "Get random data from SE05x \n");
    status = sss_rng_get_random(&sss_rng_ctx, out, outlen);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    ret = 1;
cleanup:
    if (sss_rng_ctx.session != NULL) {
        sss_rng_context_free(&sss_rng_ctx);
    }
    return ret;
}

static int sss_rand_instantiate(void *ctx,
    unsigned int strength,
    int prediction_resistance,
    const unsigned char *pstr,
    size_t pstr_len,
    const OSSL_PARAM params[])
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(ctx);
    (void)(strength);
    (void)(prediction_resistance);
    (void)(pstr);
    (void)(pstr_len);
    (void)(params);
    return 1;
}

static int sss_rand_uninstantiate(void *ctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(ctx);
    return 1;
}

static int sss_rand_enable_locking(void *ctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(ctx);
    return 1;
}

static const OSSL_PARAM *sss_rand_gettable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL), OSSL_PARAM_END};
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(ctx);
    (void)(provctx);
    return known_gettable_ctx_params;
}

static int sss_rand_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(ctx);

    if (params == NULL) {
        return 1;
    }

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, MAX_RND_REQUEST)) {
        return 0;
    }

    return 1;
}

const OSSL_DISPATCH sss_rand_functions[] = {{OSSL_FUNC_RAND_NEWCTX, (void (*)(void))sss_rand_newctx},
    {OSSL_FUNC_RAND_FREECTX, (void (*)(void))sss_rand_freectx},
    {OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))sss_rand_instantiate},
    {OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))sss_rand_uninstantiate},
    {OSSL_FUNC_RAND_GENERATE, (void (*)(void))sss_rand_generate},
    {OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))sss_rand_enable_locking},
    {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))sss_rand_gettable_ctx_params},
    {OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))sss_rand_get_ctx_params},
    {0, NULL}};
