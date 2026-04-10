/*
 * Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TST_CRYPTO_H_INC
#define TST_CRYPTO_H_INC
#include <stdio.h>
#include <string.h>

#include "fsl_sss_api.h"
#include "fsl_sss_user_apis.h"
#include "fsl_sss_mbedtls_apis.h"
#include "fsl_sss_openssl_apis.h"
#include "nxLog_App.h"

#include "sm_types.h"

typedef struct userCtx
{
    sss_session_t session;
    sss_key_store_t ks;
    sss_object_t key;
    sss_rng_context_t rng;
    sss_symmetric_t symm;
    sss_mac_t mac;
} userCtx_t;

extern sss_status_t test_mac_multiStep_algo_mmm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mmz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mmp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mmq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mzm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mzz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mzp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mzq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mpm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mpz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mpp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mpq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mqm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mqz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mqp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_mqq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zmm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zmz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zmp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zmq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zzm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zzz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zzp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zzq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zpm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zpz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zpp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zpq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zqm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zqz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zqp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_zqq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_pmm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_pmz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_pmp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_pmq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_pzm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_pzz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_pzp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_pzq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_ppm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_ppz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_ppp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_ppq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_pqm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_pqz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_pqp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_pqq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qmm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qmz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qmp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qmq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qzm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qzz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qzp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qzq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qpm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qpz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qpp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qpq(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qqm(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qqz(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qqp(userCtx_t *pUserCtx);
extern sss_status_t test_mac_multiStep_algo_qqq(userCtx_t *pUserCtx);

#endif
