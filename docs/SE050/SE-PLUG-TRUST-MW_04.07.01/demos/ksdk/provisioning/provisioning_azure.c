/**
 * @file azure_provisioning.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017,2018 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * azure provisioning file
 */
#include "sm_types.h"

/* clang-format off */
/*******************************************************************
* INCLUDE FILES
*******************************************************************/
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "provisioning.h"
#include "azure_iot_config.h"
#include "azure_credentials.h"

#if SSS_HAVE_SSS
#include <fsl_sss_api.h>
#endif

#if (SSS_HAVE_MBEDTLS_ALT_SSS && SSS_HAVE_MBEDTLS_2_X)
#  include "sss_mbedtls.h"
#  include "ex_sss.h"
#endif

#include "nxLog_App.h"


sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
#if SSS_HAVE_SSS
    sss_status_t status;
#endif
    sss_object_t obj_kp, obj_client_cert;

    status = sss_key_object_init(&obj_kp, &pCtx->ks);
    if (status != kStatus_SSS_Success) {
        LOG_I(" sss_key_object_init for keyPair Failed...\n");
        goto exit;
    }

    status = sss_key_object_allocate_handle(&obj_kp,
        AZURE_IOT_KEY_INDEX_SM,
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        sizeof(client_key),
        kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_key_object_allocate_handle for keyPair Failed...\n");
        goto exit;
    }

    status = sss_key_store_set_key(&pCtx->ks, &obj_kp, client_key, sizeof(client_key), 256, NULL, 0);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_key_store_set_key  for keyPair Failed...\n");
        goto exit;
    }

    status = sss_key_object_init(&obj_client_cert, &pCtx->ks);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_key_object_init for clientCert Failed...\n");
        goto exit;
    }

    status = sss_key_object_allocate_handle(&obj_client_cert,
        AZURE_IOT_CLIENT_CERT_INDEX_SM,
        kSSS_KeyPart_Default,
        kSSS_CipherType_Binary,
        sizeof(client_cer),
        kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_key_object_allocate_handle Failed!!!");
        goto exit;
    }

    status = sss_key_store_set_key(
        &pCtx->ks, &obj_client_cert, client_cer, sizeof(client_cer), sizeof(client_cer) * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        LOG_E(" Store Certificate Failed!!!");
        goto exit;
    }

    LOG_I(" PROVISIONING SUCCESSFUL!!!");
exit:
    LOG_I("Provisioning Example Finished");
    return status;
}
