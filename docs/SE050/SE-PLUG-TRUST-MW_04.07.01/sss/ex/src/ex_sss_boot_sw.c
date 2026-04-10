/*
 *
 * Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 *
 * ex_sss_boot_sw.c:  *The purpose and scope of this file*
 *
 * Project:  SecureIoTMW-Debug@appboot-top-eclipse_x86
 *
 * $Date: Mar 10, 2019 $
 * $Author: ing05193 $
 * $Revision$
 */

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */

#include <stdio.h>

#include "ex_sss_boot_int.h"
#include "nxLog_App.h"

/* *****************************************************************************************************************
 * Internal Definitions
 * ***************************************************************************************************************** */
#define TEST_ROOT_FOLDER "."

/* *****************************************************************************************************************
 * Type Definitions
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Global and Static Variables
 * Total Size: NNNbytes
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Private Functions Prototypes
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
sss_status_t ex_sss_boot_mbedtls_open(ex_sss_boot_ctx_t *pCtx, const char *portName)
{
    sss_status_t status = kStatus_SSS_Fail;
#ifdef MBEDTLS_FS_IO
    if (portName == NULL) {
        portName = TEST_ROOT_FOLDER;
    }
#else
    portName = NULL;
#endif
    if (pCtx != NULL) {
        status = sss_session_open(&pCtx->session, kType_SSS_mbedTLS, 0, kSSS_ConnectionType_Plain, (void *)portName);
        if (status != kStatus_SSS_Success) {
            LOG_E("mbedtls Session open failed...");
            goto cleanup;
        }
    }

cleanup:
    return status;
}
#endif

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
sss_status_t ex_sss_boot_openssl_open(ex_sss_boot_ctx_t *pCtx, const char *portName)
{
    sss_status_t status = kStatus_SSS_Fail;
    if (portName == NULL) {
        portName = TEST_ROOT_FOLDER;
    }
    if (pCtx != NULL) {
        status = sss_session_open(&pCtx->session, kType_SSS_OpenSSL, 0, kSSS_ConnectionType_Plain, (void *)portName);
        if (status != kStatus_SSS_Success) {
            LOG_E("OpenSSL Session open failed...");
            goto cleanup;
        }
    }

cleanup:
    return status;
}
#endif
/* *****************************************************************************************************************
 * Private Functions
 * ***************************************************************************************************************** */
