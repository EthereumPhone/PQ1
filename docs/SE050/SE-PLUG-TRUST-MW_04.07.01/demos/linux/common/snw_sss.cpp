/**
 * @file snw_util.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description:
 * Wrappers for basic network functionality
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>

#include "snw_common.h"

int wrapConnectToSe(ex_sss_boot_ctx_t *pSeBootCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    char *portName;

    fprintf(stdout, "wrapConnectToSe: Open connection to secure element. \n");

    status = ex_sss_boot_connectstring(0, NULL, &portName);
    if (status != kStatus_SSS_Success) {
        fprintf(stdout, "ex_sss_boot_connectstring failed ...");
        return status;
    }

    status = ex_sss_boot_open(pSeBootCtx, portName);
    if (status != kStatus_SSS_Success) {
        fprintf(stdout, "ex_sss_boot_open failed ...");
        return status;
    }

    status = ex_sss_key_store_and_object_init(pSeBootCtx);
    if (status != kStatus_SSS_Success) {
        fprintf(stdout, "ex_sss_key_store_and_object_init failed ...");
        return status;
    }

    return SE_TLS_CLIENT_OK;
}

void wrapDisconnectFromSe(ex_sss_boot_ctx_t *pSeBootCtx) {
    fprintf(stdout, "wrapDisconnectFromSe: Close connection to secure element. \n");
    sss_key_store_context_free(&(pSeBootCtx->ks));
    sss_session_close(&(pSeBootCtx->session));
}

int seGetClientCertificate(sss_key_store_t *keyStore, int certId, U8 *clientCertDer, size_t *clientCertDerLen)
{
    sss_object_t certObject;
    size_t certDerLenBits = *clientCertDerLen * 8;
    sss_status_t status;

    status = sss_key_object_init(&certObject, keyStore);
    if (status != kStatus_SSS_Success)
    {
        printf("Failed to initialize certObject: status code = 0x%04x.\n", status);
        return SE_ERR_SE_GP_NO_CERT;
    }
    certObject.objectType = kSSS_KeyPart_Default;
    certObject.cipherType = kSSS_CipherType_Binary;
    certObject.keyId = certId;

    status = sss_key_store_get_key(keyStore, &certObject, clientCertDer, clientCertDerLen, &certDerLenBits);
    if (status != kStatus_SSS_Success)
    {
        printf("Fetching client certificate fails with status code: 0x%04x.\n", status);
        return SE_ERR_SE_GP_NO_CERT;
    }

    printf("Size of certificate retrieved: %zu byte\n", *clientCertDerLen);
    // snwPrintDataAsHex(clientCertDer, *clientCertDerLen);

    return SE_TLS_CLIENT_OK;
}
