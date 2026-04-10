/*
 *
 * Copyright 2018,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include <fsl_sss_api.h>
#include <smCom.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include <fsl_sss_mbedtls_apis.h>
#include <mbedtls/version.h>
#endif

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include <fsl_sss_openssl_apis.h>
#include <openssl/opensslv.h>
#endif

#if SSS_HAVE_APPLET_SE05X_IOT
#include <fsl_sss_se05x_apis.h>
#endif

#include <ex_sss_boot.h>
#include "sm_apdu.h"

#include "nxLog_App.h"

#define MAX_TX_RX_BUFFER 1024

static ex_sss_boot_ctx_t gex_sss_gen_cert;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_gen_cert)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>
void print_usage();

void print_usage()
{
    printf("Execute APDUs on a SE\n");
    printf("  Usage:\n");
    printf("apdu_player [apdu-file] <port>\n");
    printf("\n");
    printf(
        "The apdu file contains hex strings of APDUs, one APDU per line in the "
        "following format:\n");
    printf("/send APDU [EXPECTED_RESPONSE]\n");
    printf("All lines not following this format are ignored.\n");
}

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    int argc            = gex_sss_argc;
    const char **argv   = gex_sss_argv;
    void *conn_ctx      = NULL;
    if (argc < 2) {
        print_usage();
        return status;
    }

#if SSS_HAVE_APPLET_SE05X_IOT
    conn_ctx = &((sss_se05x_session_t *)&pCtx->session)->s_ctx;
#endif

    if (strstr(argv[1], "..") != NULL) {
        LOG_W("Potential directory traversal");
    }
    if (argv[1][0] == '/') {
        LOG_W("Accessing file using absolute path");
    }
    FILE *fp = fopen(argv[1], "r");
    if (fp == NULL) {
        LOG_E("error opening file %s\n", argv[1]);
        print_usage();
        return status;
    }

    char buf[MAX_TX_RX_BUFFER * 8]      = {0};
    char apdu_str[MAX_TX_RX_BUFFER * 8] = {0};
    char resp_str[MAX_TX_RX_BUFFER * 8] = {0};

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        size_t len = strlen(buf) - 1;

        if (len >= sizeof(buf)) {
            if (fclose(fp) != 0) {
                LOG_E("fclose Error");
            }
            return status;
        }
        if (buf[len] == '\r' || buf[len] == '\n') {
            buf[len] = '\0'; // eat the newline fgets() stores
        }

        int found = sscanf(buf, "/send %s %s", apdu_str, resp_str);
        if (found <= 0) {
            LOG_I("discarding [%s]\n", buf);
            continue;
        }

        uint8_t apdu[SE05X_MAX_BUF_SIZE_CMD] = {0};
        uint8_t resp[SE05X_MAX_BUF_SIZE_RSP] = {0};
        size_t apdu_len                      = 0;
        size_t resp_len                      = 0;

        bool compare_full_response = true;
        char *resp_to_compare_str  = resp_str;

        if (!smApduGetArrayBytes(apdu_str, &apdu_len, apdu, SE05X_MAX_BUF_SIZE_CMD)) {
            LOG_E("invalid hexstr in [%s]\n", buf);
            if (fclose(fp) != 0) {
                LOG_E("Error while closing the file");
            }
            return kStatus_SSS_Fail;
        }
        if (found > 1) {
            // the response CAN be prepended with a star signifying that
            // there can be more characters. ignore those.
            if (resp_str[0] == '*') {
                compare_full_response = false;
                resp_to_compare_str   = &resp_str[1];
            }
            smApduGetArrayBytes(resp_to_compare_str, &resp_len, resp, SE05X_MAX_BUF_SIZE_RSP);
        }

        uint8_t rx[MAX_TX_RX_BUFFER] = {0};
        size_t rlen                  = sizeof(rx);
        printf("Executing [%s]\n", buf);
        if (SM_OK != DoAPDUTxRx(conn_ctx, apdu, (uint16_t)apdu_len, &rx[0], &rlen)) {
            LOG_E("Unable to send apdu [%s]\n", buf);
            if (fclose(fp) != 0) {
                LOG_E("Error while closing the file");
            }
            return status;
        }

        if (resp_len != 0) {
            if ((rlen < resp_len) ||
                ((compare_full_response) ? (memcmp(resp, rx, resp_len) != 0) :
                                           (memcmp(resp, rx + (rlen - resp_len), resp_len) != 0))) {
                LOG_E("Unexpected response for apdu [%s]\n", buf);
                if (fclose(fp) != 0) {
                    LOG_E("Error while closing the file");
                }
                return status;
            }
            else {
                LOG_I("Success");
            }
        }
        else {
            LOG_W("resp is null. Not checking response");
        }
    }

    if (fclose(fp) != 0) {
        LOG_E("Error while closing the file");
    }
    status = kStatus_SSS_Success;
    LOG_I("Example finished successfully");
    return status;
}
