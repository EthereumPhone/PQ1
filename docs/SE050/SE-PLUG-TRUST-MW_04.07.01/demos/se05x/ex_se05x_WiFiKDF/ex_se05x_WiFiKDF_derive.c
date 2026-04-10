/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>
#include <stdio.h>
#include <string.h>

#include "ex_se05x_WiFiKDF.h"

#define WIFI_DERIVED_KEY_SIZE 32
#define WIFI_COUNT 4096
/*
Note: Incase of higher iteration count, plese increase PH_PROTO_WTX_DEFAULT_COUNT in file
hostlib\hostLib\libCommon\smCom\T1oI2C\phNxpEseProto7816_3.h.
*/

static ex_sss_boot_ctx_t gex_sss_wifi_kdf;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_wifi_kdf)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    smStatus_t status;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    SE05x_Result_t pExists        = kSE05x_Result_NA;
    /* For SE052F, increase the size of wifi_ssid to atleast 16 bytes */
    uint8_t wifi_ssid[100]                         = "some-wifi-ssid";
    size_t ssid_size                               = 0;
    uint8_t wifi_derivedKey[WIFI_DERIVED_KEY_SIZE] = {0};
    size_t wifi_derivedKeyLen                      = WIFI_DERIVED_KEY_SIZE;
    size_t i;
    int argc          = gex_sss_argc;
    const char **argv = gex_sss_argv;

    ssid_size = strlen((const char *)wifi_ssid);
    for (int j = 1; j < argc; j++) {
        if (strcmp(argv[j], "-s") == 0) {
            j++;
            if (j >= argc) {
                LOG_E("Invalid arguments");
                goto cleanup;
            }
            ssid_size = strlen(argv[j]);
            if (ssid_size >= sizeof(wifi_ssid)) {
                LOG_E("SSID Size too big. Exit!");
                break;
            }
            memcpy(wifi_ssid, argv[j], ssid_size);
            break;
        }
    }

    status = Se05x_API_CheckObjectExists(&pSession->s_ctx, WIFI_OBJ_ID, &pExists);

    if (status == SM_OK && pExists != kSE05x_Result_SUCCESS) {
        LOG_E("WiFi Object does not exist");
        LOG_E(
            "Did you run 'ex_se05x_WiFiKDF_inject' before running this "
            "example?");
        goto cleanup;
    }

    LOG_I("Deriving PBKDF2 for wifi_ssid='%s', WIFI_COUNT='%d'", wifi_ssid, WIFI_COUNT);
    status = Se05x_API_PBKDF2_extended(&pSession->s_ctx,
        WIFI_OBJ_ID,
        wifi_ssid,
        ssid_size,
        0, /* Salt object id. Here it is 0 as the salt is passed as buffer */
        WIFI_COUNT,
        kSE05x_MACAlgo_HMAC_SHA256,
        WIFI_DERIVED_KEY_SIZE,
        0, /* derivedSessionKeyID. Here it is 0 as the derived key is returned on host */
        wifi_derivedKey,
        &wifi_derivedKeyLen);
    if (status != SM_OK) {
        LOG_E("Se05x_API_PBKDF2 Failed");
        goto cleanup;
    }
    LOG_AU8_I(wifi_derivedKey, wifi_derivedKeyLen);

    printf("\n# Data for /etc/wpa_supplicant/wpa_supplicant.conf");
    printf("\nnetwork={");
    printf("\n    ssid=\"");
    for (i = 0; i < ssid_size; i++) {
        printf("%c", wifi_ssid[i]);
    }
    printf("\"\n    psk=");
    for (i = 0; i < wifi_derivedKeyLen; i++) {
        printf("%x", wifi_derivedKey[i]);
    }
    printf("\n}");
    printf("\n");
    sss_status = kStatus_SSS_Success;

cleanup:
    LOG_I("Done");
    return sss_status;
}
