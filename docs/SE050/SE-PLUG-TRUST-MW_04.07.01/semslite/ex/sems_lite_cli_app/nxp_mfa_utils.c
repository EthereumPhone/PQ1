/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "nxp_mfa_utils.h"

#include <nxEnsure.h>
#include <nxLog_App.h>
#include <stdlib.h>
#include <string.h>

#include "mfa_utils.h"
#include "mfa_process.h"
#include "smCom.h"
#include "sm_apdu.h"
#ifdef SMCOM_JRCP_V2
#include <smComJRCP.h>
#endif
#include "sems_lite_api.h"
#include <stdio.h>

#if defined(RJCT_VCOM) && (RJCT_VCOM == 1)
static uint32_t vcom_set_reset_timer(uint32_t time_ms);
#endif

void prepareTear(uint32_t tear_time)
{
#if AX_EMBEDDED
#if SSS_HAVE_APPLET_SE05X_IOT
#if FSL_FEATURE_SOC_PIT_COUNT > 0
    tear_time /= 10;
    LOG_W("Starting the %d usec Timer to reset the IC", tear_time);
    se_pit_SetTimer(tear_time);
#endif
#endif
#elif defined(RJCT_VCOM) && (RJCT_VCOM == 1)
    tear_time /= 10;
    vcom_set_reset_timer(tear_time);
#elif SMCOM_JRCP_V2
    smComJRCP_Reset(NULL, tear_time);
#endif
}

#if defined(RJCT_VCOM) && (RJCT_VCOM == 1)
static uint32_t vcom_set_reset_timer(uint32_t time_ms)
{
    U8 txBuf[6] = {0};
    U16 txLen = sizeof(txBuf);
    U8 rxBuf[MAX_APDU_BUF_LENGTH];
    U32 rxBufLen = sizeof(rxBuf);
    U32 st = 0;
    txBuf[0] = 0xFF;                   //propritery set timer CLA byte
    txBuf[1] = 0x0B;                   // INS does not matter can be anything
    txBuf[2] = (time_ms >> 24) & 0xFF; // P1 time
    txBuf[3] = (time_ms >> 16) & 0xFF; // P2 time
    txBuf[4] = (time_ms >> 8) & 0xFF;  // P3 time
    txBuf[5] = time_ms & 0xFF;         // P4 time

    st = smCom_TransceiveRaw(NULL, txBuf, txLen, rxBuf, &rxBufLen);
    if (st != SMCOM_OK) {
        LOG_E("Transceive failed returns : %d\r\n", st);
        return st;
    }
    return st;
}
#endif

void mfa_process_loadpkg_with_tear(const char *pkgname, uint32_t tear_time)
{
    sems_lite_status_t status = kStatus_SEMS_Lite_ERR_Fatal;
    FILE *fp = NULL;
    size_t numbytes;
    uint8_t *buffer;
    multicast_package_t package;
    sub_component_metaData_t subcomponent[SEMS_LITE_MAX_SUBCOMPONENT_NUMBER];

    if (strstr(pkgname, "..") != NULL) {
        LOG_W("Potential directory traversal");
    }

    fp = fopen(pkgname, "rb");
    if (fp == NULL) {
        printf("File not found");
        exit(2);
    }
    fseek(fp, 0L, SEEK_END);
    numbytes = ftell(fp);

    buffer = (uint8_t *)malloc(numbytes); /* Total binary file size */
    if (buffer == NULL) {
        printf("malloc failed !!!");
        exit(2);
    }

    fseek(fp, 0L, SEEK_SET);
    fread(buffer, numbytes, 1, fp);


    if (tear_time > 0) {
        prepareTear(tear_time);
    }

    if (mfa_process_parse_binary(buffer, numbytes, &package, subcomponent) != kStatus_SSS_Success){
        LOG_E("Parse binary file failed");
        goto cleanup;
    }

    // Load package
    status = sems_lite_agent_load_package(
        &g_sems_lite_agent_load_ctx, &package);
    printSEMSLiteStatusCode(status);

cleanup:
    free(buffer);
}

