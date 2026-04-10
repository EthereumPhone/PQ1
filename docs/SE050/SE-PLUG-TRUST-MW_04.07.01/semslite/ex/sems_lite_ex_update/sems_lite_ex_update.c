/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include <string.h>
/* doc:start:SEMS-Lite-include-files */
#include "sems_lite_api.h"
/* doc:end:SEMS-Lite-include-files */

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_boot_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0
#define EX_SSS_BOOT_SKIP_SELECT_APPLET 1

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

extern multicast_package_t multicast_package;

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sems_lite_status_t status = kStatus_SEMS_Lite_ERR_General;
    sss_status_t rv = kStatus_SSS_Fail;
    /* doc:start:SEMS-Lite-context-declare */
    sems_lite_agent_ctx_t s_sems_lite_agent_ctx = {0};
    /* doc:end:SEMS-Lite-context-declare */

    /* doc:start:SEMS-Lite-api-usage-init */
    rv = sems_lite_agent_init_context(&s_sems_lite_agent_ctx, &pCtx->session);
    /* doc:end:SEMS-Lite-api-usage-init */
    ENSURE_OR_GO_CLEANUP(rv == kStatus_SSS_Success);

    /* In case channel is not close in former operation. */
    rv = sems_lite_agent_session_close(&s_sems_lite_agent_ctx);
    ENSURE_OR_GO_CLEANUP(rv == kStatus_SSS_Success);

    /* doc:start:SEMS-Lite-api-usage-open */
    rv = sems_lite_agent_session_open(&s_sems_lite_agent_ctx);
    /* doc:end:SEMS-Lite-api-usage-open */
    ENSURE_OR_GO_CLEANUP(rv == kStatus_SSS_Success);

    /* doc:start:SEMS-Lite-api-usage-load-pkg */
    status = sems_lite_agent_load_package(
        &s_sems_lite_agent_ctx, &multicast_package);
    /* doc:end:SEMS-Lite-api-usage-load-pkg */
    if (status != kStatus_SEMS_Lite_Success) {
        rv = sems_lite_agent_session_close(&s_sems_lite_agent_ctx);
        ENSURE_OR_GO_CLEANUP(rv == kStatus_SSS_Success);
    }
    ENSURE_OR_GO_CLEANUP(status == kStatus_SEMS_Lite_Success);

    /* doc:start:SEMS-Lite-api-close */
    rv = sems_lite_agent_session_close(&s_sems_lite_agent_ctx);
    /* doc:end:SEMS-Lite-api-close */
    ENSURE_OR_GO_CLEANUP(rv == kStatus_SSS_Success);

    LOG_I("Update Applet successful !!!");

cleanup:
    if (kStatus_SEMS_Lite_Success == status) {
        LOG_I("sems_lite_ex_update Example Success !!!...");
        rv = kStatus_SSS_Success;
    }
    else {
        LOG_E("sems_lite_ex_update Example Failed !!!...");
        rv = kStatus_SSS_Fail;
    }

    return rv;
}
