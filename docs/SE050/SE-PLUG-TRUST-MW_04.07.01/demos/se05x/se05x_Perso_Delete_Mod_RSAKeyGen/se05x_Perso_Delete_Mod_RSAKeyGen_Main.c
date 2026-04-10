/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file se05x_Personalization_Main.c
 *
 * This file solves purpose for
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "se05x_Perso_Delete_Mod_RSAKeyGen.h"
#include "nxLog_App.h"
#include "se05x_perso_api.h"
#include "nxEnsure.h"

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
/* Public Functions                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_perso_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_perso_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1
#define EX_SSS_BOOT_SKIP_SELECT_APPLET 1

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                 = kStatus_SSS_Fail;
    smStatus_t sm_status                = SM_NOT_OK;
    sss_se05x_session_t *pSession       = (sss_se05x_session_t *)&pCtx->session;
    smStatus_t open_perso_applet_status = ex_perso_OpenApplet(&pSession->s_ctx);
    ENSURE_OR_GO_EXIT(SM_OK == open_perso_applet_status);
    LOG_I("# Running Remove Module RSAKEYGEN : On chip generation of RSA keys.");
    sm_status = ex_perso_RM_MOD_RSAKEYGEN(&pSession->s_ctx);

    if (sm_status == SM_OK) {
        LOG_I("# Remove Module RSAKEYGEN is complete.");
        status = kStatus_SSS_Success;
    }
exit:
    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_Perso_Delete_Mod_RSAKeyGen Example Success !!!...");
    }
    else {
        LOG_E("se05x_Perso_Delete_Mod_RSAKeyGen Example Failed !!!...");
    }
    return status;
}

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

smStatus_t ex_perso_OpenApplet(pSe05xSession_t session_ctx)
{
    smStatus_t status = Se05x_API_Perso_SelectApplet(session_ctx);
    return status;
}