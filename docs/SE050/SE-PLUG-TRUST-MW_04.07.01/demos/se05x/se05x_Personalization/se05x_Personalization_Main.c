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
#include <stdio.h>
#include "se05x_Personalization.h"
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

#define PERSO_IF_API(NAME, DESCRIPTION)            \
    {                                              \
        (#NAME), (DESCRIPTION), (&ex_perso_##NAME) \
    }

static const ex_perso_if_t gpExPersoIF[] = {
    PERSO_IF_API(HELP, "Prints list of APIs"),
    PERSO_IF_API(I2C_DisableClockStretching, "I2C: Disables clock stretching"),
    PERSO_IF_API(I2C_EnableCLockStretching, "I2C: Enables clock stretching"),

    PERSO_IF_API(I2C_ProtocolGP, "I2C: Use GP Mode for I2C"),
    PERSO_IF_API(I2C_ProtocolUM, "I2C: Use UM Mode like SE050 for I2C"),

    PERSO_IF_API(I2C_ProtocolAutoDetect, "I2C: Automatically detect I2C Protocol"),
    PERSO_IF_API(I2C_ProtocolManual, "I2C: Manually use fixed Protocol"),

    PERSO_IF_API(I2C_EnablePowerSave, "I2C: Go to power save after last APDU"),
    PERSO_IF_API(I2C_DisablePowerSave, "I2C: DO not go to power save after last APDU"),

    PERSO_IF_API(I2C_SemiBlocking, "I2C: SEMI Blocking I2C"),
    PERSO_IF_API(I2C_NonBlocking, "I2C: Non Blocking I2C"),

    PERSO_IF_API(RM_MOD_IOT_EXTENDED, "Delete: Extension to Elliptic Curve Cryptography."),

    PERSO_IF_API(RM_MOD_IOT_BASE, "Delete: Collection of crypto algorithms often used in IoT devices."),

    PERSO_IF_API(RM_MODX_EGOVACCELERATORS,
        "Delete: Secure Messaging Accelerators for eGovernment applications and modular arithmetic math API."),

    PERSO_IF_API(RM_MOD_RSAKEYGEN, "On chip generation of RSA keys."),

    {NULL, NULL, NULL},
};

const char *program_name = NULL;

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status           = kStatus_SSS_Fail;
    smStatus_t sm_status          = SM_NOT_OK;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    unsigned int i                = 0;
    program_name                  = gex_sss_argv[0];
    bool fFound                   = FALSE;

    const ex_perso_if_t *apis_to_run[50] = {0};

    for (i = 0; i < ARRAY_SIZE(apis_to_run); i++) {
        int j;
        for (j = i + 1; j < (gex_sss_argc - 1) && apis_to_run[i] == NULL; j++) {
            for (const ex_perso_if_t *pf = &gpExPersoIF[0]; pf->name != NULL; pf++) {
                if (0 == STRNICMP(pf->name, gex_sss_argv[j], strlen(pf->name) + 1)) {
                    apis_to_run[i] = pf;
                    fFound         = TRUE;
                    break;
                }
            }
            if (apis_to_run[i] == NULL) {
                LOG_E("Don't know what to do with argument '%s'", gex_sss_argv[j]);
                fFound = FALSE;
                i      = ARRAY_SIZE(apis_to_run);
                break;
            }
        }
    }

    if (fFound) {
        smStatus_t open_perso_applet_status = ex_perso_OpenApplet(&pSession->s_ctx);
        ENSURE_OR_GO_EXIT(SM_OK == open_perso_applet_status);
        for (i = 0; i < ARRAY_SIZE(apis_to_run); i++) {
            const ex_perso_if_t *api_to_run = apis_to_run[i];
            if (api_to_run != NULL) {
                LOG_I("# Running %s : %s", api_to_run->name, api_to_run->description);
                sm_status = api_to_run->fpAPI(&pSession->s_ctx);
                ENSURE_OR_GO_EXIT(SM_OK == sm_status);
            }
        }
    }
    else {
        // ! fFound;
        sm_status = ex_perso_HELP(&pSession->s_ctx);
    }

    if (sm_status == SM_OK) {
        status = kStatus_SSS_Success;
    }
exit:
    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_Personalization Example Success !!!...");
    }
    else {
        LOG_E("se05x_Personalization Example Failed !!!...");
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

smStatus_t ex_perso_HELP(pSe05xSession_t session_ctx)
{
    AX_UNUSED_ARG(session_ctx);
    printf("\nUSAGE:\n");
    if (program_name != NULL) {
        printf("%s <operation> [operation] <port_name>\n", program_name);
        printf("\n");
        printf("Where, 'operation': one or sequence of the following:\n\n");
        for (const ex_perso_if_t *pf = &gpExPersoIF[0]; pf->name != NULL; pf++) {
            printf(" %30s : %s\n", pf->name, pf->description);
        }
        printf("\n");
        LOG_I("NOTE-1: You can add more operations in a single command.");
        LOG_W("NOTE-2: These values are effective only after IC Reset.");
        printf("\n");
    }
    return SM_OK;
}
