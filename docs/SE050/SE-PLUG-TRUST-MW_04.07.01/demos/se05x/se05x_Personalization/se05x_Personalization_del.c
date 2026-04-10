/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file se05x_Personalization_del.c
 *
 * This file solves purpose for
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "se05x_Personalization.h"
#include "se05x_perso_api.h"
#include "nxEnsure.h"
#include "nxLog_hostLib.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

#define RM_PERSO_MOD(MOD_NAME)                                                              \
    smStatus_t ex_perso_RM_##MOD_NAME(pSe05xSession_t session_ctx)                          \
    {                                                                                       \
        smStatus_t status;                                                                  \
        const uint8_t rm_mod[] = SE05X_API_PERSO_##MOD_NAME;                                \
                                                                                            \
        status = Se05x_API_Perso_Set_DELETE_OS_MODULE(session_ctx, rm_mod, sizeof(rm_mod)); \
        ENSURE_OR_GO_CLEANUP(status == SM_OK);                                              \
    cleanup:                                                                                \
        return status;                                                                      \
    }
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

#if 0
smStatus_t ex_perso_RM_MOD_IOT_BASE(pSe05xSession_t session_ctx) {
    smStatus_t status;
    const uint8_t rm_mod[] = SE05X_API_PERSO_MOD_IOT_BASE;

    status = Se05x_API_Perso_Set_DELETE_OS_MODULE(
        session_ctx, rm_mod, sizeof(rm_mod));
    ENSURE_OR_GO_CLEANUP(status == SM_OK);
cleanup:
    return status;
}
#endif

RM_PERSO_MOD(MOD_IOT_BASE)

RM_PERSO_MOD(MOD_IOT_EXTENDED)

RM_PERSO_MOD(MODX_EGOVACCELERATORS)

RM_PERSO_MOD(MOD_RSAKEYGEN)

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */
