/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file se05x_Personalization.h
 *
 * This file solves purpose for
 */

#ifndef DEMOS_SE05X_SE05X_PERSONALIZATION_SE05X_PERSONALIZATION_H_
#define DEMOS_SE05X_SE05X_PERSONALIZATION_SE05X_PERSONALIZATION_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <ex_sss_boot.h>

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

/** Personalization infterface */

typedef smStatus_t (*ex_perso_api_t)(pSe05xSession_t session_ctx);
typedef struct
{
    const char *name;
    const char *description;
    ex_perso_api_t fpAPI;
} ex_perso_if_t;

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

smStatus_t ex_perso_HELP(pSe05xSession_t session_ctx);

smStatus_t ex_perso_OpenApplet(pSe05xSession_t session_ctx);

smStatus_t ex_perso_I2C_EnableCLockStretching(pSe05xSession_t session_ctx);
smStatus_t ex_perso_I2C_DisableClockStretching(pSe05xSession_t session_ctx);

smStatus_t ex_perso_I2C_ProtocolGP(pSe05xSession_t session_ctx);
smStatus_t ex_perso_I2C_ProtocolUM(pSe05xSession_t session_ctx);

smStatus_t ex_perso_I2C_ProtocolAutoDetect(pSe05xSession_t session_ctx);
smStatus_t ex_perso_I2C_ProtocolManual(pSe05xSession_t session_ctx);

smStatus_t ex_perso_I2C_EnablePowerSave(pSe05xSession_t session_ctx);
smStatus_t ex_perso_I2C_DisablePowerSave(pSe05xSession_t session_ctx);

smStatus_t ex_perso_I2C_SemiBlocking(pSe05xSession_t session_ctx);
smStatus_t ex_perso_I2C_NonBlocking(pSe05xSession_t session_ctx);

smStatus_t ex_perso_RM_MOD_IOT_BASE(pSe05xSession_t session_ctx);
smStatus_t ex_perso_RM_MOD_IOT_EXTENDED(pSe05xSession_t session_ctx);
smStatus_t ex_perso_RM_MODX_EGOVACCELERATORS(pSe05xSession_t session_ctx);
smStatus_t ex_perso_RM_MOD_RSAKEYGEN(pSe05xSession_t session_ctx);

#endif /* DEMOS_SE05X_SE05X_PERSONALIZATION_SE05X_PERSONALIZATION_H_ */
