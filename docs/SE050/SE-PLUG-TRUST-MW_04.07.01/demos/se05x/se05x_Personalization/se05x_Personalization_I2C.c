/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file se05x_Personalization_I2C.c
 *
 * This file solves purpose for
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "se05x_Personalization.h"
#include <se05x_perso_api.h>
#include <se05x_perso_cnst.h>
#include <nxEnsure.h>
#include <nxLog_App.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

#define I2C_SET_API(NAME, DEF_NAME)                                                    \
    smStatus_t ex_perso_I2C_##NAME(pSe05xSession_t session_ctx)                        \
    {                                                                                  \
        smStatus_t status;                                                             \
        uint8_t i2c_params = 0;                                                        \
        status             = Se05x_API_Perso_Get_I2C_PARAMS(session_ctx, &i2c_params); \
        ENSURE_OR_GO_CLEANUP(status == SM_OK);                                         \
        i2c_params |= SE05X_PERSO_I2C_PARAMS_SET_##DEF_NAME;                           \
        status = Se05x_API_Perso_Set_I2C_PARAMS(session_ctx, i2c_params);              \
        ENSURE_OR_GO_CLEANUP(status == SM_OK);                                         \
    cleanup:                                                                           \
        return status;                                                                 \
    }

#define I2C_MSK_API(NAME, DEF_NAME)                                                    \
    smStatus_t ex_perso_I2C_##NAME(pSe05xSession_t session_ctx)                        \
    {                                                                                  \
        smStatus_t status;                                                             \
        uint8_t i2c_params = 0;                                                        \
        status             = Se05x_API_Perso_Get_I2C_PARAMS(session_ctx, &i2c_params); \
        ENSURE_OR_GO_CLEANUP(status == SM_OK);                                         \
        i2c_params &= SE05X_PERSO_I2C_PARAMS_MSK_##DEF_NAME;                           \
        status = Se05x_API_Perso_Set_I2C_PARAMS(session_ctx, i2c_params);              \
        ENSURE_OR_GO_CLEANUP(status == SM_OK);                                         \
    cleanup:                                                                           \
        return status;                                                                 \
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

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

#if 0
smStatus_t ex_perso_I2CEnableCLockStretching2(pSe05xSession_t session_ctx) {
    smStatus_t status;
    uint8_t i2c_params = 0;
    status = Se05x_API_Perso_Get_I2C_PARAMS(session_ctx, &i2c_params);
    ENSURE_OR_GO_CLEANUP(status == SM_OK);
    i2c_params |= (SE05X_PERSO_I2C_PARAMS_SET_SLAVE_CLK_STRCH);
    status = Se05x_API_Perso_Set_I2C_PARAMS(session_ctx, i2c_params);
    ENSURE_OR_GO_CLEANUP(status == SM_OK);
cleanup:
    return status;
}

smStatus_t ex_perso_I2CDisableClockStretching2(pSe05xSession_t session_ctx) {
    smStatus_t status;
    uint8_t i2c_params = 0;
    status = Se05x_API_Perso_Get_I2C_PARAMS(session_ctx, &i2c_params);
    ENSURE_OR_GO_CLEANUP(status == SM_OK);
    i2c_params &= SE05X_PERSO_I2C_PARAMS_MSK_SLAVE_CLK_STRCH;
    status = Se05x_API_Perso_Set_I2C_PARAMS(session_ctx, i2c_params);
    ENSURE_OR_GO_CLEANUP(status == SM_OK);
cleanup:
    return status;
}

#endif

I2C_SET_API(EnableCLockStretching, CLK_STRCH_ENABLED)
I2C_MSK_API(DisableClockStretching, CLK_STRCH_DISABLED)

I2C_SET_API(ProtocolGP, I2C_GP)
I2C_MSK_API(ProtocolUM, I2C_UM)

I2C_SET_API(EnablePowerSave, PWR_SAVE_ENABLED)
I2C_MSK_API(DisablePowerSave, PWR_SAVE_DISABLED)

I2C_SET_API(SemiBlocking, I2C_SEMI_BLOCKING)
I2C_MSK_API(NonBlocking, I2C_NON_BLOCKING)

I2C_MSK_API(ProtocolAutoDetect, PROTO_DETECT_AUTO)
I2C_SET_API(ProtocolManual, PROTO_SEL_MANUAL)
