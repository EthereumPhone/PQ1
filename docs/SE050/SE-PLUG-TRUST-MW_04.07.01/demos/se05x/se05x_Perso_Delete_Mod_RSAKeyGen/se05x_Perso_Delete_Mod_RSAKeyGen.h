/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file se05x_Perso_Delete_Mod_RSAKeyGen.h
 *
 * This file solves purpose for
 */

#ifndef DEMOS_SE05X_PERSO_DELETE_MOD_RSA_KEYGEN_H
#define DEMOS_SE05X_PERSO_DELETE_MOD_RSA_KEYGEN_H

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

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

smStatus_t ex_perso_OpenApplet(pSe05xSession_t session_ctx);
smStatus_t ex_perso_RM_MOD_RSAKEYGEN(pSe05xSession_t session_ctx);

#endif /* DEMOS_SE05X_PERSO_DELETE_MOD_RSA_KEYGEN_H */
