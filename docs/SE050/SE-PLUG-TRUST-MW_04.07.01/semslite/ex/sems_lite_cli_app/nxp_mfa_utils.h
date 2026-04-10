/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#ifndef NXP_MFA_UTILS_H_INCLUDED
#define NXP_MFA_UTILS_H_INCLUDED

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <sems_lite_agent_context.h>

void prepareTear(uint32_t tear_time);

void mfa_process_loadpkg_with_tear(const char *pkgname, uint32_t tear_time);
#endif //NXP_MFA_UTILS_H_INCLUDED