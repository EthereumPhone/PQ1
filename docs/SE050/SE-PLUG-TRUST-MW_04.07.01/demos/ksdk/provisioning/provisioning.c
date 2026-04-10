/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "provisioning.h"
#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <nxLog_App.h>

static ex_sss_boot_ctx_t gex_sss_provisioning_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_provisioning_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>
