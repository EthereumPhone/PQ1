/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sa_qi_auth.h"

ex_sss_boot_ctx_t gex_qi_auth_ctx;
pSe05xSession_t pgSe05xSessionctx = &(((sss_se05x_session_t *)&gex_qi_auth_ctx.session)->s_ctx);

#define EX_SSS_BOOT_PCONTEXT (&gex_qi_auth_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>
