/*
 *
 * Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DEMOS_SE05X_TLA_H_
#define DEMOS_SE05X_TLA_H_

#include <ex_sss_boot.h>

/** Open an Authenticated session to SE050 using
 * the reserved key Transport Lock. */
sss_status_t se05x_TA_OpenAuthSession(ex_sss_boot_ctx_t *pCtx, sss_session_t *pTxSession, sss_tunnel_t *ptxTunnel);

/** Create Key on the Host so that host crypto can use it
 * during authenticaiton */
sss_status_t se05x_TA_CreateHostKey(ex_sss_boot_ctx_t *pCtx);

/** Transport Auth session is authenticated using transport Obj
 */
smStatus_t se05x_TA_CreateSETransportLockKey(Se05xSession_t *pSe05xSession);

#endif //DEMOS_SE05X_TLA_H_
