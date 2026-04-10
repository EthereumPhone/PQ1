/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SE05X_MULTITHREADED_DEMO_H
#define SE05X_MULTITHREADED_DEMO_H
/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <ex_sss.h>
#if defined(AX_EMBEDDED) && (AX_EMBEDDED == 1)
#include <ex_sss_boot.h>
#endif
#include "ex_sss_auth.h"

/*******************************************************************
* Defines
*******************************************************************/

#if defined(FRDM_KW41Z) || defined(FRDM_K64F) || defined(IMX_RT) || defined(LPC_55x) || defined(QN9090DK6) || \
    defined(CPU_MCXN947VDF_cm33_core0)
#define HAVE_KSDK
#endif

#if (SSS_HAVE_SE05X_AUTH_USERID) || (SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03) //UserID Session
#define TST_LOCAL_OBJ_AUTH_ID_USER1 EX_SSS_AUTH_SE05X_UserID_AUTH_ID + USER1
#define TST_LOCAL_OBJ_AUTH_ID_USER2 EX_SSS_AUTH_SE05X_UserID_AUTH_ID + USER2
#elif (SSS_HAVE_SE05X_AUTH_NONE) || (SSS_HAVE_SE05X_AUTH_PLATFSCP03) //No auth
#define TST_LOCAL_OBJ_AUTH_ID_USER1 EX_SSS_AUTH_SE05X_NONE_AUTH_ID + USER1
#define TST_LOCAL_OBJ_AUTH_ID_USER2 EX_SSS_AUTH_SE05X_NONE_AUTH_ID + USER1
#elif (SSS_HAVE_SE05X_AUTH_AESKEY) || (SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03) //AESKey
#define TST_LOCAL_OBJ_AUTH_ID_USER1 EX_SSS_AUTH_SE05X_APPLETSCP_AUTH_ID + USER1
#define TST_LOCAL_OBJ_AUTH_ID_USER2 EX_SSS_AUTH_SE05X_APPLETSCP_AUTH_ID + USER2
#elif (SSS_HAVE_SE05X_AUTH_ECKEY) || (SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03) //ECKey session
#define TST_LOCAL_OBJ_AUTH_ID_USER1 EX_SSS_AUTH_SE05X_ECKEY_ECDSA_AUTH_ID + USER1
#define TST_LOCAL_OBJ_AUTH_ID_USER2 EX_SSS_AUTH_SE05X_ECKEY_ECDSA_AUTH_ID + USER2
#endif

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

typedef struct demoCtx_t
{
    sss_session_t session;
    sss_key_store_t ks;
    sss_object_t key;
    sss_object_t public_key;
    sss_asymmetric_t asymm;

#if SSS_HAVE_APPLET_SE05X_IOT
    sss_session_t hostSession;
    sss_key_store_t hostKs;
    SE_Connect_Ctx_t se05x_AuthCtx;
    SE_Connect_Ctx_t se05x_ChannelCtx;
    sss_tunnel_t *tunnel_ctx;
    ex_SE05x_authCtx_t tst_se05x_auth;
    sss_se05x_session_t *pSession_SE05x;
#endif
} demoCtx_t;

extern void setup_se05x(void);
extern void cleanup_se05x(void);
extern void *Sign_Verify_eccsecp256r1_sha224_guser1(void *ptr);
extern void *Sign_Verify_eccsecp256r1_sha512_user2(void *ptr);
#endif /* SE05X_MULTITHREADED_DEMO_H */