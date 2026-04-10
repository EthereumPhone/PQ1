/*
*
* Copyright 2019,2020 NXP
* SPDX-License-Identifier: Apache-2.0
*/

/* clang-format off */

#include "ex_sss_boot.h"
#include "fsl_sss_api.h"
#include "fsl_sss_ftr.h"

#if SSS_HAVE_ECC && SSS_HAVE_RSA
#define C_FEATURES kSE05x_AppletConfig_ECDSA_ECDH_ECDHE |                \
                    kSE05x_AppletConfig_EDDSA |                           \
                    kSE05x_AppletConfig_DH_MONT |                         \
                    kSE05x_AppletConfig_HMAC |                            \
                    kSE05x_AppletConfig_RSA_PLAIN |                       \
                    kSE05x_AppletConfig_RSA_CRT |                         \
                    kSE05x_AppletConfig_AES |                             \
                    kSE05x_AppletConfig_DES |                             \
                    kSE05x_AppletConfig_PBKDF |                           \
                    kSE05x_AppletConfig_TLS |                             \
                    kSE05x_AppletConfig_MIFARE |                          \
                    kSE05x_AppletConfig_I2CM

#elif SSS_HAVE_ECC
#define A_FEATURES kSE05x_AppletConfig_DES |                             \
                    kSE05x_AppletConfig_PBKDF |                           \
                    kSE05x_AppletConfig_TLS |                             \
                    kSE05x_AppletConfig_AES |                             \
                    kSE05x_AppletConfig_HMAC |                            \
                    kSE05x_AppletConfig_DH_MONT |                         \
                    kSE05x_AppletConfig_ECDSA_ECDH_ECDHE

#elif SSS_HAVE_RSA
#define B_FEATURES kSE05x_AppletConfig_DES |                             \
                    kSE05x_AppletConfig_PBKDF |                           \
                    kSE05x_AppletConfig_TLS |                             \
                    kSE05x_AppletConfig_HMAC |                            \
                    kSE05x_AppletConfig_RSA_PLAIN |                       \
                    kSE05x_AppletConfig_RSA_CRT |                         \
                    kSE05x_AppletConfig_AES |                             \
                    kSE05x_AppletConfig_DH_MONT
#endif

/* clang-format ON */


sss_status_t session_open_with_feature_id(ex_sss_boot_ctx_t *pCtx);
sss_status_t ex_sss_se05x_prepare_host_EX(sss_session_t *host_session, sss_key_store_t *host_ks, SE_Connect_Ctx_t *se05x_open_ctx, ex_SE05x_authCtx_t *se05x_auth_ctx, SE_AuthType_t auth_type);
sss_status_t ex_sss_se05x_prepare_host_eckey_EX(SE05x_AuthCtx_ECKey_t *pAuthCtx, ex_SE05x_authCtx_t *pEx_auth, sss_key_store_t *pKs);
sss_status_t Alloc_ECKeykey_toSE05xAuthctx_EX(sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId, sss_key_part_t keypart);
sss_status_t Alloc_Scp03key_toSE05xAuthctx_EX(sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId);
