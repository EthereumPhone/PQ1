/**
 * @file ax_embSeEngine_Internal.h
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017,2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Engine for Embedded Secure Element (A70CM/CI, A71CH)
 * Definitions and types with local scope
 */

#ifndef AX_EMB_SE_ENGINE_INTERNAL_H
#define AX_EMB_SE_ENGINE_INTERNAL_H

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <ex_sss_boot.h>
#include <fsl_sss_api.h>

extern ex_sss_boot_ctx_t *gpCtx;

#define AX_ENGINE_SUPPORTS_RAND

#if SSS_HAVE_APPLET_SE05X_IOT
#include <fsl_sss_se05x_types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// <Conditionally activate features at compile time>
#define PRIVATE_KEY_HANDOVER_TO_SW
#define PUBLIC_KEY_HANDOVER_TO_SW
// </Conditionally activate features at compile time>

// Looking for a key reference in a key object can lead to either of the following results
#define AX_ENGINE_INVOKE_NOTHING 0 // Do no nothing, key object is not valid
#define AX_ENGINE_INVOKE_SE 1 // Found a reference to a key contained in the Secure Element
#define AX_ENGINE_INVOKE_OPENSSL_SW 2 // Pass on key object to OpenSSL SW implementation

#define ECC_PUB_KEY_ASN1_DECORATION_SECP256R1                                                                         \
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, \
        0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00

#define ECC_PUB_KEY_ASN1_DECORATION_SECP384R1                                                                         \
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, \
        0x22, 0x03, 0x62, 0x00

#define LOG_FLOW_MASK 0x01
#define LOG_DBG_MASK 0x02
#define LOG_ERR_MASK 0x04

#define LOG_FLOW_ON 0x01
#define LOG_DBG_ON 0x02
#define LOG_ERR_ON 0x04

void EmbSe_Print(int flag, const char *format, ...);
void EmbSe_PrintPayload(int flag, const U8 *pPayload, U16 nLength, const char *title);

#define EMBSE_ENSURE_OR_GO_EXIT(CONDITION) \
    if (!(CONDITION)) {                    \
        goto exit;                         \
    }

#define EMBSE_ENSURE_OR_GO_EXIT_WITH_MSG(CONDITION, MSG) \
    if (!(CONDITION)) {                                  \
        EmbSe_Print(LOG_ERR_ON, MSG);                    \
        goto exit;                                       \
    }

#define EMBSE_ENSURE_OR_GO_ERR_WITH_MSG(CONDITION, MSG) \
    if (!(CONDITION)) {                                 \
        EmbSe_Print(LOG_ERR_ON, MSG);                   \
        goto err;                                       \
    }

int EmbSe_Simple_Key_gen(EC_KEY *key);
int setup_ec_key_method(void);
int setup_load_priv_key_method(ENGINE *e);
sss_algorithm_t getSignAlgorithmfromSHAtype(int type);
sss_algorithm_t getEncryptAlgorithmfromPaddingType(int padding, int bit_length);
int setup_rsa_key_method(void);
EVP_PKEY_METHOD *EmbSe_assign_x25519_pkey_meth(void);
EVP_PKEY_METHOD *EmbSe_assign_x448_pkey_meth(void);
int setup_pkey_methods(ENGINE *e, EVP_PKEY_METHOD **pkey_meth, const int **nid_list, int nid);

#ifdef __cplusplus
}
#endif

#endif // AX_EMB_SE_ENGINE_INTERNAL_H
