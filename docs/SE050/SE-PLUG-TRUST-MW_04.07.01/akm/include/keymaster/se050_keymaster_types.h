/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYSTEM_KEYMASTER_SE050_KEYMASTER_TYPES_H_
#define SYSTEM_KEYMASTER_SE050_KEYMASTER_TYPES_H_

//#include <cstdlib>
//#include <map>
//#include <vector>

#include <hardware/keymaster0.h>
#include <hardware/keymaster1.h>
#include <hardware/keymaster2.h>

#include <keymaster/android_keymaster.h>
#include <keymaster/soft_keymaster_context.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#include "fsl_sss_api.h"
#include "nxEnsure.h"

#if defined(__cplusplus)
}
#endif

namespace keymaster {

#define TP_MAGIC                                                                                   \
    { 0xa5, 0xa6, 0xb5, 0xb6, 0xa5, 0xa6, 0xb5, 0xb6 }

#define AES_BLOCK_SIZE 16
#define GCM_NONCE_SIZE 12

typedef enum {
    kOperation_SSS_KM_None,
    kOperation_SSS_KM_Asymm,
    kOperation_SSS_KM_Symm,
    kOperation_SSS_KM_Mac,
} sss_km_operation_type;

typedef struct _asymmetric_context {
    sss_asymmetric_t asymm_ctx;
    keymaster_digest_t digest;
    keymaster_padding_t padding;
    Buffer update_ec_buf;
    Buffer update_rsa_buf;
} sss_km_asymmetric_context_t;

typedef struct _symmetric_context {
    sss_symmetric_t symm_ctx;
    sss_aead_t aead_ctx;
    keymaster_block_mode_t block_mode;
    keymaster_padding_t padding;
    uint8_t iv[16];
    size_t ivLen;
    uint8_t tag[16];
    size_t tagLen;
    bool data_started;
} sss_km_symmetric_context_t;

typedef struct _mac_context {
    sss_mac_t mac_ctx;
    uint32_t mac_length;
} sss_km_mac_context_t;

typedef struct {
    sss_km_operation_type op_type;
    union {
        sss_km_asymmetric_context_t op_asymm;
        sss_km_symmetric_context_t op_symm;
        sss_km_mac_context_t op_mac;
    } op_handle;
} sss_km_operation_t;

};  // namespace keymaster
#endif
