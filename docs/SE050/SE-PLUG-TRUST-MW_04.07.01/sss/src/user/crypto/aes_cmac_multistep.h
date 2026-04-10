/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __AES_CMAC_MULTI_STEP_H__
#define __AES_CMAC_MULTI_STEP_H__

#include <string.h>
#include <stdlib.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_USER
#include "aes_cmac.h"
void aes_cmac_onego(aes_ctx_t *context, uint8_t *input, unsigned long length, uint8_t *key, uint8_t *mac_value);
void aes_cmac_update(
    aes_ctx_t *context, uint8_t *input, uint8_t *IV, unsigned long length, uint8_t *key, uint8_t *mac_value);
void aes_cmac_finish(
    aes_ctx_t *context, uint8_t *input, uint8_t *IV, unsigned long length, uint8_t *key, uint8_t *mac_value);

#endif //#if SSS_HAVE_HOSTCRYPTO_USER
#endif
