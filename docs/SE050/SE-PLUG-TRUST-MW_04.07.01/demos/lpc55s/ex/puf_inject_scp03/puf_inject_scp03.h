/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __PUF_PAIR_S_H__
#define __PUF_PAIR_S_H__

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <ex_sss_scp03_keys.h>
#include <ex_scp03_puf.h>

#define PUF_INTRINSIC_KEY_SIZE 16

/* Key codes for PUF Index 1 */
uint8_t keyCodeENC_01[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)] = {0};
uint8_t keyCodeMAC_01[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)] = {0};
uint8_t keyCodeDEK_01[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)] = {0};

#endif // __PUF_PAIR_S_H__