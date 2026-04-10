/*
 * Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _LPC55S_SEC_RNG_H_
#define _LPC55S_SEC_RNG_H_

#include "fsl_common.h"
#include "fsl_rng.h"

/***********************************************************************************************************************
 * Definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * API
 **********************************************************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif

/* Required when CRYPTO_InitHardware is called from secure zone.
 * The definition for this function will be in secure zone.
 * This function will be called from non-secure zone.
 * See ksdk_mbedcrypto_entropy.c
 */

void SEC_RNG_Init(RNG_Type *base);

status_t SEC_RNG_GetRandomData(RNG_Type *base, void *data, size_t dataSize);

#if defined(__cplusplus)
}
#endif

/*!
 * @}
 */
#endif /* _LPC55S_SEC_RNG_H_ */

/***********************************************************************************************************************
 * EOF
 **********************************************************************************************************************/
