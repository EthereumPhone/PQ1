/*
 *
 * Copyright 2018,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */
#if (__ARM_FEATURE_CMSE & 1) == 0
#error "Need ARMv8-M security extensions"
#elif (__ARM_FEATURE_CMSE & 2) == 0
#error "Compile with --cmse"
#endif

#include "fsl_common.h"
#include "fsl_rng.h"

#include "tzm_config.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief Application-specific implementation of the SystemInitHook() weak function.
 */
void SystemInitHook(void)
{
    /* The TrustZone should be configured as early as possible after RESET.
 * Therefore it is called from SystemInit() during startup. The SystemInitHook() weak function
 * overloading is used for this purpose.
*/
    BOARD_InitTrustZone();
}

// __attribute__((cmse_nonsecure_entry)) status_t SEC_RNG_GetRandomData(RNG_Type *base, void *data, size_t dataSize)
// {
//     return RNG_GetRandomData(base, data, dataSize);
// }

// __attribute__((cmse_nonsecure_entry)) void SEC_RNG_Init(RNG_Type *base)
// {
//     return RNG_Init(base);
// }
