/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __PSA_ALT_SE_DRIVER_H__
#define __PSA_ALT_SE_DRIVER_H__

#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
// psa_se_drv_table_entry_t driver_table[PSA_MAX_SE_DRIVERS];

/* Register SE05x driver with PSA library */
psa_status_t psa_alt_register_se_driver(void);

#endif // __PSA_ALT_SE_DRIVER_H__