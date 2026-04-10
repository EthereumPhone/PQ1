/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SA_QI_TX_PORT_H__
#define __SA_QI_TX_PORT_H__

#include <sm_types.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>

#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>

#include "nxEnsure.h"

#ifndef SSS_MALLOC
#define SSS_MALLOC sm_malloc
#endif // SSS_MALLOC

#ifndef SSS_FREE
#define SSS_FREE sm_free
#endif // SSS_FREE

#endif // __SA_QI_TX_PORT_H__
