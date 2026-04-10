/* Copyright 2018 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef HOSTLIB_HOSTLIB_LIBCOMMON_SMCOM_SMCOMPN7150_H_
#define HOSTLIB_HOSTLIB_LIBCOMMON_SMCOM_SMCOMPN7150_H_

#include "sm_types.h"


/**
* Opens connection.
* @return
*/
U16 smComPN7150_Init(void);

U16 smComPN7150_Open(U8 mode, U8 seqCnt, U8 *T1oI2Catr, U16 *T1oI2CatrLen);


#endif /* HOSTLIB_HOSTLIB_LIBCOMMON_SMCOM_SMCOMPN7150_H_ */
