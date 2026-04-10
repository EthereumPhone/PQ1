/**
 *
 * Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 *****************************************************************************/

#ifndef SM_COM_THREAD_H
#define SM_COM_THREAD_H

#include "smCom.h"

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * closes communication layer.
 *
 * @return
 */
U16 smComThread_Close(void);

/**
 * Initializes the communication layer.
 *
 * @return
 */
U16 smComThread_Open(U8 *Threadatr, U16 *ThreadatrLen);

#if defined(__cplusplus)
}
#endif

#endif /* SM_COM_THREAD_H */
