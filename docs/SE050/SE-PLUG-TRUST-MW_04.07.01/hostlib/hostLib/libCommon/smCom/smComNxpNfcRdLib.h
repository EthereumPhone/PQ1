/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _SMCOMNxpNfcRdLib_H_INC_
#define _SMCOMNxpNfcRdLib_H_INC_

#include "npRdLib/npRdLib.h"
#include "smCom.h"

/* ------------------------------------------------------------------------- */

/** TODO */
U16 smComNxpNfcRdLib_OpenVCOM(void **conn_ctx, const char * vPortName);

void smComNxpNfcRdLib_Close(void);

#endif /* _SMCOMNxpNfcRdLib_H_INC_ */
