/**
* @file accessManager_com.c
* @author NXP Semiconductors
* @version 1.0
* @par License
*
* Copyright 2016,2020 NXP
* SPDX-License-Identifier: Apache-2.0
*
* @par Description
* This file implements basic communication functionality between Host and
* Secure element.
* @par History
*
*****************************************************************************/
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "nxLog_App.h"
#include "accessManager_com.h"
