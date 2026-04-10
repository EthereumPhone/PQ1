/*
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_OSA_UCOSIII_H__
#define __USB_OSA_UCOSIII_H__

#include "os.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define USB_OSA_SR_ALLOC() CPU_SR_ALLOC()
#define USB_OSA_ENTER_CRITICAL() CPU_CRITICAL_ENTER()
#define USB_OSA_EXIT_CRITICAL() CPU_CRITICAL_EXIT()

#endif /* __USB_OSA_UCOSIII_H__ */
