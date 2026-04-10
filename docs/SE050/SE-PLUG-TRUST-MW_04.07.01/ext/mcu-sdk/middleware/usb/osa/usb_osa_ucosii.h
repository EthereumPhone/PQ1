/*
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_OSA_UCOSII_H__
#define __USB_OSA_UCOSII_H__

#include "ucos_ii.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define USB_OSA_SR_ALLOC() uint8_t usb_osa_current_sr;
#define USB_OSA_ENTER_CRITICAL() USB_OsaEnterCritical(&usb_osa_current_sr)
#define USB_OSA_EXIT_CRITICAL() USB_OsaExitCritical(usb_osa_current_sr)

/*******************************************************************************
 * API
 ******************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif

extern void USB_OsaEnterCritical(uint8_t *sr);
extern void USB_OsaExitCritical(uint8_t sr);

#if defined(__cplusplus)
}
#endif

#endif /* __USB_OSA_UCOSII_H__ */
