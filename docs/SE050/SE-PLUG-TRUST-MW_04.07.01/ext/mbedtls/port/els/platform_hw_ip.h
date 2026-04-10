/*--------------------------------------------------------------------------*/
/* Copyright 2021 NXP                                                       */
/*                                                                          */
/* NXP Confidential. This software is owned or controlled by NXP and may    */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms. If you do not agree to be bound by the applicable license */
/* terms, then you may not retain, install, activate or otherwise use the   */
/* software.                                                                */
/*--------------------------------------------------------------------------*/

/** @file  platform_hw_ip.h
 *  @brief header of hardware IP functions for mbedTLS
 */

#ifndef PLATFORM_HW_IP_H
#define PLATFORM_HW_IP_H

#include <mcuxClEls.h>
#include <mcuxClMemory.h>

/**
 * \brief Initialization function for MCUX HW IPs. It shall be called by all alternative implementations of mbedTLS
 * functions that make use of MCUX HW IPs.
 */
extern int mbedtls_hw_init(void);

#endif /* PLATFORM_HW_IP_H */
