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

/** @file  ecc_alt.h
 *  @brief common header of alternative ECC implementations with PKC IP
 */

#ifndef MBEDTLS_ECC_ALT_H
#define MBEDTLS_ECC_ALT_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/**
 * \brief                 This function sets up the domain parameters to be used in the
 *                        mcuxCl implementation, which requires big-endian input parameters
 *                        (the endianess of parameters is inverted).
 *
 * \param grp             The ECP group to use. This must be initialized and have
 *                        domain parameters loaded, for example through
 *                        mbedtls_ecp_load() or mbedtls_ecp_tls_read_group().
 * \param pDomainParams   Structure to hold the domain parameters in suitable format
 *                        for the mcuxCl implementation.The buffers for the parameters must be alocated
 *                        before this function is called.
 *
 * \retval                \c 0 on success.
 * \retval                \c MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED error code on failure.
 */
int mbedtls_ecp_setupDomainParams(mbedtls_ecp_group *grp, mcuxClEcc_DomainParam_t *pDomainParams);

#endif /* MBEDTLS_ECC_ALT_H */
