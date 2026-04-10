/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2023 NXP                                                 */
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

/** @file  ecc_alt.c
 *  @brief common code for alternative ECC implementations with PKC IP
 */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdint.h>
#include <string.h>
#include <mcuxClEcc.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ccm.h>
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <ecc_alt.h>

/**
 * \brief                 This function sets up the domain parameters to be used in the
 *                        mcuxCl implementation, which requires big-endian input parameters
 *                        (the endianess of parameters is inverted).
 *
 * \param grp             The ECP group to use. This must be initialized and have
 *                        domain parameters loaded, for example through
 *                        mbedtls_ecp_load() or mbedtls_ecp_tls_read_group().
 * \param pDomainParams   Structure to hold the domain parameters in suitable format
 *                        for the mcuxCl implementation. The buffers for the parameters must be alocated
 *                        before this function is called.
 *
 * \retval                \c 0 on success.
 * \retval                \c MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED error code on failure.
 */
int mbedtls_ecp_setupDomainParams(mbedtls_ecp_group *grp, mcuxClEcc_DomainParam_t *pDomainParams)
{
    /* Byte-length of prime p. */
    const uint32_t pByteLength = (grp->pbits + 7u) / 8u;
    /* Byte-length of group-order n. */
    const uint32_t nByteLength = (grp->nbits + 7u) / 8u;

    pDomainParams->misc = (pByteLength & 0xFFu) | ((nByteLength << 8) & 0xFF00u);

    /* Convert endianess of domain parameters. */
    if (0 != mbedtls_mpi_write_binary(&grp->P, (unsigned char *)pDomainParams->pP, pByteLength))
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    /* For SECP R1 curves, MBEDTLS does not provide curve parameter a; calculate it here as follows: a = p - 3 */
    if ((MBEDTLS_ECP_DP_SECP192R1 == grp->id) || (MBEDTLS_ECP_DP_SECP256R1 == grp->id) ||
        (MBEDTLS_ECP_DP_SECP521R1 == grp->id) || (MBEDTLS_ECP_DP_SECP384R1 == grp->id))
    {
        // only correct for secp192r1, secp256r1, secp384r1, secp521r1
        if (0 != mbedtls_mpi_write_binary(&grp->P, (unsigned char *)pDomainParams->pA, pByteLength))
        {
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        }
        uint8_t last_byte = pDomainParams->pA[pByteLength - 1u] - 3u;
        (void)memcpy((void *)(pDomainParams->pA + pByteLength - 1u), (void const *)&last_byte, 1);
    }
    else if (MBEDTLS_ECP_DP_SECP224R1 == grp->id)
    {
        // can also be done by memcpy P[0:16]*2 -> A and A[16] -= 1, A[pByteLength-1] -= 1
        const uint8_t A[28u] = {0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU};
        (void)memcpy((void *)pDomainParams->pA, (void const *)A, pByteLength);
    }
    else
    {
        if (0 != mbedtls_mpi_write_binary(&grp->A, (unsigned char *)pDomainParams->pA, pByteLength))
        {
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        }
    }
    if (0 != mbedtls_mpi_write_binary(&grp->B, (unsigned char *)pDomainParams->pB, pByteLength))
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (0 != mbedtls_mpi_write_binary(&grp->G.X, (unsigned char *)pDomainParams->pG, pByteLength))
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (0 != mbedtls_mpi_write_binary(&grp->G.Y, (unsigned char *)pDomainParams->pG + pByteLength, pByteLength))
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (0 != mbedtls_mpi_write_binary(&grp->N, (unsigned char *)pDomainParams->pN, nByteLength))
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    return 0;
}
