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

/** @file  ctr_drbg_alt.h
 *  @brief header of alternative RNG implementation with CSS IP
 */


#if defined(MBEDTLS_CTR_DRBG_ALT)

typedef struct mbedtls_ctr_drbg_context {
    int prediction_resistance;          /*!< This implementation does not support reseeding
                                            setting this option will result in errors when requesting rng values */

} mbedtls_ctr_drbg_context;

#endif /* MBEDTLS_CTR_DRBG_ALT */
