/*
 * Copyright 2022 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if !defined(MBEDTLS_MCUX_FREERTOS_THREADING_ALT) && defined(MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT)
extern void CRYPTO_ConfigureThreading(void);
#endif

#include "mcux_els.h" // Power Down Wake-up Init
#include "mcux_pkc.h" // Power Down Wake-up Init
#include "platform_hw_ip.h"
#include "els_pkc_mbedtls.h"
#include "fsl_common.h"

#ifndef PKC
#define PKC PKC0
#endif

/******************************************************************************/
/*************************** Mutex ********************************************/
/******************************************************************************/
#if defined(MBEDTLS_THREADING_C)

/**
 * \def MBEDTLS_MCUX_FREERTOS_THREADING_ALT
 * You can comment this macro if you provide your own alternate implementation.
 *
 */
#if defined(SDK_OS_FREE_RTOS)
#define MBEDTLS_MCUX_FREERTOS_THREADING_ALT
#endif

/*
 * Define global mutexes for HW accelerator
 */
mbedtls_threading_mutex_t mbedtls_threading_hwcrypto_els_mutex;
mbedtls_threading_mutex_t mbedtls_threading_hwcrypto_pkc_mutex;

#if defined(MBEDTLS_MCUX_FREERTOS_THREADING_ALT)
/**
 * @brief Initializes the mbedTLS mutex functions.
 *
 * Provides mbedTLS access to mutex create, destroy, take and free.
 *
 * @see MBEDTLS_THREADING_ALT
 */
static void CRYPTO_ConfigureThreadingMcux(void);
#endif /* defined(MBEDTLS_MCUX_FREERTOS_THREADING_ALT) */

#endif /* defined(MBEDTLS_THREADING_C) */

static uint32_t g_isCryptoHWInitialized = ELS_PKC_CRYPTOHW_NONINITIALIZED;

__WEAK uint32_t __stack_chk_guard;

__WEAK void __stack_chk_fail(void)
{
    while (1)
    {
    };
}

int mbedtls_hw_init(void)
{
    status_t status;

    if (g_isCryptoHWInitialized == ELS_PKC_CRYPTOHW_NONINITIALIZED)
    {
        /* Enable ELS and related clocks */
        status = ELS_PowerDownWakeupInit(ELS);
        if (status != kStatus_Success)
        {
            return status;
        }

        /* Enable PKC related clocks without RAM zeroize */
        status = PKC_InitNoZeroize(PKC);
        if (status != kStatus_Success)
        {
            return status;
        }
    }
    else
    {
        return kStatus_Success;
    }

    return status;
}

/******************************************************************************/
/******************** CRYPTO_InitHardware **************************************/
/******************************************************************************/
/*!
 * @brief Application init for various Crypto blocks.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic init for Crypto Hw acceleration and Hw entropy modules.
 */
status_t CRYPTO_InitHardware(void)
{
    status_t status;
#if defined(MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT)

    CRYPTO_ConfigureThreadingMcux();

#endif /* (MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT) */

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_init(&mbedtls_threading_hwcrypto_els_mutex);
#endif /* (MBEDTLS_THREADING_C) */

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_init(&mbedtls_threading_hwcrypto_pkc_mutex);
#endif /* (MBEDTLS_THREADING_C) */
    /* Enable ELS and related clocks */
    status = ELS_PowerDownWakeupInit(ELS);
    if (status != kStatus_Success)
    {
        return kStatus_Fail;
    }

    /* Enable PKC related clocks and RAM zeroize */
    status = PKC_PowerDownWakeupInit(PKC);
    if (status != kStatus_Success)
    {
        return kStatus_Fail;
    }

    g_isCryptoHWInitialized = ELS_PKC_CRYPTOHW_INITIALIZED;

    return status;
}

/*-----------------------------------------------------------*/
/*--------- mbedTLS threading functions for FreeRTOS --------*/
/*--------------- See MBEDTLS_THREADING_ALT -----------------*/
/*-----------------------------------------------------------*/
#if defined(MBEDTLS_MCUX_FREERTOS_THREADING_ALT)
/* Threading mutex implementations for mbedTLS. */
#include "mbedtls/threading.h"
#include "threading_alt.h"

/**
 * @brief Implementation of mbedtls_mutex_init for thread-safety.
 *
 */
void mcux_mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex)
{
    mutex->mutex = xSemaphoreCreateMutex();

    if (mutex->mutex != NULL)
    {
        mutex->is_valid = 1;
    }
    else
    {
        mutex->is_valid = 0;
    }
}

/**
 * @brief Implementation of mbedtls_mutex_free for thread-safety.
 *
 */
void mcux_mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex)
{
    if (mutex->is_valid == 1)
    {
        vSemaphoreDelete(mutex->mutex);
        mutex->is_valid = 0;
    }
}

/**
 * @brief Implementation of mbedtls_mutex_lock for thread-safety.
 *
 * @return 0 if successful, MBEDTLS_ERR_THREADING_MUTEX_ERROR if timeout,
 * MBEDTLS_ERR_THREADING_BAD_INPUT_DATA if the mutex is not valid.
 */
int mcux_mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
    int ret = MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;

    if (mutex->is_valid == 1)
    {
        if (xSemaphoreTake(mutex->mutex, portMAX_DELAY))
        {
            ret = 0;
        }
        else
        {
            ret = MBEDTLS_ERR_THREADING_MUTEX_ERROR;
        }
    }

    return ret;
}

/**
 * @brief Implementation of mbedtls_mutex_unlock for thread-safety.
 *
 * @return 0 if successful, MBEDTLS_ERR_THREADING_MUTEX_ERROR if timeout,
 * MBEDTLS_ERR_THREADING_BAD_INPUT_DATA if the mutex is not valid.
 */
int mcux_mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
    int ret = MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;

    if (mutex->is_valid == 1)
    {
        if (xSemaphoreGive(mutex->mutex))
        {
            ret = 0;
        }
        else
        {
            ret = MBEDTLS_ERR_THREADING_MUTEX_ERROR;
        }
    }

    return ret;
}

static void CRYPTO_ConfigureThreadingMcux(void)
{
    /* Configure mbedtls to use FreeRTOS mutexes. */
    mbedtls_threading_set_alt(mcux_mbedtls_mutex_init, mcux_mbedtls_mutex_free, mcux_mbedtls_mutex_lock,
                              mcux_mbedtls_mutex_unlock);
}
#endif /* defined(MBEDTLS_MCUX_FREERTOS_THREADING_ALT) */
