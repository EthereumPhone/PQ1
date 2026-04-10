/*
 * Copyright 2019-2021, 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include "board.h"
#include "fsl_usart_freertos.h"
#include "serial_mwm_port.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define SERIAL_MWM_PORT_NVIC_PRIO 5

/* Ring buffer size */
#define RING_BUFFER_SIZE 2048

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
static uint8_t s_background_buffer[RING_BUFFER_SIZE];

static usart_rtos_handle_t s_handle;
static usart_handle_t s_t_handle;

static struct rtos_usart_config s_usart_config = {
    .baudrate    = 115200,
    .parity      = kUSART_ParityDisabled,
    .stopbits    = kUSART_OneStopBit,
    .buffer      = s_background_buffer,
    .buffer_size = sizeof(s_background_buffer),
};

/*******************************************************************************
 * Code
 ******************************************************************************/
int mwm_rx(uint8_t *read_buf, uint32_t len)
{
    if ((read_buf == NULL) || (len == 0u))
    {
        return -1;
    }

    int error;
    size_t n = 0;
    error    = USART_RTOS_Receive(&s_handle, (uint8_t *)read_buf, len, &n);
    if (error == kStatus_Success)
    {
        return 0;
    }

    return -1;
}

int mwm_tx(uint8_t *write_buf, uint32_t len)
{
    if ((write_buf == NULL) || (len == 0u))
    {
        return -1;
    }

    int error;
    error = USART_RTOS_Send(&s_handle, (uint8_t *)write_buf, len);
    if (error == kStatus_Success)
    {
        return 0;
    }

    return -1;
}

int mwm_port_init(void)
{
#if defined(BOARD_SERIAL_MWM_PORT) && defined(BOARD_SERIAL_MWM_PORT_CLK_FREQ) && defined(BOARD_SERIAL_MWM_PORT_IRQn)
    s_usart_config.srcclk = BOARD_SERIAL_MWM_PORT_CLK_FREQ;
    s_usart_config.base   = BOARD_SERIAL_MWM_PORT;

    NVIC_SetPriority(BOARD_SERIAL_MWM_PORT_IRQn, SERIAL_MWM_PORT_NVIC_PRIO);
#else
/*
 * Example of USART settings:
 * #define BOARD_SERIAL_MWM_PORT_CLK_FREQ CLOCK_GetFlexCommClkFreq(2)
 * #define BOARD_SERIAL_MWM_PORT          USART2
 * #define BOARD_SERIAL_MWM_PORT_IRQn     FLEXCOMM2_IRQn
 */
#warning "Define BOARD_SERIAL_MWM_PORT, BOARD_SERIAL_MWM_PORT_CLK_FREQ, BOARD_SERIAL_MWM_PORT_IRQn in board.h"
#endif

    if (0 > USART_RTOS_Init(&s_handle, &s_t_handle, &s_usart_config))
    {
        return -1;
    }

    return 0;
}

int mwm_port_deinit(void)
{
    if (0 > USART_RTOS_Deinit(&s_handle))
    {
        return -1;
    }

    return 0;
}
