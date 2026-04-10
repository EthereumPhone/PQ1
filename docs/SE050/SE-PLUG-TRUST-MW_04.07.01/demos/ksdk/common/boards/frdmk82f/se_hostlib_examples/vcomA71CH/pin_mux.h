/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2018 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _PIN_MUX_H_
#define _PIN_MUX_H_

/***********************************************************************************************************************
 * Definitions
 **********************************************************************************************************************/

/*! @brief Direction type  */
typedef enum _pin_mux_direction
{
    kPIN_MUX_DirectionInput = 0U,        /* Input direction */
    kPIN_MUX_DirectionOutput = 1U,       /* Output direction */
    kPIN_MUX_DirectionInputOrOutput = 2U /* Input or output direction */
} pin_mux_direction_t;

/*!
 * @addtogroup pin_mux
 * @{
 */

/***********************************************************************************************************************
 * API
 **********************************************************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @brief Calls initialization functions.
 *
 */
void BOARD_InitBootPins(void);

/*! @name PORTC14 (number 86), OpenSDA_UART
  @{ */
#define BOARD_DEBUG_UART_RX_PERIPHERAL LPUART4   /*!<@brief Device name: LPUART4 */
#define BOARD_DEBUG_UART_RX_SIGNAL RX            /*!<@brief LPUART4 signal: RX */
#define BOARD_DEBUG_UART_RX_PORT PORTC           /*!<@brief PORT device name: PORTC */
#define BOARD_DEBUG_UART_RX_PIN 14U              /*!<@brief PORTC pin index: 14 */
#define BOARD_DEBUG_UART_RX_PIN_NAME LPUART4_RX  /*!<@brief Pin name */
#define BOARD_DEBUG_UART_RX_LABEL "OpenSDA_UART" /*!<@brief Label */
#define BOARD_DEBUG_UART_RX_NAME "DEBUG_UART_RX" /*!<@brief Identifier name */
                                                 /* @} */

/*! @name PORTC15 (number 87), OpenSDA_UART
  @{ */
#define BOARD_DEBUG_UART_TX_PERIPHERAL LPUART4   /*!<@brief Device name: LPUART4 */
#define BOARD_DEBUG_UART_TX_SIGNAL TX            /*!<@brief LPUART4 signal: TX */
#define BOARD_DEBUG_UART_TX_PORT PORTC           /*!<@brief PORT device name: PORTC */
#define BOARD_DEBUG_UART_TX_PIN 15U              /*!<@brief PORTC pin index: 15 */
#define BOARD_DEBUG_UART_TX_PIN_NAME LPUART4_TX  /*!<@brief Pin name */
#define BOARD_DEBUG_UART_TX_LABEL "OpenSDA_UART" /*!<@brief Label */
#define BOARD_DEBUG_UART_TX_NAME "DEBUG_UART_TX" /*!<@brief Identifier name */
                                                 /* @} */

/*! @name PORTA1 (number 37), J2[18]/J12[4]/U6[6]/D14/I2C SDA
  @{ */
#define BOARD_I2C_SDA_PERIPHERAL I2C3                         /*!<@brief Device name: I2C3 */
#define BOARD_I2C_SDA_SIGNAL SDA                              /*!<@brief I2C3 signal: SDA */
#define BOARD_I2C_SDA_PORT PORTA                              /*!<@brief PORT device name: PORTA */
#define BOARD_I2C_SDA_PIN 1U                                  /*!<@brief PORTA pin index: 1 */
#define BOARD_I2C_SDA_PIN_NAME I2C3_SDA                       /*!<@brief Pin name */
#define BOARD_I2C_SDA_LABEL "J2[18]/J12[4]/U6[6]/D14/I2C SDA" /*!<@brief Label */
#define BOARD_I2C_SDA_NAME "I2C_SDA"                          /*!<@brief Identifier name */
                                                              /* @} */

/*! @name PORTA2 (number 38), J2[20]J12[3]/J19[6]/U6[4]/I2C_SCL
  @{ */
#define BOARD_I2C_SCL_PERIPHERAL I2C3                           /*!<@brief Device name: I2C3 */
#define BOARD_I2C_SCL_SIGNAL SCL                                /*!<@brief I2C3 signal: SCL */
#define BOARD_I2C_SCL_PORT PORTA                                /*!<@brief PORT device name: PORTA */
#define BOARD_I2C_SCL_PIN 2U                                    /*!<@brief PORTA pin index: 2 */
#define BOARD_I2C_SCL_PIN_NAME I2C3_SCL                         /*!<@brief Pin name */
#define BOARD_I2C_SCL_LABEL "J2[20]J12[3]/J19[6]/U6[4]/I2C_SCL" /*!<@brief Label */
#define BOARD_I2C_SCL_NAME "I2C_SCL"                            /*!<@brief Identifier name */
                                                                /* @} */

/*!
 * @brief Configures pin routing and optionally pin electrical features.
 *
 */
void BOARD_InitPins(void);

#if defined(__cplusplus)
}
#endif

/*!
 * @}
 */
#endif /* _PIN_MUX_H_ */

/***********************************************************************************************************************
 * EOF
 **********************************************************************************************************************/
