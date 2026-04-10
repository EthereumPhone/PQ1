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

#define SOPT5_LPUART0RXSRC_LPUART_RX 0x00u /*!<@brief LPUART0 Receive Data Source Select: LPUART_RX pin */
#define SOPT5_LPUART0TXSRC_LPUART_TX 0x00u /*!<@brief LPUART0 Transmit Data Source Select: LPUART0_TX pin */

/*! @name PORTC6 (number 42), J1[1]/D0/UART0_RX_TGTMCU
  @{ */
#define BOARD_DEBUG_UART_RX_PERIPHERAL LPUART0               /*!<@brief Device name: LPUART0 */
#define BOARD_DEBUG_UART_RX_SIGNAL RX                        /*!<@brief LPUART0 signal: RX */
#define BOARD_DEBUG_UART_RX_PORT PORTC                       /*!<@brief PORT device name: PORTC */
#define BOARD_DEBUG_UART_RX_PIN 6U                           /*!<@brief PORTC pin index: 6 */
#define BOARD_DEBUG_UART_RX_PIN_NAME UART0_RX                /*!<@brief Pin name */
#define BOARD_DEBUG_UART_RX_LABEL "J1[1]/D0/UART0_RX_TGTMCU" /*!<@brief Label */
#define BOARD_DEBUG_UART_RX_NAME "DEBUG_UART_RX"             /*!<@brief Identifier name */
                                                             /* @} */

/*! @name PORTC7 (number 43), J1[2]/D1/UART0_TX_TGTMCU
  @{ */
#define BOARD_DEBUG_UART_TX_PERIPHERAL LPUART0               /*!<@brief Device name: LPUART0 */
#define BOARD_DEBUG_UART_TX_SIGNAL TX                        /*!<@brief LPUART0 signal: TX */
#define BOARD_DEBUG_UART_TX_PORT PORTC                       /*!<@brief PORT device name: PORTC */
#define BOARD_DEBUG_UART_TX_PIN 7U                           /*!<@brief PORTC pin index: 7 */
#define BOARD_DEBUG_UART_TX_PIN_NAME UART0_TX                /*!<@brief Pin name */
#define BOARD_DEBUG_UART_TX_LABEL "J1[2]/D1/UART0_TX_TGTMCU" /*!<@brief Label */
#define BOARD_DEBUG_UART_TX_NAME "DEBUG_UART_TX"             /*!<@brief Identifier name */
                                                             /* @} */

/*! @name PORTC2 (number 38), J2[10]/U9[4]/D15/I2C1_SCL
  @{ */
#define BOARD_ACCEL_SCL_PERIPHERAL I2C1                   /*!<@brief Device name: I2C1 */
#define BOARD_ACCEL_SCL_SIGNAL CLK                        /*!<@brief I2C1 signal: CLK */
#define BOARD_ACCEL_SCL_PORT PORTC                        /*!<@brief PORT device name: PORTC */
#define BOARD_ACCEL_SCL_PIN 2U                            /*!<@brief PORTC pin index: 2 */
#define BOARD_ACCEL_SCL_PIN_NAME I2C1_SCL                 /*!<@brief Pin name */
#define BOARD_ACCEL_SCL_LABEL "J2[10]/U9[4]/D15/I2C1_SCL" /*!<@brief Label */
#define BOARD_ACCEL_SCL_NAME "ACCEL_SCL"                  /*!<@brief Identifier name */
                                                          /* @} */

/*! @name PORTC3 (number 39), J2[9]/U9[6]/D14/I2C1_SDA
  @{ */
#define BOARD_ACCEL_SDA_PERIPHERAL I2C1                  /*!<@brief Device name: I2C1 */
#define BOARD_ACCEL_SDA_SIGNAL SDA                       /*!<@brief I2C1 signal: SDA */
#define BOARD_ACCEL_SDA_PORT PORTC                       /*!<@brief PORT device name: PORTC */
#define BOARD_ACCEL_SDA_PIN 3U                           /*!<@brief PORTC pin index: 3 */
#define BOARD_ACCEL_SDA_PIN_NAME I2C1_SDA                /*!<@brief Pin name */
#define BOARD_ACCEL_SDA_LABEL "J2[9]/U9[6]/D14/I2C1_SDA" /*!<@brief Label */
#define BOARD_ACCEL_SDA_NAME "ACCEL_SDA"                 /*!<@brief Identifier name */
                                                         /* @} */

/*! @name PORTA19 (number 7), J2[3]/D10/RGB_GREEN
  @{ */
#define BOARD_LED_GREEN_PERIPHERAL GPIOA            /*!<@brief Device name: GPIOA */
#define BOARD_LED_GREEN_SIGNAL GPIO                 /*!<@brief GPIOA signal: GPIO */
#define BOARD_LED_GREEN_GPIO GPIOA                  /*!<@brief GPIO device name: GPIOA */
#define BOARD_LED_GREEN_GPIO_PIN 19U                /*!<@brief PORTA pin index: 19 */
#define BOARD_LED_GREEN_PORT PORTA                  /*!<@brief PORT device name: PORTA */
#define BOARD_LED_GREEN_PIN 19U                     /*!<@brief PORTA pin index: 19 */
#define BOARD_LED_GREEN_CHANNEL 19                  /*!<@brief GPIOA GPIO channel: 19 */
#define BOARD_LED_GREEN_PIN_NAME PTA19              /*!<@brief Pin name */
#define BOARD_LED_GREEN_LABEL "J2[3]/D10/RGB_GREEN" /*!<@brief Label */
#define BOARD_LED_GREEN_NAME "LED_GREEN"            /*!<@brief Identifier name */
                                                    /* @} */

/*! @name PORTA18 (number 6), J2[6]/D13/RGB_BLUE
  @{ */
#define BOARD_LED_BLUE_PERIPHERAL GPIOA           /*!<@brief Device name: GPIOA */
#define BOARD_LED_BLUE_SIGNAL GPIO                /*!<@brief GPIOA signal: GPIO */
#define BOARD_LED_BLUE_GPIO GPIOA                 /*!<@brief GPIO device name: GPIOA */
#define BOARD_LED_BLUE_GPIO_PIN 18U               /*!<@brief PORTA pin index: 18 */
#define BOARD_LED_BLUE_PORT PORTA                 /*!<@brief PORT device name: PORTA */
#define BOARD_LED_BLUE_PIN 18U                    /*!<@brief PORTA pin index: 18 */
#define BOARD_LED_BLUE_CHANNEL 18                 /*!<@brief GPIOA GPIO channel: 18 */
#define BOARD_LED_BLUE_PIN_NAME PTA18             /*!<@brief Pin name */
#define BOARD_LED_BLUE_LABEL "J2[6]/D13/RGB_BLUE" /*!<@brief Label */
#define BOARD_LED_BLUE_NAME "LED_BLUE"            /*!<@brief Identifier name */
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
