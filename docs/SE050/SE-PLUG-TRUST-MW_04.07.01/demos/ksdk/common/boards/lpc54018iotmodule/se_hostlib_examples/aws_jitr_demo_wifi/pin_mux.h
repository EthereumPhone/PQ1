/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2017 NXP
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
  kPIN_MUX_DirectionInput = 0U,         /* Input direction */
  kPIN_MUX_DirectionOutput = 1U,        /* Output direction */
  kPIN_MUX_DirectionInputOrOutput = 2U  /* Input or output direction */
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

#define PIO017_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO017_FUNC_ALT7 0x07u        /*!<@brief Selects pin function.: Alternative connection 7. */
#define PIO323_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO323_FUNC_ALT1 0x01u        /*!<@brief Selects pin function.: Alternative connection 1. */
#define PIO324_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO324_FUNC_ALT1 0x01u        /*!<@brief Selects pin function.: Alternative connection 1. */
#define PIO410_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO410_FUNC_ALT1 0x01u        /*!<@brief Selects pin function.: Alternative connection 1. */
#define PIO411_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO411_FUNC_ALT1 0x01u        /*!<@brief Selects pin function.: Alternative connection 1. */
#define PIO412_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO412_FUNC_ALT1 0x01u        /*!<@brief Selects pin function.: Alternative connection 1. */
#define PIO413_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO413_FUNC_ALT1 0x01u        /*!<@brief Selects pin function.: Alternative connection 1. */
#define PIO414_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO414_FUNC_ALT1 0x01u        /*!<@brief Selects pin function.: Alternative connection 1. */
#define PIO415_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO415_FUNC_ALT1 0x01u        /*!<@brief Selects pin function.: Alternative connection 1. */
#define PIO416_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO416_FUNC_ALT1 0x01u        /*!<@brief Selects pin function.: Alternative connection 1. */
#define PIO48_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO48_FUNC_ALT1 0x01u         /*!<@brief Selects pin function.: Alternative connection 1. */
#define PIO022_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO022_FUNC_ALT7 0x07u        /*!<@brief Selects pin function.: Alternative connection 7. */
/*! @name FC2_CTS_SDA_SSEL0 (coord C2), J4[77/]P3_23-FC2_SDAX
  @{ */
#define BOARD_FC2_SDAX_PERIPHERAL FLEXCOMM2          /*!<@brief Device name: FLEXCOMM2 */
#define BOARD_FC2_SDAX_SIGNAL CTS_SDA_SSEL0          /*!<@brief FLEXCOMM2 signal: CTS_SDA_SSEL0 */
#define BOARD_FC2_SDAX_PIN_NAME FC2_CTS_SDA_SSEL0    /*!<@brief Pin name */
#define BOARD_FC2_SDAX_LABEL "J4[77/]P3_23-FC2_SDAX" /*!<@brief Label */
#define BOARD_FC2_SDAX_NAME "FC2_SDAX"               /*!<@brief Identifier name */
                                                     /* @} */

/*! @name FC2_RTS_SCL_SSEL1 (coord E2), J4[75]/P3_24-FC2_SCLX
  @{ */
#define BOARD_FC2_SCLX_PERIPHERAL FLEXCOMM2          /*!<@brief Device name: FLEXCOMM2 */
#define BOARD_FC2_SCLX_SIGNAL RTS_SCL_SSEL1          /*!<@brief FLEXCOMM2 signal: RTS_SCL_SSEL1 */
#define BOARD_FC2_SCLX_PIN_NAME FC2_RTS_SCL_SSEL1    /*!<@brief Pin name */
#define BOARD_FC2_SCLX_LABEL "J4[75]/P3_24-FC2_SCLX" /*!<@brief Label */
#define BOARD_FC2_SCLX_NAME "FC2_SCLX"               /*!<@brief Identifier name */
                                                     /* @} */

/*! @name ENET_TXD1 (coord E14), J3[45]/P0_17-ENET_TXD1
  @{ */
#define BOARD_ENET_TXD1_PERIPHERAL ENET                /*!<@brief Device name: ENET */
#define BOARD_ENET_TXD1_SIGNAL ENET_TXD                /*!<@brief ENET signal: ENET_TXD */
#define BOARD_ENET_TXD1_CHANNEL 1                      /*!<@brief ENET ENET_TXD channel: 1 */
#define BOARD_ENET_TXD1_PIN_NAME ENET_TXD1             /*!<@brief Pin name */
#define BOARD_ENET_TXD1_LABEL "J3[45]/P0_17-ENET_TXD1" /*!<@brief Label */
#define BOARD_ENET_TXD1_NAME "ENET_TXD1"               /*!<@brief Identifier name */
                                                       /* @} */

/*! @name ENET_RX_DV (coord B9), J3[74]/P4_10-ENET_CRS_DV
  @{ */
#define BOARD_ENET_CRS_DV_PERIPHERAL ENET                  /*!<@brief Device name: ENET */
#define BOARD_ENET_CRS_DV_SIGNAL ENET_RX_DV                /*!<@brief ENET signal: ENET_RX_DV */
#define BOARD_ENET_CRS_DV_PIN_NAME ENET_RX_DV              /*!<@brief Pin name */
#define BOARD_ENET_CRS_DV_LABEL "J3[74]/P4_10-ENET_CRS_DV" /*!<@brief Label */
#define BOARD_ENET_CRS_DV_NAME "ENET_CRS_DV"               /*!<@brief Identifier name */
                                                           /* @} */

/*! @name ENET_RXD1 (coord A6), J3[78]P4_12-ENET_RXD1
  @{ */
#define BOARD_ENET_RXD1_PERIPHERAL ENET               /*!<@brief Device name: ENET */
#define BOARD_ENET_RXD1_SIGNAL ENET_RXD               /*!<@brief ENET signal: ENET_RXD */
#define BOARD_ENET_RXD1_CHANNEL 1                     /*!<@brief ENET ENET_RXD channel: 1 */
#define BOARD_ENET_RXD1_PIN_NAME ENET_RXD1            /*!<@brief Pin name */
#define BOARD_ENET_RXD1_LABEL "J3[78]P4_12-ENET_RXD1" /*!<@brief Label */
#define BOARD_ENET_RXD1_NAME "ENET_RXD1"              /*!<@brief Identifier name */
                                                      /* @} */

/*! @name ENET_TX_EN (coord B6), J3[80]P4_13-ENET_TX_EN
  @{ */
#define BOARD_ENET_TX_EN_PERIPHERAL ENET                /*!<@brief Device name: ENET */
#define BOARD_ENET_TX_EN_SIGNAL ENET_TX_EN              /*!<@brief ENET signal: ENET_TX_EN */
#define BOARD_ENET_TX_EN_PIN_NAME ENET_TX_EN            /*!<@brief Pin name */
#define BOARD_ENET_TX_EN_LABEL "J3[80]P4_13-ENET_TX_EN" /*!<@brief Label */
#define BOARD_ENET_TX_EN_NAME "ENET_TX_EN"              /*!<@brief Identifier name */
                                                        /* @} */

/*! @name ENET_RX_CLK (coord B5), J3[82]/P4_14-ENET_RX_CLK
  @{ */
#define BOARD_ENET_RX_CLK_PERIPHERAL ENET                  /*!<@brief Device name: ENET */
#define BOARD_ENET_RX_CLK_SIGNAL ENET_RX_CLK               /*!<@brief ENET signal: ENET_RX_CLK */
#define BOARD_ENET_RX_CLK_PIN_NAME ENET_RX_CLK             /*!<@brief Pin name */
#define BOARD_ENET_RX_CLK_LABEL "J3[82]/P4_14-ENET_RX_CLK" /*!<@brief Label */
#define BOARD_ENET_RX_CLK_NAME "ENET_RX_CLK"               /*!<@brief Identifier name */
                                                           /* @} */

/*! @name ENET_MDC (coord A4), J3[84]/P4_15-ENET_MDC
  @{ */
#define BOARD_ENET_MDC_PERIPHERAL ENET               /*!<@brief Device name: ENET */
#define BOARD_ENET_MDC_SIGNAL ENET_MDC               /*!<@brief ENET signal: ENET_MDC */
#define BOARD_ENET_MDC_PIN_NAME ENET_MDC             /*!<@brief Pin name */
#define BOARD_ENET_MDC_LABEL "J3[84]/P4_15-ENET_MDC" /*!<@brief Label */
#define BOARD_ENET_MDC_NAME "ENET_MDC"               /*!<@brief Identifier name */
                                                     /* @} */

/*! @name ENET_MDIO (coord C4), J3[86]/P4_16-ENET_MDIO
  @{ */
#define BOARD_ENET_MDIO_PERIPHERAL ENET                /*!<@brief Device name: ENET */
#define BOARD_ENET_MDIO_SIGNAL ENET_MDIO               /*!<@brief ENET signal: ENET_MDIO */
#define BOARD_ENET_MDIO_PIN_NAME ENET_MDIO             /*!<@brief Pin name */
#define BOARD_ENET_MDIO_LABEL "J3[86]/P4_16-ENET_MDIO" /*!<@brief Label */
#define BOARD_ENET_MDIO_NAME "ENET_MDIO"               /*!<@brief Identifier name */
                                                       /* @} */

/*! @name ENET_TXD0 (coord B14), J3[72]/P4_8-ENET_TXD0
  @{ */
#define BOARD_ENET_TXD0_PERIPHERAL ENET               /*!<@brief Device name: ENET */
#define BOARD_ENET_TXD0_SIGNAL ENET_TXD               /*!<@brief ENET signal: ENET_TXD */
#define BOARD_ENET_TXD0_CHANNEL 0                     /*!<@brief ENET ENET_TXD channel: 0 */
#define BOARD_ENET_TXD0_PIN_NAME ENET_TXD0            /*!<@brief Pin name */
#define BOARD_ENET_TXD0_LABEL "J3[72]/P4_8-ENET_TXD0" /*!<@brief Label */
#define BOARD_ENET_TXD0_NAME "ENET_TXD0"              /*!<@brief Identifier name */
                                                      /* @} */

/*!
 * @brief Configures pin routing and optionally pin electrical features.
 *
 */
void BOARD_InitPins(void); /* Function assigned for the Cortex-M4F */

#define PIO023_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO023_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO024_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO024_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO025_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO025_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO026_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO026_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO027_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO027_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO028_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO028_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO212_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO212_FUNC_ALT0 0x00u        /*!<@brief Selects pin function.: Alternative connection 0. */

/*! @name SPIFI_CLK (coord M13), U20[6]/P0_26-SPIFI_CLK
  @{ */
#define BOARD_SPIFI_CLK_PERIPHERAL SPIFI0              /*!<@brief Device name: SPIFI0 */
#define BOARD_SPIFI_CLK_SIGNAL SPIFI_SCK               /*!<@brief SPIFI0 signal: SPIFI_SCK */
#define BOARD_SPIFI_CLK_PIN_NAME SPIFI_CLK             /*!<@brief Pin name */
#define BOARD_SPIFI_CLK_LABEL "U20[6]/P0_26-SPIFI_CLK" /*!<@brief Label */
#define BOARD_SPIFI_CLK_NAME "SPIFI_CLK"               /*!<@brief Identifier name */
                                                       /* @} */

/*! @name SPIFI_IO(0) (coord M7), U20[5]/P0_24-SPIFI_IO0
  @{ */
#define BOARD_SPIFI_IO0_PERIPHERAL SPIFI0              /*!<@brief Device name: SPIFI0 */
#define BOARD_SPIFI_IO0_SIGNAL SPIFI_IO0/SPIFI_MOSI    /*!<@brief SPIFI0 signal: SPIFI_IO0/SPIFI_MOSI */
#define BOARD_SPIFI_IO0_PIN_NAME SPIFI_IO(0)           /*!<@brief Pin name */
#define BOARD_SPIFI_IO0_LABEL "U20[5]/P0_24-SPIFI_IO0" /*!<@brief Label */
#define BOARD_SPIFI_IO0_NAME "SPIFI_IO0"               /*!<@brief Identifier name */
                                                       /* @} */

/*! @name SPIFI_IO(1) (coord K8), U20[2]/P0_25-SPIFI_IO1
  @{ */
#define BOARD_SPIFI_IO1_PERIPHERAL SPIFI0              /*!<@brief Device name: SPIFI0 */
#define BOARD_SPIFI_IO1_SIGNAL SPIFI_IO1/SPIFI_MISO    /*!<@brief SPIFI0 signal: SPIFI_IO1/SPIFI_MISO */
#define BOARD_SPIFI_IO1_PIN_NAME SPIFI_IO(1)           /*!<@brief Pin name */
#define BOARD_SPIFI_IO1_LABEL "U20[2]/P0_25-SPIFI_IO1" /*!<@brief Label */
#define BOARD_SPIFI_IO1_NAME "SPIFI_IO1"               /*!<@brief Identifier name */
                                                       /* @} */

/*! @name SPIFI_IO(3) (coord L9), U20[7]/P0_27-SPIFI_IO3
  @{ */
#define BOARD_SPIFI_IO3_PERIPHERAL SPIFI0              /*!<@brief Device name: SPIFI0 */
#define BOARD_SPIFI_IO3_SIGNAL SPIFI_IO                /*!<@brief SPIFI0 signal: SPIFI_IO */
#define BOARD_SPIFI_IO3_CHANNEL 3                      /*!<@brief SPIFI0 SPIFI_IO channel: 3 */
#define BOARD_SPIFI_IO3_PIN_NAME SPIFI_IO(3)           /*!<@brief Pin name */
#define BOARD_SPIFI_IO3_LABEL "U20[7]/P0_27-SPIFI_IO3" /*!<@brief Label */
#define BOARD_SPIFI_IO3_NAME "SPIFI_IO3"               /*!<@brief Identifier name */
                                                       /* @} */

/*! @name SPIFI_IO(2) (coord M9), U20[3]/P0_28-SPIFI_IO2-USB0_OCURRn
  @{ */
#define BOARD_SPIFI_IO2_PERIPHERAL SPIFI0                          /*!<@brief Device name: SPIFI0 */
#define BOARD_SPIFI_IO2_SIGNAL SPIFI_IO                            /*!<@brief SPIFI0 signal: SPIFI_IO */
#define BOARD_SPIFI_IO2_CHANNEL 2                                  /*!<@brief SPIFI0 SPIFI_IO channel: 2 */
#define BOARD_SPIFI_IO2_PIN_NAME SPIFI_IO(2)                       /*!<@brief Pin name */
#define BOARD_SPIFI_IO2_LABEL "U20[3]/P0_28-SPIFI_IO2-USB0_OCURRn" /*!<@brief Label */
#define BOARD_SPIFI_IO2_NAME "SPIFI_IO2"                           /*!<@brief Identifier name */
                                                                   /* @} */

/*! @name SPIFI_CSN (coord N7), U20[1]/P0_23-SPIFI_CSn-MCLK
  @{ */
#define BOARD_SPIFI_CSn_PERIPHERAL SPIFI0                   /*!<@brief Device name: SPIFI0 */
#define BOARD_SPIFI_CSn_SIGNAL SPIFI_CSN                    /*!<@brief SPIFI0 signal: SPIFI_CSN */
#define BOARD_SPIFI_CSn_PIN_NAME SPIFI_CSN                  /*!<@brief Pin name */
#define BOARD_SPIFI_CSn_LABEL "U20[1]/P0_23-SPIFI_CSn-MCLK" /*!<@brief Label */
#define BOARD_SPIFI_CSn_NAME "SPIFI_CSn"                    /*!<@brief Identifier name */
                                                            /* @} */

/*! @name PIO2_12 (coord M2), J4[28]/P2_12-SPIFI_RSTn
  @{ */
#define BOARD_SPIFI_RSTn_PERIPHERAL GPIO                 /*!<@brief Device name: GPIO */
#define BOARD_SPIFI_RSTn_SIGNAL PIO2                     /*!<@brief GPIO signal: PIO2 */
#define BOARD_SPIFI_RSTn_GPIO GPIO                       /*!<@brief GPIO device name: GPIO */
#define BOARD_SPIFI_RSTn_GPIO_PIN 12U                    /*!<@brief PIO2 pin index: 12 */
#define BOARD_SPIFI_RSTn_PORT 2U                         /*!<@brief PORT device name: 2U */
#define BOARD_SPIFI_RSTn_PIN 12U                         /*!<@brief 2U pin index: 12 */
#define BOARD_SPIFI_RSTn_CHANNEL 12                      /*!<@brief GPIO PIO2 channel: 12 */
#define BOARD_SPIFI_RSTn_PIN_NAME PIO2_12                /*!<@brief Pin name */
#define BOARD_SPIFI_RSTn_LABEL "J4[28]/P2_12-SPIFI_RSTn" /*!<@brief Label */
#define BOARD_SPIFI_RSTn_NAME "SPIFI_RSTn"               /*!<@brief Identifier name */
                                                         /* @} */

/*!
 * @brief Configures pin routing and optionally pin electrical features.
 *
 */
void BOARD_InitQSPI_FLASH(void); /* Function assigned for the Cortex-M4F */

#define PIO015_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO015_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO018_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO018_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO019_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO019_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO020_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO020_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO021_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO021_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO02_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO02_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO03_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO03_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO04_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO04_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO05_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO05_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO06_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO06_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO07_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO07_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO08_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO08_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO09_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO09_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO110_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO110_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO111_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO111_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO112_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO112_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO113_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO113_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO114_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO114_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO115_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO115_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO116_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO116_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO119_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO119_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO120_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO120_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO121_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO121_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO123_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO123_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO124_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO124_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO125_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO125_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO126_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO126_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO127_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO127_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO128_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO128_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO129_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO129_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO130_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO130_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO131_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO131_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO14_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO14_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO15_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO15_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO16_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO16_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO17_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO17_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO18_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO18_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO19_DIGIMODE_DIGITAL 0x01u  /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO19_FUNC_ALT6 0x06u         /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO325_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO325_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */

/*! @name EMC_A(14) (coord P9), J3[3]/P3_25-EMC_A14
  @{ */
#define BOARD_EMC_A14_PERIPHERAL EMC              /*!<@brief Device name: EMC */
#define BOARD_EMC_A14_SIGNAL EMC_A                /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A14_CHANNEL 14                  /*!<@brief EMC EMC_A channel: 14 */
#define BOARD_EMC_A14_PIN_NAME EMC_A(14)          /*!<@brief Pin name */
#define BOARD_EMC_A14_LABEL "J3[3]/P3_25-EMC_A14" /*!<@brief Label */
#define BOARD_EMC_A14_NAME "EMC_A14"              /*!<@brief Identifier name */
                                                  /* @} */

/*! @name EMC_A(13) (coord M12), J3[25]/P1_25-EMC_A13
  @{ */
#define BOARD_EMC_A13_PERIPHERAL EMC               /*!<@brief Device name: EMC */
#define BOARD_EMC_A13_SIGNAL EMC_A                 /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A13_CHANNEL 13                   /*!<@brief EMC EMC_A channel: 13 */
#define BOARD_EMC_A13_PIN_NAME EMC_A(13)           /*!<@brief Pin name */
#define BOARD_EMC_A13_LABEL "J3[25]/P1_25-EMC_A13" /*!<@brief Label */
#define BOARD_EMC_A13_NAME "EMC_A13"               /*!<@brief Identifier name */
                                                   /* @} */

/*! @name EMC_A(12) (coord N14), J3[27]/P1_24-EMC_A12
  @{ */
#define BOARD_EMC_A12_PERIPHERAL EMC               /*!<@brief Device name: EMC */
#define BOARD_EMC_A12_SIGNAL EMC_A                 /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A12_CHANNEL 12                   /*!<@brief EMC EMC_A channel: 12 */
#define BOARD_EMC_A12_PIN_NAME EMC_A(12)           /*!<@brief Pin name */
#define BOARD_EMC_A12_LABEL "J3[27]/P1_24-EMC_A12" /*!<@brief Label */
#define BOARD_EMC_A12_NAME "EMC_A12"               /*!<@brief Identifier name */
                                                   /* @} */

/*! @name EMC_A(11) (coord M10), J3[13]/P1_23-EMC_A11
  @{ */
#define BOARD_EMC_A11_PERIPHERAL EMC               /*!<@brief Device name: EMC */
#define BOARD_EMC_A11_SIGNAL EMC_A                 /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A11_CHANNEL 11                   /*!<@brief EMC EMC_A channel: 11 */
#define BOARD_EMC_A11_PIN_NAME EMC_A(11)           /*!<@brief Pin name */
#define BOARD_EMC_A11_LABEL "J3[13]/P1_23-EMC_A11" /*!<@brief Label */
#define BOARD_EMC_A11_NAME "EMC_A11"               /*!<@brief Identifier name */
                                                   /* @} */

/*! @name EMC_A(10) (coord B7), J4[96]/P1_16-EMC_A10
  @{ */
#define BOARD_EMC_A10_PERIPHERAL EMC               /*!<@brief Device name: EMC */
#define BOARD_EMC_A10_SIGNAL EMC_A                 /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A10_CHANNEL 10                   /*!<@brief EMC EMC_A channel: 10 */
#define BOARD_EMC_A10_PIN_NAME EMC_A(10)           /*!<@brief Pin name */
#define BOARD_EMC_A10_LABEL "J4[96]/P1_16-EMC_A10" /*!<@brief Label */
#define BOARD_EMC_A10_NAME "EMC_A10"               /*!<@brief Identifier name */
                                                   /* @} */

/*! @name EMC_A(9) (coord F10), J3[55]/P1_27-EMC_A9
  @{ */
#define BOARD_EMC_A9_PERIPHERAL EMC              /*!<@brief Device name: EMC */
#define BOARD_EMC_A9_SIGNAL EMC_A                /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A9_CHANNEL 9                   /*!<@brief EMC EMC_A channel: 9 */
#define BOARD_EMC_A9_PIN_NAME EMC_A(9)           /*!<@brief Pin name */
#define BOARD_EMC_A9_LABEL "J3[55]/P1_27-EMC_A9" /*!<@brief Label */
#define BOARD_EMC_A9_NAME "EMC_A9"               /*!<@brief Identifier name */
                                                 /* @} */

/*! @name EMC_A(8) (coord J10), J3[51]/P1_26-EMC_A8
  @{ */
#define BOARD_EMC_A8_PERIPHERAL EMC              /*!<@brief Device name: EMC */
#define BOARD_EMC_A8_SIGNAL EMC_A                /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A8_CHANNEL 8                   /*!<@brief EMC EMC_A channel: 8 */
#define BOARD_EMC_A8_PIN_NAME EMC_A(8)           /*!<@brief Pin name */
#define BOARD_EMC_A8_LABEL "J3[51]/P1_26-EMC_A8" /*!<@brief Label */
#define BOARD_EMC_A8_NAME "EMC_A8"               /*!<@brief Identifier name */
                                                 /* @} */

/*! @name EMC_A(7) (coord P8), J4[4]/P1_8-EMC_A7
  @{ */
#define BOARD_EMC_A7_PERIPHERAL EMC            /*!<@brief Device name: EMC */
#define BOARD_EMC_A7_SIGNAL EMC_A              /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A7_CHANNEL 7                 /*!<@brief EMC EMC_A channel: 7 */
#define BOARD_EMC_A7_PIN_NAME EMC_A(7)         /*!<@brief Pin name */
#define BOARD_EMC_A7_LABEL "J4[4]/P1_8-EMC_A7" /*!<@brief Label */
#define BOARD_EMC_A7_NAME "EMC_A7"             /*!<@brief Identifier name */
                                               /* @} */

/*! @name EMC_A(6) (coord N1), J4[31]/P1_7-EMC_A6
  @{ */
#define BOARD_EMC_A6_PERIPHERAL EMC             /*!<@brief Device name: EMC */
#define BOARD_EMC_A6_SIGNAL EMC_A               /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A6_CHANNEL 6                  /*!<@brief EMC EMC_A channel: 6 */
#define BOARD_EMC_A6_PIN_NAME EMC_A(6)          /*!<@brief Pin name */
#define BOARD_EMC_A6_LABEL "J4[31]/P1_7-EMC_A6" /*!<@brief Label */
#define BOARD_EMC_A6_NAME "EMC_A6"              /*!<@brief Identifier name */
                                                /* @} */

/*! @name EMC_A(5) (coord G4), J4[50]/P1_6-EMC_A5
  @{ */
#define BOARD_EMC_A5_PERIPHERAL EMC             /*!<@brief Device name: EMC */
#define BOARD_EMC_A5_SIGNAL EMC_A               /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A5_CHANNEL 5                  /*!<@brief EMC EMC_A channel: 5 */
#define BOARD_EMC_A5_PIN_NAME EMC_A(5)          /*!<@brief Pin name */
#define BOARD_EMC_A5_LABEL "J4[50]/P1_6-EMC_A5" /*!<@brief Label */
#define BOARD_EMC_A5_NAME "EMC_A5"              /*!<@brief Identifier name */
                                                /* @} */

/*! @name EMC_A(4) (coord E4), J4[68]P1_5-EMC_A4
  @{ */
#define BOARD_EMC_A4_PERIPHERAL EMC            /*!<@brief Device name: EMC */
#define BOARD_EMC_A4_SIGNAL EMC_A              /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A4_CHANNEL 4                 /*!<@brief EMC EMC_A channel: 4 */
#define BOARD_EMC_A4_PIN_NAME EMC_A(4)         /*!<@brief Pin name */
#define BOARD_EMC_A4_LABEL "J4[68]P1_5-EMC_A4" /*!<@brief Label */
#define BOARD_EMC_A4_NAME "EMC_A4"             /*!<@brief Identifier name */
                                               /* @} */

/*! @name EMC_A(3) (coord C13), J3[54]P0_21-EMC_A3
  @{ */
#define BOARD_EMC_A3_PERIPHERAL EMC             /*!<@brief Device name: EMC */
#define BOARD_EMC_A3_SIGNAL EMC_A               /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A3_CHANNEL 3                  /*!<@brief EMC EMC_A channel: 3 */
#define BOARD_EMC_A3_PIN_NAME EMC_A(3)          /*!<@brief Pin name */
#define BOARD_EMC_A3_LABEL "J3[54]P0_21-EMC_A3" /*!<@brief Label */
#define BOARD_EMC_A3_NAME "EMC_A3"              /*!<@brief Identifier name */
                                                /* @} */

/*! @name EMC_A(2) (coord D13), J3[50]/P0_20-EMC_A2
  @{ */
#define BOARD_EMC_A2_PERIPHERAL EMC              /*!<@brief Device name: EMC */
#define BOARD_EMC_A2_SIGNAL EMC_A                /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A2_CHANNEL 2                   /*!<@brief EMC EMC_A channel: 2 */
#define BOARD_EMC_A2_PIN_NAME EMC_A(2)           /*!<@brief Pin name */
#define BOARD_EMC_A2_LABEL "J3[50]/P0_20-EMC_A2" /*!<@brief Label */
#define BOARD_EMC_A2_NAME "EMC_A2"               /*!<@brief Identifier name */
                                                 /* @} */

/*! @name EMC_A(1) (coord C6), J4[88]/P0_19-EMC_A1
  @{ */
#define BOARD_EMC_A1_PERIPHERAL EMC              /*!<@brief Device name: EMC */
#define BOARD_EMC_A1_SIGNAL EMC_A                /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A1_CHANNEL 1                   /*!<@brief EMC EMC_A channel: 1 */
#define BOARD_EMC_A1_PIN_NAME EMC_A(1)           /*!<@brief Pin name */
#define BOARD_EMC_A1_LABEL "J4[88]/P0_19-EMC_A1" /*!<@brief Label */
#define BOARD_EMC_A1_NAME "EMC_A1"               /*!<@brief Identifier name */
                                                 /* @} */

/*! @name EMC_A(0) (coord C14), J3[52]/P0_18-EMC_A0
  @{ */
#define BOARD_EMC_A0_PERIPHERAL EMC              /*!<@brief Device name: EMC */
#define BOARD_EMC_A0_SIGNAL EMC_A                /*!<@brief EMC signal: EMC_A */
#define BOARD_EMC_A0_CHANNEL 0                   /*!<@brief EMC EMC_A channel: 0 */
#define BOARD_EMC_A0_PIN_NAME EMC_A(0)           /*!<@brief Pin name */
#define BOARD_EMC_A0_LABEL "J3[52]/P0_18-EMC_A0" /*!<@brief Label */
#define BOARD_EMC_A0_NAME "EMC_A0"               /*!<@brief Identifier name */
                                                 /* @} */

/*! @name EMC_WEN (coord L4), J4[46]/P0_15-EMC_WEn
  @{ */
#define BOARD_EMC_WEn_PERIPHERAL EMC               /*!<@brief Device name: EMC */
#define BOARD_EMC_WEn_SIGNAL EMC_WE                /*!<@brief EMC signal: EMC_WE */
#define BOARD_EMC_WEn_PIN_NAME EMC_WEN             /*!<@brief Pin name */
#define BOARD_EMC_WEn_LABEL "J4[46]/P0_15-EMC_WEn" /*!<@brief Label */
#define BOARD_EMC_WEn_NAME "EMC_WEn"               /*!<@brief Identifier name */
                                                   /* @} */

/*! @name EMC_CASN (coord K6), J4[12]/P1_9-EMC_CASn
  @{ */
#define BOARD_EMC_CASn_PERIPHERAL EMC               /*!<@brief Device name: EMC */
#define BOARD_EMC_CASn_SIGNAL EMC_CAS               /*!<@brief EMC signal: EMC_CAS */
#define BOARD_EMC_CASn_PIN_NAME EMC_CASN            /*!<@brief Pin name */
#define BOARD_EMC_CASn_LABEL "J4[12]/P1_9-EMC_CASn" /*!<@brief Label */
#define BOARD_EMC_CASn_NAME "EMC_CASn"              /*!<@brief Identifier name */
                                                    /* @} */

/*! @name EMC_RASN (coord N9), J3[5]/P1_10-EMC_RASn
  @{ */
#define BOARD_EMC_RASn_PERIPHERAL EMC               /*!<@brief Device name: EMC */
#define BOARD_EMC_RASn_SIGNAL EMC_RAS               /*!<@brief EMC signal: EMC_RAS */
#define BOARD_EMC_RASn_PIN_NAME EMC_RASN            /*!<@brief Pin name */
#define BOARD_EMC_RASn_LABEL "J3[5]/P1_10-EMC_RASn" /*!<@brief Label */
#define BOARD_EMC_RASn_NAME "EMC_RASn"              /*!<@brief Identifier name */
                                                    /* @} */

/*! @name EMC_DYCSN(0) (coord K9), J3[7]/P1_12-EMC_DYCSn0
  @{ */
#define BOARD_EMC_DYCSn0_PERIPHERAL EMC                 /*!<@brief Device name: EMC */
#define BOARD_EMC_DYCSn0_SIGNAL EMC_DYCS                /*!<@brief EMC signal: EMC_DYCS */
#define BOARD_EMC_DYCSn0_CHANNEL 0                      /*!<@brief EMC EMC_DYCS channel: 0 */
#define BOARD_EMC_DYCSn0_PIN_NAME EMC_DYCSN(0)          /*!<@brief Pin name */
#define BOARD_EMC_DYCSn0_LABEL "J3[7]/P1_12-EMC_DYCSn0" /*!<@brief Label */
#define BOARD_EMC_DYCSn0_NAME "EMC_DYCSn0"              /*!<@brief Identifier name */
                                                        /* @} */

/*! @name EMC_D(15) (coord C5), J4[84]/P1_31-EMC_D15
  @{ */
#define BOARD_EMC_D15_PERIPHERAL EMC               /*!<@brief Device name: EMC */
#define BOARD_EMC_D15_SIGNAL EMC_D                 /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D15_CHANNEL 15                   /*!<@brief EMC EMC_D channel: 15 */
#define BOARD_EMC_D15_PIN_NAME EMC_D(15)           /*!<@brief Pin name */
#define BOARD_EMC_D15_LABEL "J4[84]/P1_31-EMC_D15" /*!<@brief Label */
#define BOARD_EMC_D15_NAME "EMC_D15"               /*!<@brief Identifier name */
                                                   /* @} */

/*! @name EMC_D(14) (coord A8), J3[92]/P1_30-EMC_D14
  @{ */
#define BOARD_EMC_D14_PERIPHERAL EMC               /*!<@brief Device name: EMC */
#define BOARD_EMC_D14_SIGNAL EMC_D                 /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D14_CHANNEL 14                   /*!<@brief EMC EMC_D channel: 14 */
#define BOARD_EMC_D14_PIN_NAME EMC_D(14)           /*!<@brief Pin name */
#define BOARD_EMC_D14_LABEL "J3[92]/P1_30-EMC_D14" /*!<@brief Label */
#define BOARD_EMC_D14_NAME "EMC_D14"               /*!<@brief Identifier name */
                                                   /* @} */

/*! @name EMC_D(13) (coord C11), J3[85]/P1_29-EMC_D13
  @{ */
#define BOARD_EMC_D13_PERIPHERAL EMC               /*!<@brief Device name: EMC */
#define BOARD_EMC_D13_SIGNAL EMC_D                 /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D13_CHANNEL 13                   /*!<@brief EMC EMC_D channel: 13 */
#define BOARD_EMC_D13_PIN_NAME EMC_D(13)           /*!<@brief Pin name */
#define BOARD_EMC_D13_LABEL "J3[85]/P1_29-EMC_D13" /*!<@brief Label */
#define BOARD_EMC_D13_NAME "EMC_D13"               /*!<@brief Identifier name */
                                                   /* @} */

/*! @name EMC_D(12) (coord E12), J3[77]/P1_28-EMC_D12
  @{ */
#define BOARD_EMC_D12_PERIPHERAL EMC               /*!<@brief Device name: EMC */
#define BOARD_EMC_D12_SIGNAL EMC_D                 /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D12_CHANNEL 12                   /*!<@brief EMC EMC_D channel: 12 */
#define BOARD_EMC_D12_PIN_NAME EMC_D(12)           /*!<@brief Pin name */
#define BOARD_EMC_D12_LABEL "J3[77]/P1_28-EMC_D12" /*!<@brief Label */
#define BOARD_EMC_D12_NAME "EMC_D12"               /*!<@brief Identifier name */
                                                   /* @} */

/*! @name EMC_D(11) (coord D4), J4[74]/P1_4-EMC_D11
  @{ */
#define BOARD_EMC_D11_PERIPHERAL EMC              /*!<@brief Device name: EMC */
#define BOARD_EMC_D11_SIGNAL EMC_D                /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D11_CHANNEL 11                  /*!<@brief EMC EMC_D channel: 11 */
#define BOARD_EMC_D11_PIN_NAME EMC_D(11)          /*!<@brief Pin name */
#define BOARD_EMC_D11_LABEL "J4[74]/P1_4-EMC_D11" /*!<@brief Label */
#define BOARD_EMC_D11_NAME "EMC_D11"              /*!<@brief Identifier name */
                                                  /* @} */

/*! @name EMC_D(10) (coord N8), J4[6]/P1_21-EMC_D10
  @{ */
#define BOARD_EMC_D10_PERIPHERAL EMC              /*!<@brief Device name: EMC */
#define BOARD_EMC_D10_SIGNAL EMC_D                /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D10_CHANNEL 10                  /*!<@brief EMC EMC_D channel: 10 */
#define BOARD_EMC_D10_PIN_NAME EMC_D(10)          /*!<@brief Pin name */
#define BOARD_EMC_D10_LABEL "J4[6]/P1_21-EMC_D10" /*!<@brief Label */
#define BOARD_EMC_D10_NAME "EMC_D10"              /*!<@brief Identifier name */
                                                  /* @} */

/*! @name EMC_D(9) (coord M1), J4[33]/P1_20-EMC_D9
  @{ */
#define BOARD_EMC_D9_PERIPHERAL EMC              /*!<@brief Device name: EMC */
#define BOARD_EMC_D9_SIGNAL EMC_D                /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D9_CHANNEL 9                   /*!<@brief EMC EMC_D channel: 9 */
#define BOARD_EMC_D9_PIN_NAME EMC_D(9)           /*!<@brief Pin name */
#define BOARD_EMC_D9_LABEL "J4[33]/P1_20-EMC_D9" /*!<@brief Label */
#define BOARD_EMC_D9_NAME "EMC_D9"               /*!<@brief Identifier name */
                                                 /* @} */

/*! @name EMC_D(8) (coord L1), J4[35]/P1_19-EMC_D8
  @{ */
#define BOARD_EMC_D8_PERIPHERAL EMC              /*!<@brief Device name: EMC */
#define BOARD_EMC_D8_SIGNAL EMC_D                /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D8_CHANNEL 8                   /*!<@brief EMC EMC_D channel: 8 */
#define BOARD_EMC_D8_PIN_NAME EMC_D(8)           /*!<@brief Pin name */
#define BOARD_EMC_D8_LABEL "J4[35]/P1_19-EMC_D8" /*!<@brief Label */
#define BOARD_EMC_D8_NAME "EMC_D8"               /*!<@brief Identifier name */
                                                 /* @} */

/*! @name EMC_D(7) (coord G12), J3[57]/P0_9-EMC_D7
  @{ */
#define BOARD_EMC_D7_PERIPHERAL EMC             /*!<@brief Device name: EMC */
#define BOARD_EMC_D7_SIGNAL EMC_D               /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D7_CHANNEL 7                  /*!<@brief EMC EMC_D channel: 7 */
#define BOARD_EMC_D7_PIN_NAME EMC_D(7)          /*!<@brief Pin name */
#define BOARD_EMC_D7_LABEL "J3[57]/P0_9-EMC_D7" /*!<@brief Label */
#define BOARD_EMC_D7_NAME "EMC_D7"              /*!<@brief Identifier name */
                                                /* @} */

/*! @name EMC_D(6) (coord H10), J3[36]/P0_8-EMC_D6
  @{ */
#define BOARD_EMC_D6_PERIPHERAL EMC             /*!<@brief Device name: EMC */
#define BOARD_EMC_D6_SIGNAL EMC_D               /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D6_CHANNEL 6                  /*!<@brief EMC EMC_D channel: 6 */
#define BOARD_EMC_D6_PIN_NAME EMC_D(6)          /*!<@brief Pin name */
#define BOARD_EMC_D6_LABEL "J3[36]/P0_8-EMC_D6" /*!<@brief Label */
#define BOARD_EMC_D6_NAME "EMC_D6"              /*!<@brief Identifier name */
                                                /* @} */

/*! @name EMC_D(5) (coord H12), J3[49]P0_7-EMC_D5
  @{ */
#define BOARD_EMC_D5_PERIPHERAL EMC            /*!<@brief Device name: EMC */
#define BOARD_EMC_D5_SIGNAL EMC_D              /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D5_CHANNEL 5                 /*!<@brief EMC EMC_D channel: 5 */
#define BOARD_EMC_D5_PIN_NAME EMC_D(5)         /*!<@brief Pin name */
#define BOARD_EMC_D5_LABEL "J3[49]P0_7-EMC_D5" /*!<@brief Label */
#define BOARD_EMC_D5_NAME "EMC_D5"             /*!<@brief Identifier name */
                                               /* @} */

/*! @name EMC_D(4) (coord A5), J3[96]/P0_6-EMC_D4
  @{ */
#define BOARD_EMC_D4_PERIPHERAL EMC             /*!<@brief Device name: EMC */
#define BOARD_EMC_D4_SIGNAL EMC_D               /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D4_CHANNEL 4                  /*!<@brief EMC EMC_D channel: 4 */
#define BOARD_EMC_D4_PIN_NAME EMC_D(4)          /*!<@brief Pin name */
#define BOARD_EMC_D4_LABEL "J3[96]/P0_6-EMC_D4" /*!<@brief Label */
#define BOARD_EMC_D4_NAME "EMC_D4"              /*!<@brief Identifier name */
                                                /* @} */

/*! @name EMC_D(3) (coord E7), J3[92]/P0_5-EMC_D3
  @{ */
#define BOARD_EMC_D3_PERIPHERAL EMC             /*!<@brief Device name: EMC */
#define BOARD_EMC_D3_SIGNAL EMC_D               /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D3_CHANNEL 3                  /*!<@brief EMC EMC_D channel: 3 */
#define BOARD_EMC_D3_PIN_NAME EMC_D(3)          /*!<@brief Pin name */
#define BOARD_EMC_D3_LABEL "J3[92]/P0_5-EMC_D3" /*!<@brief Label */
#define BOARD_EMC_D3_NAME "EMC_D3"              /*!<@brief Identifier name */
                                                /* @} */

/*! @name EMC_D(2) (coord C8), J3[94]/P0_4-EMC_D2
  @{ */
#define BOARD_EMC_D2_PERIPHERAL EMC             /*!<@brief Device name: EMC */
#define BOARD_EMC_D2_SIGNAL EMC_D               /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D2_CHANNEL 2                  /*!<@brief EMC EMC_D channel: 2 */
#define BOARD_EMC_D2_PIN_NAME EMC_D(2)          /*!<@brief Pin name */
#define BOARD_EMC_D2_LABEL "J3[94]/P0_4-EMC_D2" /*!<@brief Label */
#define BOARD_EMC_D2_NAME "EMC_D2"              /*!<@brief Identifier name */
                                                /* @} */

/*! @name EMC_D(1) (coord A10), J3[70]P0_3-ISP_FC3_MOSI-EMC_D1
  @{ */
#define BOARD_EMC_D1_PERIPHERAL EMC                         /*!<@brief Device name: EMC */
#define BOARD_EMC_D1_SIGNAL EMC_D                           /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D1_CHANNEL 1                              /*!<@brief EMC EMC_D channel: 1 */
#define BOARD_EMC_D1_PIN_NAME EMC_D(1)                      /*!<@brief Pin name */
#define BOARD_EMC_D1_LABEL "J3[70]P0_3-ISP_FC3_MOSI-EMC_D1" /*!<@brief Label */
#define BOARD_EMC_D1_NAME "EMC_D1"                          /*!<@brief Identifier name */
                                                            /* @} */

/*! @name EMC_D(0) (coord E9), J3[97]/P0_2-ISP_FC3_MISO-EMC_D0
  @{ */
#define BOARD_EMC_D0_PERIPHERAL EMC                          /*!<@brief Device name: EMC */
#define BOARD_EMC_D0_SIGNAL EMC_D                            /*!<@brief EMC signal: EMC_D */
#define BOARD_EMC_D0_CHANNEL 0                               /*!<@brief EMC EMC_D channel: 0 */
#define BOARD_EMC_D0_PIN_NAME EMC_D(0)                       /*!<@brief Pin name */
#define BOARD_EMC_D0_LABEL "J3[97]/P0_2-ISP_FC3_MISO-EMC_D0" /*!<@brief Label */
#define BOARD_EMC_D0_NAME "EMC_D0"                           /*!<@brief Identifier name */
                                                             /* @} */

/*! @name EMC_DQM(1) (coord C12), J3[83]/P1_14-EMC_DQM1
  @{ */
#define BOARD_EMC_DQM1_PERIPHERAL EMC                /*!<@brief Device name: EMC */
#define BOARD_EMC_DQM1_SIGNAL EMC_DQM                /*!<@brief EMC signal: EMC_DQM */
#define BOARD_EMC_DQM1_CHANNEL 1                     /*!<@brief EMC EMC_DQM channel: 1 */
#define BOARD_EMC_DQM1_PIN_NAME EMC_DQM(1)           /*!<@brief Pin name */
#define BOARD_EMC_DQM1_LABEL "J3[83]/P1_14-EMC_DQM1" /*!<@brief Label */
#define BOARD_EMC_DQM1_NAME "EMC_DQM1"               /*!<@brief Identifier name */
                                                     /* @} */

/*! @name EMC_DQM(0) (coord G10), J3[53]/P1_13-EMC_DQM0
  @{ */
#define BOARD_EMC_DQM0_PERIPHERAL EMC                /*!<@brief Device name: EMC */
#define BOARD_EMC_DQM0_SIGNAL EMC_DQM                /*!<@brief EMC signal: EMC_DQM */
#define BOARD_EMC_DQM0_CHANNEL 0                     /*!<@brief EMC EMC_DQM channel: 0 */
#define BOARD_EMC_DQM0_PIN_NAME EMC_DQM(0)           /*!<@brief Pin name */
#define BOARD_EMC_DQM0_LABEL "J3[53]/P1_13-EMC_DQM0" /*!<@brief Label */
#define BOARD_EMC_DQM0_NAME "EMC_DQM0"               /*!<@brief Identifier name */
                                                     /* @} */

/*! @name EMC_CLK(0) (coord B4), J4[94]/P1_11-EMC_CLK0
  @{ */
#define BOARD_EMC_CLK0_PERIPHERAL EMC                /*!<@brief Device name: EMC */
#define BOARD_EMC_CLK0_SIGNAL EMC_CLK                /*!<@brief EMC signal: EMC_CLK */
#define BOARD_EMC_CLK0_CHANNEL 0                     /*!<@brief EMC EMC_CLK channel: 0 */
#define BOARD_EMC_CLK0_PIN_NAME EMC_CLK(0)           /*!<@brief Pin name */
#define BOARD_EMC_CLK0_LABEL "J4[94]/P1_11-EMC_CLK0" /*!<@brief Label */
#define BOARD_EMC_CLK0_NAME "EMC_CLK0"               /*!<@brief Identifier name */
                                                     /* @} */

/*! @name EMC_CKE(0) (coord A11), J3[73]/P1_15-EMC_CKE0
  @{ */
#define BOARD_EMC_CKE0_PERIPHERAL EMC                /*!<@brief Device name: EMC */
#define BOARD_EMC_CKE0_SIGNAL EMC_CKE                /*!<@brief EMC signal: EMC_CKE */
#define BOARD_EMC_CKE0_CHANNEL 0                     /*!<@brief EMC EMC_CKE channel: 0 */
#define BOARD_EMC_CKE0_PIN_NAME EMC_CKE(0)           /*!<@brief Pin name */
#define BOARD_EMC_CKE0_LABEL "J3[73]/P1_15-EMC_CKE0" /*!<@brief Label */
#define BOARD_EMC_CKE0_NAME "EMC_CKE0"               /*!<@brief Identifier name */
                                                     /* @} */

/*!
 * @brief Configures pin routing and optionally pin electrical features.
 *
 */

#define PIO029_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO029_FUNC_ALT1 0x01u        /*!<@brief Selects pin function.: Alternative connection 1. */
#define PIO030_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO030_FUNC_ALT1 0x01u        /*!<@brief Selects pin function.: Alternative connection 1. */

/*! @name FC0_RXD_SDA_MOSI (coord B13), J4[97]/P0_29-ISP_FC0_RXD
  @{ */
#define BOARD_ISP_FC0_RXD_PERIPHERAL FLEXCOMM0              /*!<@brief Device name: FLEXCOMM0 */
#define BOARD_ISP_FC0_RXD_SIGNAL RXD_SDA_MOSI               /*!<@brief FLEXCOMM0 signal: RXD_SDA_MOSI */
#define BOARD_ISP_FC0_RXD_PIN_NAME FC0_RXD_SDA_MOSI         /*!<@brief Pin name */
#define BOARD_ISP_FC0_RXD_LABEL "J4[97]/P0_29-ISP_FC0_RXD"  /*!<@brief Label */
#define BOARD_ISP_FC0_RXD_NAME "ISP_FC0_RXD"                /*!<@brief Identifier name */
#define BOARD_ISP_FC0_RXD_DIRECTION kPIN_MUX_DirectionInput /*!<@brief Direction */
                                                            /* @} */

/*! @name FC0_TXD_SCL_MISO (coord A2), J4[93]/P0_30-ISP_FC0_TXD
  @{ */
#define BOARD_ISP_FC0_TXD_PERIPHERAL FLEXCOMM0               /*!<@brief Device name: FLEXCOMM0 */
#define BOARD_ISP_FC0_TXD_SIGNAL TXD_SCL_MISO                /*!<@brief FLEXCOMM0 signal: TXD_SCL_MISO */
#define BOARD_ISP_FC0_TXD_PIN_NAME FC0_TXD_SCL_MISO          /*!<@brief Pin name */
#define BOARD_ISP_FC0_TXD_LABEL "J4[93]/P0_30-ISP_FC0_TXD"   /*!<@brief Label */
#define BOARD_ISP_FC0_TXD_NAME "ISP_FC0_TXD"                 /*!<@brief Identifier name */
#define BOARD_ISP_FC0_TXD_DIRECTION kPIN_MUX_DirectionOutput /*!<@brief Direction */
                                                             /* @} */

/*!
 * @brief Configures pin routing and optionally pin electrical features.
 *
 */
void BOARD_InitDEBUG_UART(void); /* Function assigned for the Cortex-M4F */

#define PIO010_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO010_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO011_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO011_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */
#define PIO012_DIGIMODE_DIGITAL 0x01u /*!<@brief Select Analog/Digital mode.: Digital mode. */
#define PIO012_FUNC_ALT6 0x06u        /*!<@brief Selects pin function.: Alternative connection 6. */

/*! @name SWDIO (coord M3), J4[32]/J7[4]/IF_SWDIO
  @{ */
#define BOARD_IF_SWDIO_PERIPHERAL SWD                /*!<@brief Device name: SWD */
#define BOARD_IF_SWDIO_SIGNAL SWDIO                  /*!<@brief SWD signal: SWDIO */
#define BOARD_IF_SWDIO_PIN_NAME SWDIO                /*!<@brief Pin name */
#define BOARD_IF_SWDIO_LABEL "J4[32]/J7[4]/IF_SWDIO" /*!<@brief Label */
#define BOARD_IF_SWDIO_NAME "IF_SWDIO"               /*!<@brief Identifier name */
                                                     /* @} */

/*! @name SWCLK (coord L3), J4[34]/J7[4]/SWDCLK_TRGT
  @{ */
#define BOARD_SWDCLK_TRGT_PERIPHERAL SWD                   /*!<@brief Device name: SWD */
#define BOARD_SWDCLK_TRGT_SIGNAL SWCLK                     /*!<@brief SWD signal: SWCLK */
#define BOARD_SWDCLK_TRGT_PIN_NAME SWCLK                   /*!<@brief Pin name */
#define BOARD_SWDCLK_TRGT_LABEL "J4[34]/J7[4]/SWDCLK_TRGT" /*!<@brief Label */
#define BOARD_SWDCLK_TRGT_NAME "SWDCLK_TRGT"               /*!<@brief Identifier name */
                                                           /* @} */

/*! @name SWO (coord P2), J4[27]/J7[6]/SWO_TRGT
  @{ */
#define BOARD_SWO_TRGT_PERIPHERAL SWD                /*!<@brief Device name: SWD */
#define BOARD_SWO_TRGT_SIGNAL SWO                    /*!<@brief SWD signal: SWO */
#define BOARD_SWO_TRGT_PIN_NAME SWO                  /*!<@brief Pin name */
#define BOARD_SWO_TRGT_LABEL "J4[27]/J7[6]/SWO_TRGT" /*!<@brief Label */
#define BOARD_SWO_TRGT_NAME "SWO_TRGT"               /*!<@brief Identifier name */
                                                     /* @} */

/*!
 * @brief Configures pin routing and optionally pin electrical features.
 *
 */
/* FC8_SCK (coord D2), RP1[1]/U9[8]/P3_15-SD_WPn */
#define BOARD_INITGT202SHIELD_SD_WPn_PERIPHERAL                        FLEXCOMM8   /*!< Device name: FLEXCOMM8 */
#define BOARD_INITGT202SHIELD_SD_WPn_SIGNAL                                  SCK   /*!< FLEXCOMM8 signal: SCK */
#define BOARD_INITGT202SHIELD_SD_WPn_PIN_NAME                            FC8_SCK   /*!< Pin name */
#define BOARD_INITGT202SHIELD_SD_WPn_LABEL           "RP1[1]/U9[8]/P3_15-SD_WPn"   /*!< Label */
#define BOARD_INITGT202SHIELD_SD_WPn_NAME                               "SD_WPn"   /*!< Identifier name */

/* PIO3_3 (coord A13), PWRON */
#define BOARD_INITGT202SHIELD_PWRON_GPIO                                    GPIO   /*!< GPIO device name: GPIO */
#define BOARD_INITGT202SHIELD_PWRON_PORT                                      3U   /*!< PORT device index: 3 */
#define BOARD_INITGT202SHIELD_PWRON_GPIO_PIN                                  3U   /*!< PIO3 pin index: 3 */
#define BOARD_INITGT202SHIELD_PWRON_PIN_NAME                              PIO3_3   /*!< Pin name */
#define BOARD_INITGT202SHIELD_PWRON_LABEL                                "PWRON"   /*!< Label */
#define BOARD_INITGT202SHIELD_PWRON_NAME                                 "PWRON"   /*!< Identifier name */
#define BOARD_INITGT202SHIELD_PWRON_DIRECTION           kPIN_MUX_DirectionOutput   /*!< Direction */

/* PIO1_0 (coord N3), IRQ */
#define BOARD_INITGT202SHIELD_IRQ_GPIO                                      GPIO   /*!< GPIO device name: GPIO */
#define BOARD_INITGT202SHIELD_IRQ_PORT                                        1U   /*!< PORT device index: 1 */
#define BOARD_INITGT202SHIELD_IRQ_GPIO_PIN                                    0U   /*!< PIO1 pin index: 0 */
#define BOARD_INITGT202SHIELD_IRQ_PIN_NAME                                PIO1_0   /*!< Pin name */
#define BOARD_INITGT202SHIELD_IRQ_LABEL                                    "IRQ"   /*!< Label */
#define BOARD_INITGT202SHIELD_IRQ_NAME                                     "IRQ"   /*!< Identifier name */
#define BOARD_INITGT202SHIELD_IRQ_DIRECTION              kPIN_MUX_DirectionInput   /*!< Direction */

void BOARD_InitSWD_DEBUG(void); /* Function assigned for the Cortex-M4F */
void BOARD_InitGT202Shield(void); /* Function assigned for the Cortex-M4F */
void BOARD_InitSPIFI(void); /* Function assigned for the Core #0 (ARM Cortex-M4) */

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
