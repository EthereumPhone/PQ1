/* Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifndef SIM
#include <termios.h>
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "sm_types.h"

#define SM_UART_OK                   0x9000
#define SM_UART_CHANNEL_INIT_FAILED        -1
#define SM_UART_CHANNEL_BAUDRATE_UNKNOWN   -2
#define SM_UART_CHANNEL_SET_TIMEOUT_FAILED -3
#define SM_UART_CHANNEL_SET_ATTRIB_FAILED  -4

#define SM_BR_38400    0x03
#define SM_BR_115200   0x06

/**
 * Initialize UART: Open serial device and store handle.
 * Configure the UART link with default parameters:
 * - baudrate 38.4 kbps
 * - 8 bit no parity
 * - timeout of 500 ms in case no character is read
 *
 * \param[IN] portname    Name of serial device to be opened (e.g. "/dev/ttyUSB0")
 *
 * \retval (<0)           Could not open device; error code of 'open' is returned
 * \retval ::SM_UART_OK   UART device was opened successfully
 *
 */
int smUartInit(char *portname);

/**
 * Configure the UART for the requested baudrate.
 *
 * \param[IN] baudRateIdx    Symbolic constant representing the requested baudrate
 *
 * \retval ::SM_UART_CHANNEL_INIT_FAILED  UART channel was not initialized
 * \retval ::SM_UART_CHANNEL_BAUDRATE_UNKNOWN  requested baudrate not known or supported
 * \retval ::SM_UART_CHANNEL_SET_ATTRIB_FAILED failed to set requested baudrate
 * \retval ::SM_UART_OK      Baudrate was successfully set
 *
 */
int smUartSetBaudRate(int baudRateIdx);

/**
 * Send data on UART channel previously opened with smUartInit
 *
 * \param[IN] sndBuf   Data to be sent
 * \param[IN] nSndBuf  amount of byte to be sent
 *
 * \retval ::SM_UART_CHANNEL_INIT_FAILED  UART channel was not initialized
 * \retvak ::SM_UART_OK                   All other cases
 */
int smUartWrite(U8 *sndBuf, int nSndBuf);

/**
 * Retrieve data from UART channel previously opened with smUartInit
 *
 * \param[IN,OUT] rcvBuf    IN: Buffer provided by caller; OUT: Data retrieved
 * \param[IN]     nRcvBuf   IN: Size of data buffer provided by caller
 *
 * \retval (>=0)                          Amount of data retrieved in this call
 * \retval ::SM_UART_CHANNEL_INIT_FAILED  UART channel was not initialized
 *
 */
int smUartRead(U8 *rcvBuf, int nRcvBuf);

/**
 * Implements a simple one character timeout model
 *
 * \param[IN] n100ms    n100ms < 1: Either at least one byte is read or the timeout value has been exceeded; n100ms = 0: no timeout
 *
 * \retval ::SM_UART_OK
 * \retval ::SM_UART_CHANNEL_SET_TIMEOUT_FAILED
 * \retval ::SM_UART_CHANNEL_INIT_FAILED  UART channel was not initialized
 *
 */
int smUartTimeout(int n100ms);
