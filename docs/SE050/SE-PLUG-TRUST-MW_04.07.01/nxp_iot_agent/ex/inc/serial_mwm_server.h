/*
 * Copyright 2020-2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _SERIAL_MWM_SERVER_H_
#define _SERIAL_MWM_SERVER_H_

#include <stdio.h>
#include <stdint.h>

#if defined(LPC_WIFI)
#include "serial_mwm.h"
#endif //LPC_WIFI

/*!
 * @defgroup serial_mwm SerialMWM
 * @{
 */

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * API
 ******************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif

#if defined(LPC_WIFI)
/*!
 * @name Initialization
 * @{
 */

/*!
 * @brief Binds socket to port.
 *
 * This function binds the socket to the port.
 *
 * @param socket Handle of socket
 * @param addr Valid address of remote host
 * @param addrlen Size of addr
 * @return 0 - success, negative number - error
 */
int mwm_bind(int socket, mwm_sockaddr_t *addr, uint32_t addrlen);

/*!
 * @brief Puts socket in listen.
 *
 * This function puts the socket in listening mode.
 *
 * @param socket Handle of socket
 * @param backlog Maximum number of connections
 * @param addrlen Size of addr
 * @return 0 - success, negative number - error
 */
int mwm_listen(int socket, int backlog);

/*!
 * @brief Accepts client connection.
 *
 * This function accepts client connection.
 *
 * @param socket Handle of socket
 * @return handle of socket for further communication, negative number - error
 */
int mwm_accept(int socket);
/* @} */

#endif

#if defined(__cplusplus)
}
#endif //LPC_WIFI

/* @} */
#endif /* _SERIAL_MWM_SERVER_H_ */
