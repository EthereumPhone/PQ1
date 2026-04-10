/* Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _VENEER_PRINTF_TABLE_H_
#define _VENEER_PRINTF_TABLE_H_

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*!
 * @brief Entry function for debug PRINTF (DbgConsole_Printf)
 *
 * This function provides interface between secure and normal worlds
 * This function is called from normal world only
 *
 * @param s     String to be printed
 *
*/
void DbgConsole_Printf_NSE(char const *s);

#endif /* _VENEER_PRINTF_TABLE_H_ */
