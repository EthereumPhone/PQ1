/*
 * Copyright 2018 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef EXT_UNITY_UNITY_CONFIG_H_
#define EXT_UNITY_UNITY_CONFIG_H_

#ifdef USE_SERGER_RTT
#include <SEGGER_RTT.h>
#endif

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */



/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

#define UNITY_PRINT_EOL() \
    UNITY_OUTPUT_CHAR('\r'); \
    UNITY_OUTPUT_CHAR('\n'); \
    UNITY_OUTPUT_CHAR('\r'); \
    UNITY_OUTPUT_CHAR('\n');

#ifdef USE_SERGER_RTT
#define UNITY_OUTPUT_CHAR(v) \
    SEGGER_RTT_PutChar(0,v)
#define UNITY_OUTPUT_COMPLETE()                     \
    UNITY_PRINT_EOL();                              \
    SEGGER_RTT_WriteString(0,                       \
        "AUTOMATED TESTS: UNITY_OUTPUT_COMPLETE"    \
        );                                          \
    UNITY_PRINT_EOL();


#endif

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */


#endif /* EXT_UNITY_UNITY_CONFIG_H_ */
