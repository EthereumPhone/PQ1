/*
 *
 * Copyright 2018 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "veneer_table.h"
#include "pin_mux.h"
#include "board.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define PRINTF_NSE DbgConsole_Printf_NSE
/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/

void SystemInit(void)
{
}
/*!
 * @brief Main function
 */
int main(void)
{
    PRINTF_NSE("Welcome in normal world (SIMW)!\r\n");

    while (1) {
    }
}
