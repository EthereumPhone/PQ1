/*
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 *
 * Copyright 2016-2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/*${header:start}*/
#include "fsl_device_registers.h"
#include "pin_mux.h"
#include "board.h"
#include "clock_config.h"
/*${header:end}*/

/*${function:start}*/
void BOARD_InitHardware(void)
{
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();
}
/*${function:end}*/
