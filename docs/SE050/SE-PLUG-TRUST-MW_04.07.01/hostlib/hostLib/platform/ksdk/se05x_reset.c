/* Copyright 2018,2020,2025 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "se05x_reset_apis.h"
#include "ax_reset.h"
#include "se_board_config.h"
#include <stdio.h>

#ifndef NORDIC_MCU
#include "fsl_gpio.h"
#endif

#include "sm_timer.h"
#include "sm_types.h"
#include "smComT1oI2C.h"
#include "nxLog_smCom.h"

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_APPLET_SE05X_IOT || SSS_HAVE_APPLET_LOOPBACK

#define SE05X_RESET_CHECK_52F_VERSION(app_ver) ((((app_ver >> 8) & 0xFF) >= 0x10) && (((app_ver >> 8) & 0xFF) <= 0x1F))

void se05x_ic_reset(uint32_t applet_version)
{
    axReset_HostConfigure();

    if (SE05X_RESET_CHECK_52F_VERSION(applet_version)){
        axReset_ResetPulseDUT(0);
    }
    else {
        axReset_ResetPulseDUT(SE_RESET_LOGIC);
    }

    smComT1oI2C_ComReset(NULL);
    sm_usleep(3000);
    return;
}

#endif
