/*
 * Copyright 2018, 2020-2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include "board.h"
#include "fsl_gpio.h"
#include "pin_mux.h"

#if defined(MBEDTLS)
#include "ksdk_mbedtls.h"
#endif

#ifndef INC_FREERTOS_H /* Header guard of FreeRTOS */
#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#endif /* INC_FREERTOS_H */
#include "task.h"

#if defined(LPC_WIFI)
#include "iot_wifi.h"
#include "sm_demo_utils.h"
#endif // LPC_WIFI

#include <nxp_iot_agent_status.h>

iot_agent_status_t network_init(void)
{
#if defined(LPC_WIFI)

    if (network_wifi_init() != eWiFiSuccess) {
        return IOT_AGENT_FAILURE;
    }
    if (network_wifi_connect_ap() != eWiFiSuccess) {
            return IOT_AGENT_FAILURE;
    }
    return IOT_AGENT_SUCCESS;
#else
    return IOT_AGENT_FAILURE;
#endif // LPC_WIFI
}
