/*
 * Copyright 2020-2021,2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iot_agent_rtp_client.h>
#include <nxp_iot_agent_macros.h>

#if defined(USE_RTOS) && (USE_RTOS == 1)
#ifndef INC_FREERTOS_H /* Header guard of FreeRTOS */
#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#endif /* INC_FREERTOS_H */
#include "task.h"
#include <iot_agent_osal_freertos.h>
#include <iot_agent_network.h>
#define EX_SSS_BOOT_RTOS_STACK_SIZE (1024*16)
#endif

const char* hostname = "127.0.0.1";
const char* port = "7050";

#if defined(USE_RTOS) && (USE_RTOS == 1)
rtos_arguments_t server;
#endif


#if defined(USE_RTOS) && (USE_RTOS == 1)
static void remote_provisioning_start_task(void *args)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    agent_status = network_init();
    AGENT_SUCCESS_OR_EXIT_MSG("Network initialization failed");

    const TickType_t xDelay = 2 * 1000 / portTICK_PERIOD_MS;

    for (;;)
    {
    	iot_agent_freertos_led_start();
        rtos_arguments_t* a = args;
        agent_status = remote_provisioning_start(a->hostname, a->port);

		if (agent_status == IOT_AGENT_SUCCESS)
		{
			iot_agent_freertos_led_success();
		}
		else
		{
			iot_agent_freertos_led_failure();
		}

		vTaskDelay(xDelay);
        //run only once
        while (1);
    }
exit:
    return;
}

static int remote_provisioning_init_rtos(void *args)
{
	iot_agent_freertos_bm();

    if (xTaskCreate(&remote_provisioning_start_task,
        "remote_runner_start_session_task",
        EX_SSS_BOOT_RTOS_STACK_SIZE,
        (void *)args,
        (tskIDLE_PRIORITY),
        NULL) != pdPASS) {
        IOT_AGENT_INFO("Task creation failed!.\r\n");
        while (1);
    }

    /* Run RTOS */
    vTaskStartScheduler();

    return 0;
}
#endif

int main(int argc, const char *argv[])
{
#if defined(USE_RTOS) && (USE_RTOS == 1)
    server.hostname = hostname;
    server.port = port;

    return remote_provisioning_init_rtos(&server);
#else
    if (argc > 1) {
        if (strcmp(argv[1], "-help") == 0)
        {
            printf("Usage: Default host and port is set to %s %s\n", hostname, port);
            printf("To run with default Host and Port: \n\tremote_provisioning_client\n");
            printf("Set Host and with default port: \n\tremote_provisioning_client 1.1.1.1\n");
            printf("Set both Host and port: \n\tremote_provisioning_client 1.1.1.1 7060\n");
            return -1;
        }
        hostname = argv[1];
    }
    if (argc > 2) {
        port = argv[2];
    }

    return remote_provisioning_start(hostname, port);
#endif
}


