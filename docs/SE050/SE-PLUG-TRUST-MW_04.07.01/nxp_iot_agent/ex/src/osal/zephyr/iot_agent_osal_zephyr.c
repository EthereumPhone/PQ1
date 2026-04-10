/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include "iot_agent_osal.h"
#include "iot_agent_network.h"
#include "nxp_iot_agent_common.h"
#include "nxp_iot_agent_log.h"
#include "nxp_iot_agent_status.h"
#include "nxp_iot_agent_macros.h"
#include "nxp_iot_agent_time.h"

#define EX_SSS_BOOT_RTOS_STACK_SIZE (1024*32)

K_THREAD_STACK_DEFINE(agent_thread_stack_area, EX_SSS_BOOT_RTOS_STACK_SIZE);

#if NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM
#ifdef NXP_IOT_AGENT_ENABLE_LITE
extern void config_mbedtls_threading_alt(void);
#else
extern uint32_t tfm_ns_interface_init(void);
#endif
#endif

// the arguments passed to the FreeRTOS as pointer to it; it should not be allocated on the stack
typedef struct agent_start_task_ags
{
	agent_start_task_t agent_start_task;
	int c;
	const char **v;
} agent_start_task_args_t;

static agent_start_task_args_t agent_start_args;

static void agent_start_task_in_loop(void *args, void*, void*){

	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

#if IOT_AGENT_TIME_MEASUREMENT_ENABLE
    iot_agent_time_context_t iot_agent_demo_boot_time = { 0 };
    iot_agent_time_init_measurement(&iot_agent_demo_boot_time);
#endif

#if NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM
#ifdef NXP_IOT_AGENT_ENABLE_LITE
	config_mbedtls_threading_alt();
#else
    tfm_ns_interface_init();
#endif
#endif

    agent_status = network_init();
    AGENT_SUCCESS_OR_EXIT_MSG("Network initialization failed");

    const k_timeout_t delay = K_SECONDS(2);

#if IOT_AGENT_TIME_MEASUREMENT_ENABLE
    iot_agent_time_conclude_measurement(&iot_agent_demo_boot_time);
    IOT_AGENT_INFO("Performance timing: DEVICE_INIT_TIME : %lums", iot_agent_time_get_measurement(&iot_agent_demo_boot_time));
    iot_agent_time_free_measurement_ctx(&iot_agent_demo_boot_time);
#endif

	for (;;)
	{
		agent_start_task_args_t* a = args;

		agent_status = a->agent_start_task(a->c, a->v);

		k_sleep(delay);

	}

exit:
	return;
}

iot_agent_status_t iot_agent_osal_start_task(agent_start_task_t agent_start_task, int argc, const char* argv[])
{
	
	agent_start_args.agent_start_task = agent_start_task;
	agent_start_args.c = argc;
	agent_start_args.v = argv;

	static struct k_thread agent_thread_data;

	k_tid_t agent_thread_id = k_thread_create(&agent_thread_data,
		agent_thread_stack_area,
		K_THREAD_STACK_SIZEOF(agent_thread_stack_area),
		agent_start_task_in_loop,
		(void *)&agent_start_args, NULL, NULL,
		0, 0, K_FOREVER
	);
	
	k_thread_name_set(agent_thread_id, "agent_start_session_task");

	k_thread_start(agent_thread_id);

	return IOT_AGENT_FAILURE;
}
