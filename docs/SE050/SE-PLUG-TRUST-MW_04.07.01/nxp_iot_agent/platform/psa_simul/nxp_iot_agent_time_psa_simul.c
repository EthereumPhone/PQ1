/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <nxp_iot_agent_time.h>
#include <nxp_iot_agent_log.h>

iot_agent_time_t iot_agent_time = { 0 };

void iot_agent_time_init_measurement(iot_agent_time_context_t* time_context)
{
	IOT_AGENT_WARN("Time measurement function to be implemented for the given platform");
}

void iot_agent_time_conclude_measurement(iot_agent_time_context_t* time_context)
{
	IOT_AGENT_WARN("Time measurement function to be implemented for the given platform");
}

long iot_agent_time_get_measurement(iot_agent_time_context_t* time_context)
{
	IOT_AGENT_WARN("Time measurement function to be implemented for the given platform");
	return 0;
}

void iot_agent_time_free_measurement_ctx(iot_agent_time_context_t* time_context)
{
	IOT_AGENT_WARN("Time measurement function to be implemented for the given platform");
}

iot_agent_status_t iot_agent_log_performance_timing(void)
{
	IOT_AGENT_WARN("Time measurement function to be implemented for the given platform");
	return IOT_AGENT_SUCCESS;
}