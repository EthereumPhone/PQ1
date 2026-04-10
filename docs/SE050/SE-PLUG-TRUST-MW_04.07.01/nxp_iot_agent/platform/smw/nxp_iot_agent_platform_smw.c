/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <nxp_iot_agent_platform.h>
#include <nxp_iot_agent_log.h>
#include <errno.h>
#include <smw_osal.h>

iot_agent_status_t iot_agent_platform_init(int argc, const char *argv[], iot_agent_platform_context_t* platform_context)
{
	int res;

	res = smw_osal_lib_init();
	if (res != SMW_STATUS_OK && res != SMW_STATUS_LIBRARY_ALREADY_INIT) {
		IOT_AGENT_ERROR("SMW library initialization failed %d", res);
		return IOT_AGENT_FAILURE;
	}

	return IOT_AGENT_SUCCESS;
}
