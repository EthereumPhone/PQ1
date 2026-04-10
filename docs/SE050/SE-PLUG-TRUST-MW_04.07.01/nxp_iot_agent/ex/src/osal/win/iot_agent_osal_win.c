/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "iot_agent_osal.h"

iot_agent_status_t iot_agent_osal_start_task(agent_start_task_t agent_start_task, int argc, const char* argv[]){
	return agent_start_task(argc, argv);
}
