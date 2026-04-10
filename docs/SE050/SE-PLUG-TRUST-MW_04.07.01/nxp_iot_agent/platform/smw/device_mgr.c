/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2023-2024 NXP
 */

#include <smw_device.h>

#include "nxp_iot_agent_macros.h"

#include "fsl_silicon_id.h"

int read_device_uuid(uint8_t *buffer, size_t *len)
{
	int agent_status = IOT_AGENT_SUCCESS;

	enum smw_status_code status;
	struct smw_device_uuid_args args = { 0 };

	args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	args.uuid_length = *len;
	args.uuid = buffer;

	status = smw_device_get_uuid(&args);
	ASSERT_OR_EXIT_MSG(status == SMW_STATUS_OK,
										"smw_device_get_uuid() error %d", status);

	*len = args.uuid_length;

exit:
	return agent_status;
}
