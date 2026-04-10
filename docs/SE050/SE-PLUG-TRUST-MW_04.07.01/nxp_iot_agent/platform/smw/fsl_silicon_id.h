
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2023 NXP
 */

#ifndef __FSL_SILICON_ID_H__
#define __FSL_SILICON_ID_H__

#include <stdint.h>
#include <stddef.h>

int read_device_uuid(uint8_t *buffer, size_t *len);

#endif /* __FSL_SILICON_ID_H__ */
