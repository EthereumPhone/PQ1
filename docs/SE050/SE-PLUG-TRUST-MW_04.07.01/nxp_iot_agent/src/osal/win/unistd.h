/*
 * Copyright 2018-2019, 2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef _NXP_IOT_AGENT_PLATFORM_UNISTD_H_
#define _NXP_IOT_AGENT_PLATFORM_UNISTD_H_

#ifdef _WIN32

#include <io.h>
 /* Values for the second argument to access.
 These may be OR'd together.  */
#define R_OK    4       /* Test for read permission.  */
#define W_OK    2       /* Test for write permission.  */
//#define   X_OK    1       /* execute permission - unsupported in windows*/
#define F_OK    0       /* Test for existence.  */

#endif // _WIN32

#endif // _NXP_IOT_AGENT_PLATFORM_UNISTD_H_
