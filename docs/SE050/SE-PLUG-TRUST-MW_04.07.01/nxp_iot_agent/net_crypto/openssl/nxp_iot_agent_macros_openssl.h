/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _NXP_IOT_AGENT_MACROS_OPENSSL_H_
#define _NXP_IOT_AGENT_MACROS_OPENSSL_H_
 
#include "nxp_iot_agent_status.h"
#include "nxp_iot_agent_log.h"

//
// The following macros simplify and unify error handling for openssl calls. They do
// rely on the following variables being available in the current scope:
//    * int openssl_status
//    * iot_agent_status_t agent_status
// Also, upon error, they want to jump to a label
//    goto exit
// which must be defined in the function scope.

#define OPENSSL_ASSERT_OR_EXIT_STATUS(CONDITION, FUNCTION_NAME, STATUS)       \
if (!(CONDITION))                                         \
{                                                         \
    print_openssl_errors(FUNCTION_NAME);                  \
	agent_status = STATUS;                     \
	goto exit;                                         \
}

#define OPENSSL_ASSERT_OR_EXIT(CONDITION, FUNCTION_NAME)       \
OPENSSL_ASSERT_OR_EXIT_STATUS(CONDITION, FUNCTION_NAME, IOT_AGENT_FAILURE)


#define OPENSSL_SUCCESS_OR_EXIT_STATUS(FUNCTION_NAME, STATUS) \
OPENSSL_ASSERT_OR_EXIT_STATUS(openssl_status == 1, FUNCTION_NAME, STATUS)

#define OPENSSL_SUCCESS_OR_EXIT(FUNCTION_NAME) \
OPENSSL_ASSERT_OR_EXIT(openssl_status == 1, FUNCTION_NAME)

#endif // _NXP_IOT_AGENT_MACROS_OPENSSL_H_
