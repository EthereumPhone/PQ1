/*
 *
 * Copyright 2018,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef _NXP_SEMS_LITE_AGENT_HANDLE_H_
#define _NXP_SEMS_LITE_AGENT_HANDLE_H_

#ifdef __cplusplus
extern "C" {
#endif

#if SSS_HAVE_APPLET_SE05X_IOT

#include <sems_lite_agent_context.h>

/** @ingroup sems_lite_agent
*
* @page page_sems_lite_agent SEMS Lite agent
*
* @brief Public Apis
*/

/*!
* @addtogroup sems_lite_agent
* @{
*/

/*! @brief Reset SE
* @param[in]  context: sems lite agent context
* @retval kStatus_SEMS_Lite_Success Upon success
*/
sems_lite_status_t sems_lite_agent_reset_se(sems_lite_agent_ctx_t *sems_lite_agent_context);

/*!
*@}
*/ /* end of sems_lite_agent */

#endif

#ifdef __cplusplus
} // extern "C"
#endif

#endif // #ifndef _NXP_SEMS_LITE_AGENT_HANDLE_H_
