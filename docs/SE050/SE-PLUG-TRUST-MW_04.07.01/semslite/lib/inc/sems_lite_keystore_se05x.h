/*
 *
 * Copyright 2018,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _NXP_IOT_AGENT_KEYSTORE_SEMS_LITE_SE05X_H_
#define _NXP_IOT_AGENT_KEYSTORE_SEMS_LITE_SE05X_H_

#include <sems_lite_agent_context.h>
#include <nxp_iot_agent_common.h>
#include <nxp_iot_agent_keystore.h>

#if SSS_HAVE_APPLET_SE05X_IOT

#include <fsl_sss_api.h>

/*!
 * @addtogroup sems_lite_agent_keystore_SE05X
 * @{
 */

/**
  * @brief A context holding the state of a keystore; this is passed to keystore interface functions.
  */
typedef struct iot_agent_keystore_sems_lite_se05x_context_t
{
    sems_lite_agent_ctx_t *sems_lite_agent_context;
} iot_agent_keystore_sems_lite_se05x_context_t;

/*! @brief Initialize a SEMS Lite keystore.
 *
 * Ownership of the keystore_context remains at the caller!
 */
iot_agent_status_t iot_agent_keystore_sems_lite_se05x_init(iot_agent_keystore_t *keystore,
    uint32_t identifier,
    iot_agent_keystore_sems_lite_se05x_context_t *keystore_context);

/*! @brief Destroy the context of the SEMS Lite keystore.
 */
iot_agent_status_t iot_agent_keystore_sems_lite_se05x_destroy(void *context);

/*! @brief Open a connection to the SEMS Lite keystore.
 */
iot_agent_status_t iot_agent_keystore_sems_lite_se05x_open_session(void *context);

/*! @brief Cloxe a connection to the SEMS Lite keystore.
 */
void iot_agent_keystore_sems_lite_se05x_close_session(void *context);

/*! @brief Get an endpoint information of the SEMS Lite keystore
 * @param[in] context End point context
 * @param[in] endpoint_information End point information
 *
 */
bool iot_agent_keystore_sems_lite_se05x_get_endpoint_info(void *context, void *endpoint_information);

/** @copydoc iot_agent_endpoint_request_handler_t
*
*/
bool iot_agent_keystore_sems_lite_se05x_handle_request(
    pb_istream_t *istream, pb_ostream_t *ostream, const pb_field_t *message_type, void *context);

extern const iot_agent_keystore_interface_t iot_agent_keystore_sems_lite_se05x_interface;

/*!
*@}
*/ /* end of edgelock2go_agent_keystore_SE05X */

#endif // #if SSS_HAVE_APPLET_SE05X_IOT

#endif // _NXP_IOT_AGENT_KEYSTORE_SEMS_LITE_SE05X_H_
