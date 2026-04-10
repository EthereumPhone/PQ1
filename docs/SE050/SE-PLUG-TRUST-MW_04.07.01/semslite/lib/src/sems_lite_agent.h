/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SEMS_LITE_AGENT_INC
#define SEMS_LITE_AGENT_INC

#include <ex_sss_boot.h>
#include <se05x_enums.h>
#include <sm_types.h>

#include "fsl_sss_api.h"
#include "nxLog.h"
#include "nxScp03_Types.h"
#if SSS_HAVE_APPLET_SE05X_IOT
#include "fsl_sss_se05x_types.h"
#endif

#include "sems_lite_api.h"
#include "sems_lite_agent_context.h"
#include "nxp_iot_agent_dispatcher.h"
#include "pb.h"
#include "pb_decode.h"
#include "pb_encode.h"

/* *****************************************************************************************************************
 * Types/Structure Declarations
 * ***************************************************************************************************************** */

/** Status of the SEMS Lite APIs */

/* *****************************************************************************************************************
 * Types/Structure Declarations
 * ***************************************************************************************************************** */

/**
 * @brief      { function_description }
 *
 * @param      ctx                  The context
 * @param[in]  keystore             The keystore
 *
 * @return     The sems lite status.
 */
sems_lite_status_t sems_lite_agent_register_keystore(iot_agent_context_t *ctx, iot_agent_keystore_t *keystore);

/**
 * @brief      { function_description }
 *
 * @param      dispatcher_context  The dispatcher context
 * @param      agent_context       The agent context
 * @param[in]  stream_type         The stream type
 *
 * @return     The sems lite status.
 */
sems_lite_status_t sems_lite_agent_init_dispatcher(iot_agent_dispatcher_context_t *dispatcher_context,
    iot_agent_context_t *agent_context,
    iot_agent_stream_type_t stream_type);

/**
 * @brief      { function_description }
 *
 * @param      context  The context
 *
 * @return     The sems lite status.
 */
sems_lite_status_t sems_lite_agent_handle_status_word(void *context);

/**
 * @brief      { function_description }
 *
 * @param      context  The context
 * @param      input  Input stream
 * @param      output  Output stream
 *
 * @return     The sems lite status.
 */
sems_lite_status_t sems_lite_agent_dispatcher(
    iot_agent_dispatcher_context_t *dispatcher_context, pb_istream_t *input, pb_ostream_t *output);

/**
 * @brief      { function_description }
 *
 * @param      context  The context
 * @param      pkgBuf  Pointer to package buffer
 * @param      pass  Verification result
 *
 * @return     The sss status.
 */
sss_status_t sems_lite_agent_verify_all_elf_version(
    sems_lite_agent_ctx_t *context, multicast_package_t *pkgBuf, sems_lite_version_check_result_t *all_elf_pass);

#endif // !SEMS_LITE_AGENT_INC
