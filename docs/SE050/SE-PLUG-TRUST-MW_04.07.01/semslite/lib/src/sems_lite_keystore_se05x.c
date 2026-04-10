/*
 *
 * Copyright 2018,2020,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <sems_lite_keystore_se05x.h>

#if SSS_HAVE_APPLET_SE05X_IOT

#include <sems_lite_agent_handle.h>
#include <nxp_iot_agent_utils_protobuf.h>
#include <nxp_iot_agent_log.h>
#include <smCom.h>

#include "../protobuf/Agent.pb.h"
#include "../protobuf/Apdu.pb.h"
#include "../protobuf/Datastore.pb.h"
#include "../protobuf/Dispatcher.pb.h"
#include "sems_lite_agent.h"
#include "sems_lite_agent_context.h"
#include "nxLog_smCom.h"
#include "se05x_tlv.h"

#define IOT_AGENT_KEYSTORE_SEMS_LITE_SE05x_VERSION_MAJOR (0)
#define IOT_AGENT_KEYSTORE_SEMS_LITE_SE05x_VERSION_MINOR (0)
#define IOT_AGENT_KEYSTORE_SEMS_LITE_SE05x_VERSION_PATCH (1)
#define IOT_AGENT_KEYSTORE_SEMS_LITE_SE05x_VERSION                                                                   \
    (((IOT_AGENT_KEYSTORE_SEMS_LITE_SE05x_VERSION_MAJOR * 256) + IOT_AGENT_KEYSTORE_SEMS_LITE_SE05x_VERSION_MINOR) * \
            256 +                                                                                                    \
        IOT_AGENT_KEYSTORE_SEMS_LITE_SE05x_VERSION_PATCH)

const iot_agent_keystore_interface_t iot_agent_keystore_sems_lite_se05x_interface = {
    &iot_agent_keystore_sems_lite_se05x_destroy,
    &iot_agent_keystore_sems_lite_se05x_open_session,
    &iot_agent_keystore_sems_lite_se05x_close_session,
    {
        &iot_agent_keystore_sems_lite_se05x_get_endpoint_info,
        &iot_agent_keystore_sems_lite_se05x_handle_request,
    }};

iot_agent_status_t iot_agent_keystore_sems_lite_se05x_init(
    iot_agent_keystore_t *keystore, uint32_t identifier, iot_agent_keystore_sems_lite_se05x_context_t *keystore_context)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    keystore->iface                 = iot_agent_keystore_sems_lite_se05x_interface;
    keystore->type                  = IOT_AGENT_KS_SSS_SE05X;
    keystore->identifier            = identifier;
    keystore->context               = keystore_context;
    return agent_status;
}

iot_agent_status_t iot_agent_keystore_sems_lite_se05x_destroy(void *context)
{
    AX_UNUSED_ARG(context);
    return IOT_AGENT_SUCCESS;
}

iot_agent_status_t iot_agent_keystore_sems_lite_se05x_open_session(void *context)
{
    AX_UNUSED_ARG(context);
    return IOT_AGENT_SUCCESS;
}

void iot_agent_keystore_sems_lite_se05x_close_session(void *context)
{
    AX_UNUSED_ARG(context);
}

bool iot_agent_keystore_sems_lite_se05x_get_endpoint_info(void *context, void *endpoint_information)
{
    AX_UNUSED_ARG(context);
    nxp_iot_EndpointInformation *info = (nxp_iot_EndpointInformation *)endpoint_information;
    info->has_version                 = true;
    info->version                     = IOT_AGENT_KEYSTORE_SEMS_LITE_SE05x_VERSION;
    return true;
}

bool iot_agent_keystore_sems_lite_se05x_handle_request(
    pb_istream_t *istream, pb_ostream_t *ostream, const pb_field_t *message_type, void *context)
{
    sems_lite_agent_ctx_t *sems_lite_agent_context = NULL;
    if (context != NULL) {
        sems_lite_agent_context = ((iot_agent_keystore_sems_lite_se05x_context_t *)context)->sems_lite_agent_context;
        if (sems_lite_agent_context == NULL) {
            // Check NULL pointer.
            IOT_AGENT_ERROR("SEMS Lite agent context pointer is NULL");
            return false;
        }
    }
    else {
        IOT_AGENT_ERROR("Keystore pointer is NULL");
        return false;
    }

    if (message_type == nxp_iot_HostControlCmdRequest_fields) {
        nxp_iot_HostControlCmdRequest request = nxp_iot_HostControlCmdRequest_init_zero;
        if (!pb_decode_delimited(istream, nxp_iot_HostControlCmdRequest_fields, &request)) {
            IOT_AGENT_ERROR("Decode Server Message failed: %s\n", PB_GET_ERROR(istream));
            return false;
        }

        if (sems_lite_agent_context->skip_next_commands) {
            /** Only for SEMS Lite agent. Skip current command if some error happens in former command*/
            LOG_W("Skip current command");
            return true;
        }

        if (request.has_hostControlCmd) {
            if (request.hostControlCmd == nxp_iot_HostControlCmdRequest_eControlCmd_RESET_SE) {
                if (sems_lite_agent_reset_se(sems_lite_agent_context) != kStatus_SEMS_Lite_Success)
                    return false;
            }
            else
                return false;
        }

        sems_lite_agent_context->status_word = SEMS_LITE_AGENT_STATUS_WORD_HOST_CMD_OK;
    }
    else if (message_type == nxp_iot_ApduRequest_fields) {
        nxp_iot_ApduRequest request = nxp_iot_ApduRequest_init_default;

        uint16_t status_word;
        uint8_t apdu_memory[1024]       = {0};
        uint8_t response_memory[1024]   = {0};
        uint8_t expectation_memory[512] = {0};

        buffer_t read_buffer;
        memset((void *)&read_buffer, 0, sizeof(read_buffer));
        read_buffer.buf = &apdu_memory[0];
        read_buffer.len = sizeof(apdu_memory);

        buffer_t write_buffer;
        memset((void *)&write_buffer, 0, sizeof(write_buffer));
        write_buffer.buf = &response_memory[0];
        write_buffer.len = sizeof(response_memory);

        expectation_t expectation = {0};
        expectation.buf           = &expectation_memory[0];
        expectation.len           = sizeof(expectation_memory);
        expectation.offset        = 0;

        request.message.funcs.decode = &decode_byte_field;
        request.message.arg          = &read_buffer;

        request.expectation.funcs.decode = &decode_expect_field;
        request.expectation.arg          = &expectation;

        if (!pb_decode_delimited(istream, nxp_iot_ApduRequest_fields, &request)) {
            IOT_AGENT_ERROR("Decode Server Message failed: %s\n", PB_GET_ERROR(istream));
            return false;
        }

        if (sems_lite_agent_context->skip_next_commands) {
            /** Only for SEMS Lite agent. Skip current command if some error happens in former command*/
            LOG_W("Skip current command");
            return true;
        }

        // TODO: we should to go via the sss tunnelling api in the end...
        // TODO: smCom_TransceiveRaw does not at all care for the buffer length (at least for jrcp...).
        // This can lead to buffer overflows!!
        U32 len = (U32)write_buffer.len;
        if (SW_OK != smCom_TransceiveRaw(sems_lite_agent_context->pS05x_Ctx->conn_ctx,
                         read_buffer.buf,
                         (U16)read_buffer.len,
                         write_buffer.buf,
                         &len)) {
            IOT_AGENT_ERROR("SEMS Lite Agent Communitcation Failure");
            sems_lite_agent_context->status_word        = SEMS_LITE_AGENT_STATUS_WORD_COM_FAILURE;
            sems_lite_agent_context->skip_next_commands = true;
            return false;
        }
        write_buffer.len = len;

        /** Process response value. */
        if (len >= 2) {
            /** If not 0x9000 and not 0x61xx and not 6310,
             *   Some error happens. Stop following C-APDU
            */
            status_word = write_buffer.buf[len - 2] << 8 | write_buffer.buf[len - 1];
            //            printf("status: %x", status_word);
            if (status_word == ERR_COMM_ERROR) {
                sems_lite_agent_context->status_word = SEMS_LITE_AGENT_STATUS_WORD_COM_FAILURE;
            }
            else {
                sems_lite_agent_context->status_word = status_word;
            }

            if (verify_return_value(status_word, &expectation)) {
                sems_lite_agent_context->skip_next_commands = false;
                sems_lite_agent_context->status_word        = SEMS_LITE_AGENT_STATUS_WORD_USER_DEFINE_SUCCESS;
            }
            else if (status_word == 0x9000) {
                sems_lite_agent_context->skip_next_commands = false;
            }
            else if (((status_word & 0xFF00) == 0x6100) || status_word == 0x6310) {
                sems_lite_agent_context->skip_next_commands = false;
            }
            else
                sems_lite_agent_context->skip_next_commands = true;
        }
        else {
            IOT_AGENT_ERROR("Unexpected response value");
            return false;
        }

        nxp_iot_ResponsePayload response = nxp_iot_ResponsePayload_init_default;
        nxp_iot_ApduResponse apdu        = nxp_iot_ApduResponse_init_default;
        response.which_message           = nxp_iot_ResponsePayload_apdu_tag;
        response.message.apdu            = apdu;

        response.message.apdu.message.funcs.encode = &encode_byte_field;
        response.message.apdu.message.arg          = &write_buffer;

        // And encode the actual payload.
        if (!pb_encode(ostream, nxp_iot_ResponsePayload_fields, &response)) {
            IOT_AGENT_ERROR("pb_encode failed for nxp_iot_ResponsePayload");
            return false;
        }
    }
    else {
        IOT_AGENT_ERROR("unsupported message type");
        return false;
    }
    return true;
}

#endif // #if SSS_HAVE_SE05x
