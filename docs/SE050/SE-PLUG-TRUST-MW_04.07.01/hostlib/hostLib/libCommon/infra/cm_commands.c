/*
*
* Copyright 2016,2020 NXP
* SPDX-License-Identifier: Apache-2.0
*/

#include <stddef.h>
#include <assert.h>
#include <string.h>
#include "se05x_tlv.h"
#include "nxLog_hostLib.h"

#include "smCom.h"
#include "cm_commands.h"

static U16 CM_SendSmComRawCommand(void *conn_ctx, uint8_t* cmd, U16 cmdLen)
{
    U16 rv = SM_NOT_OK;
    U32 ret = 0;
	uint8_t resp[256] = { 0 };
    U32 respLen = sizeof(resp);
    size_t rspIndex = 0;

    ret = smCom_TransceiveRaw(conn_ctx, cmd, cmdLen, resp, &respLen);
    if (ret != SM_OK) {
        LOG_E("Error in smCom_TransceiveRaw !!!");
        goto exit;
    }
    else {
        rspIndex = respLen - 2;
        ret = (resp[rspIndex] << 8) | (resp[rspIndex + 1]);
        if (ret != SM_OK) {
            LOG_E("Command Failed");
            LOG_MAU8_E("Command Response", resp, respLen);
            goto exit;
        }
        else {
            LOG_I("Command Successful!!!");
            if (respLen > 2) {
                LOG_MAU8_I("Command Response", resp, respLen - 2);
            }
        }
    }

    rv = SM_OK;
exit:
	return rv;
}

/**
 * Select card manager and send garbageCollection command
 *
 * \param[in] conn_ctx - Connection context
 * \param[out] None
 *
 * \retval ::SW_OK Upon successfull execution
 */
U16 CM_InvokeGarbageCollection (void *conn_ctx)
{
    U16 rv = SM_NOT_OK;
    U32 ret = 0;
    uint8_t select_cmd[5] = { 0x00, 0xA4, 0x04, 0x00, 0x00 };
    uint8_t invoke_garbage_collection_cmd[9] = { 0x80, 0xCA, 0x00, 0xFE, 0x04, 0xDF, 0x25, 0x01, 0x03 };

    LOG_W("Invoking this api will close the existing session to SE05X.");
    LOG_W("To use SE05X, open session again.");

    LOG_I("Sending Select command ");
    ret = CM_SendSmComRawCommand(conn_ctx, select_cmd, sizeof(select_cmd));
    if (ret != SM_OK) {
        LOG_E("Error in sending Select Command !!!");
        goto exit;
    }

    LOG_I("Sending 'Invoke Garbage Collection' Command ");
    ret = CM_SendSmComRawCommand(conn_ctx, invoke_garbage_collection_cmd, sizeof(invoke_garbage_collection_cmd));
    if (ret != SM_OK) {
        LOG_E("Error in sending invoke_garbage_collection_cmd !!!");
        goto exit;
    }

    rv = SW_OK;
exit:
    return rv;
}
