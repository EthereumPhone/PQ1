/*
 *
 * Copyright 2019,2020,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sems_lite_api.h"

#include <ex_sss_boot.h>
#include <nxLog_App.h>
#include <smCom.h>
#include <sm_types.h>

#include "sems_lite_agent.h"
#include "sems_lite_agent_common.h"
#include "sems_lite_agent_context.h"
#include "sems_lite_keystore_se05x.h"
#include "nxEnsure.h"
#include "nxp_iot_agent_dispatcher.h"
#include "string.h" /* memset */

/* Memory required in stack to process response buffer
 * during applet update.
 */
#define RESPONSE_BUFFER_MEMORY_SIZE 3072

#if (SSS_HAVE_SSS)
/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */
sems_lite_status_t sems_lite_agent_load_package(sems_lite_agent_ctx_t *context, multicast_package_t *pkgBuf)
{
    sems_lite_status_t retval                       = kStatus_SEMS_Lite_ERR_General;
    sems_lite_tearDown_status_t tearStatus          = sems_lite_notear;
    sems_lite_recovery_status_t recoveryStatus      = sems_lite_recovery_not_started;
    sss_status_t sss_stat                           = kStatus_SSS_Fail;
    sems_lite_version_check_result_t elf_check_pass = kStatus_SEMS_Lite_Version_Pass;
    bool skip_mem_check                             = false;
    pb_istream_t input_stream;
    pb_ostream_t output_stream;
    uint8_t prev_sign_buffer[128] = {0};
    size_t prev_sign_buffer_len   = sizeof(prev_sign_buffer);
    uint8_t *ca_identifier        = prev_sign_buffer;
    size_t ca_identifier_len      = prev_sign_buffer_len;
    uint8_t *pbKey                = prev_sign_buffer;
    size_t pbKeyLen               = prev_sign_buffer_len;
    uint8_t response_buffer_memory[RESPONSE_BUFFER_MEMORY_SIZE];
    iot_agent_context_t iot_agent_context                         = {0};
    iot_agent_keystore_t keystore                                 = {0};
    iot_agent_keystore_sems_lite_se05x_context_t keystore_context = {0};
    iot_agent_dispatcher_context_t dispatcher_context             = {0};

    ENSURE_OR_GO_EXIT((pkgBuf != NULL) && (context != NULL));

    if (context->session_opened == false) {
        LOG_E("SEMS Lite session is not opened. Call sems_lite_agent_session_open() first!!!");
        retval = kStatus_SEMS_Lite_ERR_General;
        goto exit;
    }

    /* Check if CA identifier match */
    sss_stat = sems_lite_get_CA_identifier(context, ca_identifier, &ca_identifier_len);
    ENSURE_OR_GO_EXIT(sss_stat == kStatus_SSS_Success);
    if ((sizeof(pkgBuf->targetEntityID) != ca_identifier_len) ||
        (memcmp(pkgBuf->targetEntityID, ca_identifier, sizeof(pkgBuf->targetEntityID)) != 0)) {
        LOG_E("SEMS Lite Target Entity ID Mismatch!!!");
        LOG_E("May be wrong OEF.");
        retval = kStatus_SEMS_Lite_ERR_NotApplicable;
        goto exit;
    }
    else {
        LOG_I("Check CA Identifier Passed.");
    }

    /* Check if CA Public Key match */
    if (pkgBuf->pPkSemsCaAut != NULL) {
        /* Get Public Key */
        memset(pbKey, 0, pbKeyLen);
        sss_stat = sems_lite_get_Publickey(context, pbKey, &pbKeyLen);
        ENSURE_OR_GO_EXIT(sss_stat == kStatus_SSS_Success);

        if ((pkgBuf->pkSemsCaAutLen != pbKeyLen) || (memcmp(pkgBuf->pPkSemsCaAut, pbKey, pbKeyLen) != 0)) {
            LOG_E("SEMS Lite Public Key Mismatch!!!");
            retval = kStatus_SEMS_Lite_ERR_NotApplicable;
            goto exit;
        }
        else {
            LOG_I("Check CA Public Key Passed.");
        }
    }
    else {
        LOG_W("No CA Public Key Found In Package! Maybe Old Package.");
    }

    if (pkgBuf->pSignatureOverCommands != NULL) {
        // In case user provide signature, check tear status.
        if (sems_lite_check_Tear(context, &tearStatus) == kStatus_SSS_Success) {
            if (tearStatus == sems_lite_tear) {
                // Tear happens in last script
                LOG_I("FN %s: Teardown in last script", __FUNCTION__);

                // Get Last script signature
                if (sems_lite_get_SignatureofLastScript(context, prev_sign_buffer, &prev_sign_buffer_len) ==
                    kStatus_SSS_Success) {
                    if (prev_sign_buffer_len == 0) {
                        // Tear happens but no signature.
                        // This happens only for the first package after bulk update.
                        // Skip signature check in this case.
                        LOG_I("Tear happens but no signature");
                        skip_mem_check = true;
                    }
                    // Signature doesn't match. Inform user.
                    else if ((pkgBuf->signatureOverCommandsLen != prev_sign_buffer_len) ||
                             (memcmp(pkgBuf->pSignatureOverCommands,
                                  prev_sign_buffer,
                                  pkgBuf->signatureOverCommandsLen) != 0)) {
                        LOG_W("SEMS Lite signature not match!!!");
                        LOG_MAU8_W("Current package signature",
                            pkgBuf->pSignatureOverCommands,
                            pkgBuf->signatureOverCommandsLen);
                        LOG_MAU8_W("Expected signature", prev_sign_buffer, prev_sign_buffer_len);
                    }
                    else {
                        // It's tear script
                        skip_mem_check = true;
                    }
                }
                else {
                    LOG_E("SEMS Lite get signature failed!!!");
                    retval = kStatus_SEMS_Lite_ERR_General;
                    goto exit;
                }
            }
        }
        else {
            LOG_E("SEMS Lite check tear status failed!!!");
            retval = kStatus_SEMS_Lite_ERR_General;
            goto exit;
        }
    }

#ifndef SEMS_LITE_AGENT_SKIP_MEMORY_CHECK
    // Skip memory checking if it's re-run tear script (SIMW-2078)
    if (skip_mem_check == false) {
        /* Check if have enough NV and transient memory. */
        if (context->freePHeapCentralGap < pkgBuf->requiredFreeBytesNonVolatileMemory) {
            LOG_E("SEMS Lite requires %u bytes NV memory but only have %u bytes!!!",
                pkgBuf->requiredFreeBytesNonVolatileMemory,
                context->freePHeapCentralGap);
            retval = kStatus_SEMS_Lite_ERR_NotEnoughNVMemory;
            goto exit;
        }
        if (context->freeTransient < pkgBuf->requiredFreeBytesTransientMemory) {
            LOG_E("SEMS Lite requires %u bytes transient memory but only have %u bytes!!!",
                pkgBuf->requiredFreeBytesTransientMemory,
                context->freeTransient);
            retval = kStatus_SEMS_Lite_ERR_NotEnoughTransientMemory;
            goto exit;
        }

        LOG_I("Check Memory Requirement Passed.");
    }
#endif

    /* Check if meet version requirement */
    sss_stat = sems_lite_agent_verify_all_elf_version(context, pkgBuf, &elf_check_pass);
    ENSURE_OR_GO_EXIT(sss_stat == kStatus_SSS_Success);
    if (elf_check_pass == kStatus_SEMS_Lite_Version_ERR_MIN) {
        if (skip_mem_check == false) {
            LOG_E("SEMS Lite min previous version verification failed!!!");
            retval = kStatus_SEMS_Lite_ERR_MinPreviousVersion;
            goto exit;
        }
        else {
            LOG_I("SEMS Lite ignore min previous version violation");
        }
    }
    else if (elf_check_pass == kStatus_SEMS_Lite_Version_ERR_Downgrade) {
        LOG_E("Applet in SE newer. Can not downgrade!!!");
        retval = kStatus_SEMS_Lite_ERR_OlderVersion;
        goto exit;
    }
    else {
        LOG_I("Check Version Passed.");
    }

    sss_stat = sems_lite_check_AppletRecoveryStatus(context, &recoveryStatus);
    ENSURE_OR_GO_EXIT(sss_stat == kStatus_SSS_Success);
    if (recoveryStatus == sems_lite_recovery_started) {
        // If recovery started.
        context->recovery_executed = true;
    }
    else
        context->recovery_executed = false;

    context->status_word        = SEMS_LITE_AGENT_STATUS_WORD_INIT;
    context->skip_next_commands = false;

    keystore_context.sems_lite_agent_context = context;
    iot_agent_keystore_sems_lite_se05x_init(&keystore, SEMS_LITE_AGENT_KEYSTORE_ID, &keystore_context);

    retval = sems_lite_agent_register_keystore(&iot_agent_context, &keystore);
    ENSURE_OR_GO_EXIT(retval == kStatus_SEMS_Lite_Success);

    retval = sems_lite_agent_init_dispatcher(&dispatcher_context, &iot_agent_context, STREAM_TYPE_BUFFER_REQUESTS);
    ENSURE_OR_GO_EXIT(retval == kStatus_SEMS_Lite_Success);

    input_stream  = pb_istream_from_buffer(pkgBuf->pMulticastCommands, pkgBuf->multicastCommandsLen);
    output_stream = pb_ostream_from_buffer(response_buffer_memory, sizeof(response_buffer_memory));
    retval        = sems_lite_agent_dispatcher(&dispatcher_context, &input_stream, &output_stream);

    if (retval != kStatus_SEMS_Lite_Success) {
        if (context->status_word == SEMS_LITE_AGENT_STATUS_WORD_COM_FAILURE)
            retval = kStatus_SEMS_Lite_ERR_COM;
        else
            retval = kStatus_SEMS_Lite_ERR_General;

        goto exit;
    }

    /** Process status word and map to return code. */
    retval = sems_lite_agent_handle_status_word(context);

    ENSURE_OR_GO_EXIT(retval == kStatus_SEMS_Lite_Success);

    /** Check tear status before exit.
        *   Only do it when retval is success
        */
    if (sems_lite_check_Tear(context, &tearStatus) == kStatus_SSS_Success) {
        if (tearStatus == sems_lite_tear) {
            LOG_I("FN %s: Teardown happens", __FUNCTION__);
            retval = kStatus_SEMS_Lite_ERR_Fatal;
            goto exit;
        }
        else {
            retval = kStatus_SEMS_Lite_Success;
        }
    }
    else {
        LOG_E("SEMS Lite final check tear status failed!!!");
        retval = kStatus_SEMS_Lite_ERR_General;
        goto exit;
    }

    /* Read back signature and compared with expected one */
    if (pkgBuf->pSignatureOverCommands != NULL) {
        prev_sign_buffer_len = sizeof(prev_sign_buffer);
        // Get Last script signature
        if (sems_lite_get_SignatureofLastScript(context, prev_sign_buffer, &prev_sign_buffer_len) ==
            kStatus_SSS_Success) {
            if (prev_sign_buffer_len == 0) {
                LOG_E("SEMS Lite get null signature!!!");
                retval = kStatus_SEMS_Lite_ERR_General;
                goto exit;
            }

            // Signature doesn't match. Inform user.
            if ((pkgBuf->signatureOverCommandsLen != prev_sign_buffer_len) ||
                (memcmp(pkgBuf->pSignatureOverCommands, prev_sign_buffer, pkgBuf->signatureOverCommandsLen) != 0)) {
                LOG_I("SEMS Lite signature not match!!!");
                retval = kStatus_SEMS_Lite_ERR_Fatal;
                goto exit;
            }
        }
        else {
            LOG_E("SEMS Lite read back signature failed!!!");
            retval = kStatus_SEMS_Lite_ERR_General;
            goto exit;
        }
    }

exit:
    return retval;
}

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */
sss_status_t sems_lite_agent_init_context(sems_lite_agent_ctx_t *context, sss_session_t *boot_ctx)
{
    sss_status_t retval = kStatus_SSS_Fail;
    sss_se05x_session_t *pSE05x_Session;

    ENSURE_OR_GO_EXIT((context != NULL) && (boot_ctx != NULL));

    LOG_D("SEMS Lite Agent Version: %d.%d.%d",
        SEMS_LITE_API_VERSION_MAJOR,
        SEMS_LITE_API_VERSION_MINOR,
        SEMS_LITE_API_VERSION_PATCH);

    pSE05x_Session = (sss_se05x_session_t *)boot_ctx;

    context->pS05x_Ctx           = &pSE05x_Session->s_ctx;
    context->status_word         = SEMS_LITE_AGENT_STATUS_WORD_INIT;
    context->recovery_executed   = false;
    context->skip_next_commands  = false;
    context->session_opened      = false;
    context->freePHeapCentralGap = 0;
    context->freeTransient       = 0;
#ifdef SEMS_LITE_AGENT_CHANNEL_1
    context->n_logical_channel = SEMS_LITE_AGENT_CHANNEL_0;
#endif
    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sems_lite_agent_session_open(sems_lite_agent_ctx_t *context)
{
    sss_status_t status = kStatus_SSS_Success;
    U32 respstat;
#ifdef SEMS_LITE_AGENT_CHANNEL_1
    const uint8_t openCmd[] = {0x00, 0x70, 0x00, 0x00, 0x01};
    U16 openCmdLen          = sizeof(openCmd);
#endif

    /* clang-format off */
    const uint8_t selectCmd[] = {
#ifdef SEMS_LITE_AGENT_CHANNEL_1
        0x01, 0xA4, 0x04, 0x00,     0x10, 0xA0, 0x00, 0x00,
#else
        0x00, 0xA4, 0x04, 0x00,     0x10, 0xA0, 0x00, 0x00,
#endif
        0x03, 0x96, 0x54, 0x53,     0x00, 0x00, 0x00, 0x01,
        0x03, 0x30, 0x00, 0x00,     0x00, 0x00,
    };

    /* clang-format on */
    U16 selectCmdLen                  = sizeof(selectCmd);
    uint8_t resp[128]                 = {0x00};
    U32 respLen                       = sizeof(resp);
    sems_lite_available_mem_t memInfo = {0};

    ENSURE_OR_GO_EXIT(context != NULL);

    if (context->pS05x_Ctx == NULL) {
        LOG_W("Failed : Called Session Open without Session Init");
        return status;
    }

    /* Get free memory info from SE and store in context. */
    status = sems_lite_get_available_mem(context, (uint8_t *)&memInfo);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    context->freePHeapCentralGap = memInfo.freePHeapCentralGap;
    context->freeTransient       = memInfo.freeTransient;

#ifdef SEMS_LITE_AGENT_CHANNEL_1
    respstat = smCom_TransceiveRaw(context->pS05x_Ctx->conn_ctx, (uint8_t *)openCmd, openCmdLen, resp, &respLen);
    ENSURE_OR_GO_EXIT(respstat == SM_OK);
#endif
    respLen  = sizeof(resp);
    respstat = smCom_TransceiveRaw(context->pS05x_Ctx->conn_ctx, (uint8_t *)selectCmd, selectCmdLen, resp, &respLen);
    ENSURE_OR_GO_EXIT(respstat == SM_OK);

#ifdef SEMS_LITE_AGENT_CHANNEL_1
    context->n_logical_channel = SEMS_LITE_AGENT_CHANNEL_1;
#endif

    // SEMS Lite session is opened.
    context->session_opened = true;

    status = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t sems_lite_agent_session_close(sems_lite_agent_ctx_t *context)
{
    sss_status_t status = kStatus_SSS_Fail;
    U32 respstat;
#ifdef SEMS_LITE_AGENT_CHANNEL_1
    uint8_t closeCmd[] = {0x00, 0x70, 0x80, 0x01};
#else
    uint8_t closeCmd[] = {0x00, 0xA4, 0x04, 0x00, 0x00};
#endif
    U16 closeCmdLen       = sizeof(closeCmd);
    uint8_t closeResp[32] = {0x00};
    U32 closeRespLen      = sizeof(closeResp);

    ENSURE_OR_GO_EXIT(context != NULL);

    respstat =
        smCom_TransceiveRaw(context->pS05x_Ctx->conn_ctx, (uint8_t *)closeCmd, closeCmdLen, closeResp, &closeRespLen);
    ENSURE_OR_GO_EXIT(respstat == SM_OK);

    // SEMS Lite session is closed.
    context->session_opened = false;

#ifdef SEMS_LITE_AGENT_CHANNEL_1
    context->n_logical_channel = SEMS_LITE_AGENT_CHANNEL_0;
#endif
    status = kStatus_SSS_Success;

exit:
    return status;
}

#endif /* SSS_HAVE_SSS > 1 */
