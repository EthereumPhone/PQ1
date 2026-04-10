/* Copyright 2020 NXP

 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "se05x_perso_api_int.h"
#include "smCom.h"
#include "global_platf.h"
#include "nxEnsure.h"
#include "string.h"

#ifdef FLOW_VERBOSE
#define NX_LOG_ENABLE_HOSTLIB_DEBUG 1
#endif
// #define NX_LOG_ENABLE_HOSTLIB_DEBUG 1

#include "nxLog_hostLib.h"

#ifdef __cplusplus
}
#endif

static smStatus_t Se05x_API_Perso_SetAU8(
    pSe05xSession_t session_ctx, SE05x_Cfg_P1P2_t p1p2, const uint8_t *in_buf, size_t in_bufLen, const char *szP1P2);
static smStatus_t Se05x_API_Perso_GetAU8(
    pSe05xSession_t session_ctx, SE05x_Cfg_P1P2_t p1p2, uint8_t *out_buf, size_t *out_bufLen, const char *szP1P2);
static smStatus_t Se05x_API_Perso_SetU8(
    pSe05xSession_t session_ctx, SE05x_Cfg_P1P2_t p1p2, uint8_t in_value, const char *szP1P2);
static smStatus_t Se05x_API_Perso_GetU8(
    pSe05xSession_t session_ctx, SE05x_Cfg_P1P2_t p1p2, uint8_t *out_value, const char *szP1P2);
//static smStatus_t Se05x_API_Perso_SetU16(
//    pSe05xSession_t session_ctx, SE05x_Cfg_P1P2_t p1p2, uint16_t in_value, const char *szP1P2);
//static smStatus_t Se05x_API_Perso_GetU16(
//    pSe05xSession_t session_ctx, SE05x_Cfg_P1P2_t p1p2, uint16_t *out_value, const char *szP1P2);

smStatus_t Se05x_API_Perso_SelectApplet(pSe05xSession_t session_ctx)
{
    const uint8_t SE05x_PersoApplet[] = se05x_perso_APPLET_AID;
    uint8_t rsp[100]                  = {0};
    U16 rspLen                        = sizeof(rsp);
    U16 status = GP_Select(session_ctx->conn_ctx, SE05x_PersoApplet, sizeof(SE05x_PersoApplet), rsp, &rspLen);
    return (smStatus_t)status;
}

#define SE05X_API_PERSO_AU8_CREATE_BODY_SET(P1P2) \
    return Se05x_API_Perso_SetAU8(session_ctx, kSE05x_Cfg_##P1P2##_P1P2, in_buf, in_bufLen, #P1P2)

#define SE05X_API_PERSO_AU8_CREATE_BODY_GET(P1P2) \
    return Se05x_API_Perso_GetAU8(session_ctx, kSE05x_Cfg_##P1P2##_P1P2, out_buf, out_bufLen, #P1P2)

#define SE05X_API_PERSO_U8_CREATE_BODY_SET(P1P2) \
    return Se05x_API_Perso_SetU8(session_ctx, kSE05x_Cfg_##P1P2##_P1P2, in_value, #P1P2)

#define SE05X_API_PERSO_U8_CREATE_BODY_GET(P1P2) \
    return Se05x_API_Perso_GetU8(session_ctx, kSE05x_Cfg_##P1P2##_P1P2, out_value, #P1P2)

#define SE05X_API_PERSO_U16_CREATE_BODY_SET(P1P2) \
    return Se05x_API_Perso_SetU16(session_ctx, kSE05x_Cfg_##P1P2##_P1P2, in_value, #P1P2)

#define SE05X_API_PERSO_U16_CREATE_BODY_GET(P1P2) \
    return Se05x_API_Perso_GetU16(session_ctx, kSE05x_Cfg_##P1P2##_P1P2, out_value, #P1P2)

#define SE05X_API_PERSO_U8_CREATE_API_BODY(P1P2)  \
    SE05X_API_PERSO_U8_CREATE_API_SET(P1P2)       \
    {                                             \
        SE05X_API_PERSO_U8_CREATE_BODY_SET(P1P2); \
    }                                             \
    SE05X_API_PERSO_U8_CREATE_API_GET(P1P2)       \
    {                                             \
        SE05X_API_PERSO_U8_CREATE_BODY_GET(P1P2); \
    }

#define SE05X_API_PERSO_U16_CREATE_API_BODY(P1P2)  \
    SE05X_API_PERSO_U16_CREATE_API_SET(P1P2)       \
    {                                              \
        SE05X_API_PERSO_U16_CREATE_BODY_SET(P1P2); \
    }                                              \
    SE05X_API_PERSO_U16_CREATE_API_GET(P1P2)       \
    {                                              \
        SE05X_API_PERSO_U16_CREATE_BODY_GET(P1P2); \
    }

#define SE05X_API_PERSO_AU8_CREATE_API_BODY(P1P2)  \
    SE05X_API_PERSO_AU8_CREATE_API_SET(P1P2)       \
    {                                              \
        SE05X_API_PERSO_AU8_CREATE_BODY_SET(P1P2); \
    }                                              \
    SE05X_API_PERSO_AU8_CREATE_API_GET(P1P2)       \
    {                                              \
        SE05X_API_PERSO_AU8_CREATE_BODY_GET(P1P2); \
    }

/* clang-format off */

#if 0
SE05X_API_PERSO_U8_CREATE_API_BODY(TCL_SAK_COMPLETE);
SE05X_API_PERSO_U8_CREATE_API_BODY(TCL_L3_ACTIVATION_CONTROL);
#endif
SE05X_API_PERSO_U8_CREATE_API_BODY(TCL_ATS_CURRENT_HISTLEN_CHARS);
#if 0
SE05X_API_PERSO_U8_CREATE_API_BODY(TCL_ATQA_MSB);
SE05X_API_PERSO_U8_CREATE_API_BODY(TCL_ATQA_LSB);
#endif
SE05X_API_PERSO_U8_CREATE_API_BODY(7816_ATR_COLD_HIST_LEN_CHARS);
SE05X_API_PERSO_U8_CREATE_API_BODY(7816_ATR_WARM_HIST_LEN_CHARS);
SE05X_API_PERSO_U8_CREATE_API_BODY(I2C_SLAVE_ADDRESS);
SE05X_API_PERSO_U8_CREATE_API_BODY(I2C_PARAMS);
#if 0
SE05X_API_PERSO_U8_CREATE_API_BODY(PRSWL_ENABLED);
#endif
SE05X_API_PERSO_U8_CREATE_API_BODY(FIPS_MODE_ENABLED);

#if 0
#define kSE05x_Cfg_TCL_ATS_IF_CHARS_P1P2 kSE05x_Cfg_TCL_ATS_IF_P1P2
SE05X_API_PERSO_U8_CREATE_API_BODY(TCL_ATS_IF_CHARS);

SE05X_API_PERSO_U16_CREATE_API_BODY(OS_TIMER_INIT);
SE05X_API_PERSO_U16_CREATE_API_BODY(OS_TIMER_UPDATE_THRESHOLD);
SE05X_API_PERSO_U16_CREATE_API_BODY(GP_CONFIG);

SE05X_API_PERSO_AU8_CREATE_API_BODY(TCL_ATS_IF);
#endif
SE05X_API_PERSO_AU8_CREATE_API_BODY(TCL_ATS_HISTCHARS);
SE05X_API_PERSO_AU8_CREATE_API_BODY(7816_ATR_COLD_HIST);
SE05X_API_PERSO_AU8_CREATE_API_BODY(7816_ATR_WARM_HIST);
SE05X_API_PERSO_AU8_CREATE_API_BODY(ATR_I2C_IF_BYTES);
SE05X_API_PERSO_AU8_CREATE_API_BODY(CIP_I2C_IF_BYTES);
SE05X_API_PERSO_AU8_CREATE_API_BODY(ATR_CIP_I2C_HIST_CHARS);
SE05X_API_PERSO_AU8_CREATE_API_BODY(DELETE_OS_MODULE);

/* clang-format on */

#ifndef MIN
#define MIN(X, Y) (X < Y ? X : Y)
#endif

static smStatus_t Se05x_API_Perso_GetAU8(
    pSe05xSession_t session_ctx, SE05x_Cfg_P1P2_t p1p2, uint8_t *out_buf, size_t *out_bufLen, const char *szP1P2)
{
    AX_UNUSED_ARG(*szP1P2);
    smStatus_t status    = SM_NOT_OK;
    uint8_t cmd_frame[7] = {
        /* i=0 */ 0x80,
        /* i=1 */ SE05X_PERSO_INS_READ, // read
        /* i=2 */ 0,                    // P1 - Added later
        /* i=3 */ 0,                    // P2 - Added later
        /* i=4 */ 0x01,                 // Lc
        /* i=5 */ 0x00,                 // MAX Expected Len.  Added later
        /* i=6 */ 0x00,
    };
    uint8_t full_rsp[2 + 1 + 255] = {0};
    U32 full_rspLen               = sizeof(full_rsp);
    const uint8_t u8P1            = 0xFF & (p1p2 >> 8);
    const uint8_t u8P2            = 0xFF & (p1p2);
    ENSURE_OR_GO_CLEANUP(out_bufLen != NULL);
    ENSURE_OR_GO_CLEANUP(out_buf != NULL);
    ENSURE_OR_GO_CLEANUP(*out_bufLen > 0);
    ENSURE_OR_GO_CLEANUP(*out_bufLen <= 255);

    cmd_frame[2] = u8P1;
    cmd_frame[3] = u8P2;
    cmd_frame[5] = sizeof(full_rsp) - 3; // (uint8_t)*out_bufLen;

    LOG_D("Reading %s", szP1P2);
    status = smCom_TransceiveRaw(session_ctx->conn_ctx, cmd_frame, sizeof(cmd_frame), full_rsp, &full_rspLen);
    ENSURE_OR_GO_CLEANUP(SM_OK == status);
    status = SM_NOT_OK;
    ENSURE_OR_GO_CLEANUP(full_rspLen >= (2 + 1));
    ENSURE_OR_GO_CLEANUP(full_rsp[0] == u8P1);
    ENSURE_OR_GO_CLEANUP(full_rsp[1] == u8P2);
    //ENSURE_OR_GO_CLEANUP((*out_bufLen) >= full_rsp[2]);
    //ENSURE_OR_GO_CLEANUP((*out_bufLen) >= (full_rspLen - 3 - 2));
    memcpy(out_buf, &full_rsp[3], MIN(full_rspLen - 3 - 2, *out_bufLen));
    *out_bufLen = MIN(full_rspLen - 3 - 2, *out_bufLen);
    status      = SM_OK;
cleanup:
    return status;
}

static smStatus_t Se05x_API_Perso_GetU8(
    pSe05xSession_t session_ctx, SE05x_Cfg_P1P2_t p1p2, uint8_t *out_value, const char *szP1P2)
{
    size_t rxBufLen = 1;
    return Se05x_API_Perso_GetAU8(session_ctx, p1p2, out_value, &rxBufLen, szP1P2);
}

#if 0
static smStatus_t Se05x_API_Perso_GetU16(
    pSe05xSession_t session_ctx, SE05x_Cfg_P1P2_t p1p2, uint16_t *out_value, const char *szP1P2)
{
    size_t rxBufLen = 2;
    uint8_t out_u8[2];
    smStatus_t status = Se05x_API_Perso_GetAU8(session_ctx, p1p2, out_u8, &rxBufLen, szP1P2);
    if (SM_OK == status) {
        *out_value = out_u8[0];
        *out_value <<= 8;
        *out_value |= out_u8[1];
    }
    return status;
}
#endif

static smStatus_t Se05x_API_Perso_SetAU8(
    pSe05xSession_t session_ctx, SE05x_Cfg_P1P2_t p1p2, const uint8_t *in_buf, size_t in_bufLen, const char *szP1P2)
{
    AX_UNUSED_ARG(*szP1P2);
    smStatus_t status          = SM_NOT_OK;
    uint8_t cmd_frame[5 + 255] = {
        /* i=0 */ 0x80,
        /* i=1 */ SE05X_PERSO_INS_WRITE, // read
        /* i=2 */ 0,                     // P1 - Added later
        /* i=3 */ 0,                     // P2 - Added later
        /* i=4 */ 0x00,                  // Lc = To be added later
        /* i=5 */                        // Buffer Added later
    };
    U16 cmd_frameLen;
    ;
    uint8_t full_rsp[2 + 1 + 255] = {0};
    U32 full_rspLen               = sizeof(full_rsp);
    const uint8_t u8P1            = 0xFF & (p1p2 >> 8);
    const uint8_t u8P2            = 0xFF & (p1p2);
    ENSURE_OR_GO_CLEANUP(in_bufLen > 0);
    ENSURE_OR_GO_CLEANUP(in_bufLen <= 255);
    ENSURE_OR_GO_CLEANUP(in_buf != NULL);

    cmd_frame[2] = u8P1;
    cmd_frame[3] = u8P2;
    cmd_frame[4] = (uint8_t)in_bufLen;
    cmd_frameLen = 4 + 1 + (uint8_t)in_bufLen;
    memcpy(&cmd_frame[5], in_buf, in_bufLen);
    LOG_D("Writing %s", szP1P2);
    status = (smStatus_t)smCom_TransceiveRaw(session_ctx->conn_ctx, cmd_frame, cmd_frameLen, full_rsp, &full_rspLen);
    ENSURE_OR_GO_CLEANUP(SM_OK == status);
    ENSURE_OR_GO_CLEANUP(full_rspLen == 2);
    uint16_t rv;
    rv = full_rsp[0];
    rv <<= 8;
    rv |= full_rsp[1];
    status = (smStatus_t)rv;

cleanup:
    return status;
}

static smStatus_t Se05x_API_Perso_SetU8(
    pSe05xSession_t session_ctx, SE05x_Cfg_P1P2_t p1p2, uint8_t in_value, const char *szP1P2)
{
    return Se05x_API_Perso_SetAU8(session_ctx, p1p2, &in_value, 1, szP1P2);
}

#if 0
static smStatus_t Se05x_API_Perso_SetU16(
    pSe05xSession_t session_ctx, SE05x_Cfg_P1P2_t p1p2, uint16_t in_value, const char *szP1P2)
{
    uint8_t v[2];
    v[0] = (uint8_t)(in_value >> 8 * 1);
    v[1] = (uint8_t)(in_value >> 8 * 0);
    return Se05x_API_Perso_SetAU8(session_ctx, p1p2, v, 2, szP1P2);
}
#endif
