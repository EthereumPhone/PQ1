/*
 * Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file */

#ifndef se05x_perso_API_H
#define se05x_perso_API_H

#include "se05x_tlv.h"

smStatus_t Se05x_API_Perso_SelectApplet(pSe05xSession_t session_ctx);

#define SE05X_API_PERSO_U8_CREATE_API_SET(P1P2) \
    smStatus_t Se05x_API_Perso_Set_##P1P2(pSe05xSession_t session_ctx, uint8_t in_value)

#define SE05X_API_PERSO_U8_CREATE_API_GET(P1P2) \
    smStatus_t Se05x_API_Perso_Get_##P1P2(pSe05xSession_t session_ctx, uint8_t *out_value)

#define SE05X_API_PERSO_U16_CREATE_API_SET(P1P2) \
    smStatus_t Se05x_API_Perso_Set_##P1P2(pSe05xSession_t session_ctx, uint16_t in_value)

#define SE05X_API_PERSO_U16_CREATE_API_GET(P1P2) \
    smStatus_t Se05x_API_Perso_Get_##P1P2(pSe05xSession_t session_ctx, uint16_t *out_value)

#define SE05X_API_PERSO_AU8_CREATE_API_SET(P1P2) \
    smStatus_t Se05x_API_Perso_Set_##P1P2(pSe05xSession_t session_ctx, const uint8_t *in_buf, size_t in_bufLen)

#define SE05X_API_PERSO_AU8_CREATE_API_GET(P1P2) \
    smStatus_t Se05x_API_Perso_Get_##P1P2(pSe05xSession_t session_ctx, uint8_t *out_buf, size_t *out_bufLen)

/** Deletable module com/nxp/id/jcop/iot_extended
 *
 * ID = D276000085304A434F504D4F440B
 *
 * Extension to Elliptic Curve Cryptography. */
#define SE05X_API_PERSO_MOD_IOT_EXTENDED                                                    \
    {                                                                                       \
        0xD2, 0x76, 0x00, 0x00, 0x85, 0x30, 0x4A, 0x43, 0x4F, 0x50, 0x4D, 0x4F, 0x44, 0x0B, \
    }

/** Deletable module com/nxp/id/jcop/iot_base
 *
 * ID = D276000085304A434F504D4F440A
 *
 * Collection of crypto algorithms often used in IoT devices. */
#define SE05X_API_PERSO_MOD_IOT_BASE                                                        \
    {                                                                                       \
        0xD2, 0x76, 0x00, 0x00, 0x85, 0x30, 0x4A, 0x43, 0x4F, 0x50, 0x4D, 0x4F, 0x44, 0x0A, \
    }

/** Deletable module com/nxp/id/jcopx/egovaccelerators
 *
 * ID = D276000085304A434F506E
 *
 * Secure Messaging Accelerators for eGovernment applications and modular arithmetic math API. */
#define SE05X_API_PERSO_MODX_EGOVACCELERATORS                             \
    {                                                                     \
        0xD2, 0x76, 0x00, 0x00, 0x85, 0x30, 0x4A, 0x43, 0x4F, 0x50, 0x6E, \
    }

/** Deletable module com/nxp/id/jcop/rsakeygen
 *
 * ID = D276000085304A434F504D4F4400
 *
 * On chip generation of RSA keys. */
#define SE05X_API_PERSO_MOD_RSAKEYGEN                                                       \
    {                                                                                       \
        0xD2, 0x76, 0x00, 0x00, 0x85, 0x30, 0x4A, 0x43, 0x4F, 0x50, 0x4D, 0x4F, 0x44, 0x00, \
    }
/**
 * Get value of TCL_ATS_CURRENT_HISTLEN_CHARS
 *
 * Length(1 bytes): Defines the actually used length of the historical
 * characters in configuration item TCL_ATS_HISTCHARS
 */
smStatus_t Se05x_API_Perso_Get_TCL_ATS_CURRENT_HISTLEN_CHARS(pSe05xSession_t session_ctx, uint8_t *out_value);

/**
 * Configuration of TCL_ATS_CURRENT_HISTLEN_CHARS
 *
 * Length(1 bytes): Defines the actually used length of the historical
 * characters in configuration item TCL_ATS_HISTCHARS
 */
smStatus_t Se05x_API_Perso_Set_TCL_ATS_CURRENT_HISTLEN_CHARS(pSe05xSession_t session_ctx, uint8_t in_value);

/**
 * Get value of TCL_ATS_HISTCHARS
 *
 * Byte array (max 20 bytes): Historical characters used for T=CL.
 */
smStatus_t Se05x_API_Perso_Get_TCL_ATS_HISTCHARS(pSe05xSession_t session_ctx, uint8_t *out_buf, size_t *out_bufLen);

/**
 * Configuration of TCL_ATS_HISTCHARS
 *
 * Byte array (max 20 bytes): Historical characters used for T=CL.
 */
smStatus_t Se05x_API_Perso_Set_TCL_ATS_HISTCHARS(pSe05xSession_t session_ctx, const uint8_t *in_buf, size_t in_bufLen);

/**
 * Get value of 7816_ATR_COLD_HIST_LEN_CHARS
 * Length(1 bytes):
 *
 *
 * - Histchar length for Cold Reset ISO7816 protocol.
 */
smStatus_t Se05x_API_Perso_Get_7816_ATR_COLD_HIST_LEN_CHARS(pSe05xSession_t session_ctx, uint8_t *out_value);

/**
 * Configuration of 7816_ATR_COLD_HIST_LEN_CHARS
 * Length(1 bytes):
 *
 *
 * - Histchar length for Cold Reset ISO7816 protocol.
 */
smStatus_t Se05x_API_Perso_Set_7816_ATR_COLD_HIST_LEN_CHARS(pSe05xSession_t session_ctx, uint8_t in_value);

/**
 * Get value of 7816_ATR_COLD_HIST
 *
 * Byte array (max 15 bytes): Histchars for Cold Reset ISO7816 protocol
 */
smStatus_t Se05x_API_Perso_Get_7816_ATR_COLD_HIST(pSe05xSession_t session_ctx, uint8_t *out_buf, size_t *out_bufLen);

/**
 * Configuration of 7816_ATR_COLD_HIST
 *
 * Byte array (max 15 bytes): Histchars for Cold Reset ISO7816 protocol
 */
smStatus_t Se05x_API_Perso_Set_7816_ATR_COLD_HIST(pSe05xSession_t session_ctx, const uint8_t *in_buf, size_t in_bufLen);

/**
 * Get value of 7816_ATR_WARM_HIST_LEN_CHARS
 * Length(1 bytes):
 *
 *
 * - Histchar length for Warm Reset ISO7816 protocol
 */
smStatus_t Se05x_API_Perso_Get_7816_ATR_WARM_HIST_LEN_CHARS(pSe05xSession_t session_ctx, uint8_t *out_value);

/**
 * Configuration of 7816_ATR_WARM_HIST_LEN_CHARS
 * Length(1 bytes):
 *
 *
 * - Histchar length for Warm Reset ISO7816 protocol
 */
smStatus_t Se05x_API_Perso_Set_7816_ATR_WARM_HIST_LEN_CHARS(pSe05xSession_t session_ctx, uint8_t in_value);

/**
 * Get value of 7816_ATR_WARM_HIST
 *
 * Byte array (max 15 bytes): Histchars for Warm Reset ISO7816 protocol.
 */
smStatus_t Se05x_API_Perso_Get_7816_ATR_WARM_HIST(pSe05xSession_t session_ctx, uint8_t *out_buf, size_t *out_bufLen);

/**
 * Configuration of 7816_ATR_WARM_HIST
 *
 * Byte array (max 15 bytes): Histchars for Warm Reset ISO7816 protocol.
 */
smStatus_t Se05x_API_Perso_Set_7816_ATR_WARM_HIST(pSe05xSession_t session_ctx, const uint8_t *in_buf, size_t in_bufLen);

/**
 * Get value of I2C_SLAVE_ADDRESS
 *
 * 1-byte value: I2C slave address of product.
 */
smStatus_t Se05x_API_Perso_Get_I2C_SLAVE_ADDRESS(pSe05xSession_t session_ctx, uint8_t *out_value);

/**
 * Configuration of I2C_SLAVE_ADDRESS
 *
 * 1-byte value: I2C slave address of product.
 */
smStatus_t Se05x_API_Perso_Set_I2C_SLAVE_ADDRESS(pSe05xSession_t session_ctx, uint8_t in_value);

/**
 * Get value of I2C_PARAMS
 * 1-byte value: Bitmask to configure the I2C protocol Each bit of the bitmask switches the feature:
 *
 *
 * - 0 = Off, feature disabled
 *
 * - 1 = On, feature enabled
 *
 * - bit 0 : Slave clock stretching (0=clock stretching disabled, 1=clock
 *   stretching enabled)
 *
 * - bit 1 : Enable power saving mode after sending End of APDU Session
 *   response (0=power save mode disabled, 1=power save mode enabled)
 *
 * - bit 2 : Select flavour of T1I2C protocol (0=NXP flavour, 1=GP flavour)
 *
 * - bit 3 : Select the T1I2C protocol communication mode (0=Semi Non-
 *   Blocking Communication, 1=Blocking Communication)
 *
 * - bit 7-4: Interface detection delay time during start up (multiplied by
 *   100 us)
 */
smStatus_t Se05x_API_Perso_Get_I2C_PARAMS(pSe05xSession_t session_ctx, uint8_t *out_value);

/**
 * Configuration of I2C_PARAMS
 * 1-byte value: Bitmask to configure the I2C protocol Each bit of the bitmask switches the feature:
 *
 *
 * - 0 = Off, feature disabled
 *
 * - 1 = On, feature enabled
 *
 * - bit 0 : Slave clock stretching (0=clock stretching disabled, 1=clock
 *   stretching enabled)
 *
 * - bit 1 : Enable power saving mode after sending End of APDU Session
 *   response (0=power save mode disabled, 1=power save mode enabled)
 *
 * - bit 2 : Select flavour of T1I2C protocol (0=NXP flavour, 1=GP flavour)
 *
 * - bit 3 : Select the T1I2C protocol communication mode (0=Semi Non-
 *   Blocking Communication, 1=Blocking Communication)
 *
 * - bit 7-4: Interface detection delay time during start up (multiplied by
 *   100 us)
 */
smStatus_t Se05x_API_Perso_Set_I2C_PARAMS(pSe05xSession_t session_ctx, uint8_t in_value);

/**
 * Get value of ATR_I2C_IF_BYTES
 *
 * Byte array: ATR definition for I2C interface.
 */
smStatus_t Se05x_API_Perso_Get_ATR_I2C_IF_BYTES(pSe05xSession_t session_ctx, uint8_t *out_buf, size_t *out_bufLen);

/**
 * Configuration of ATR_I2C_IF_BYTES
 *
 * Byte array: ATR definition for I2C interface.
 */
smStatus_t Se05x_API_Perso_Set_ATR_I2C_IF_BYTES(pSe05xSession_t session_ctx, const uint8_t *in_buf, size_t in_bufLen);

/**
 * Get value of PRSWL_ENABLED
 * 1-byte value: Configuration to enable/disable periodic Static Wear Leveling
 *
 *
 * - 0x00: Periodic static wear leveling is disabled. Enable periodic
 *   Static Wear Leveling:
 *
 * - Bit 0...6: a counter of APDUs after which the static wearlevelling is
 *   triggered. if 0, static wearlevelling is disabled and will only be
 *   executed during startup. Any other value (range 1 ... 127) will count
 *   the incoming APDUs and trigger the wear levelling when this counter is
 *   reached
 *
 * - Bit 7: steers time dependent behavior when set to 1, Static
 *   Wearlevelling will also happen every 3.5 hours (about) when the active
 *   interface is T1I2C. It will not have any effect on TCL or CT
 *   interface.
 */
smStatus_t Se05x_API_Perso_Get_PRSWL_ENABLED(pSe05xSession_t session_ctx, uint8_t *out_value);

/**
 * Configuration of PRSWL_ENABLED
 * 1-byte value: Configuration to enable/disable periodic Static Wear Leveling
 *
 *
 * - 0x00: Periodic static wear leveling is disabled. Enable periodic
 *   Static Wear Leveling:
 *
 * - Bit 0...6: a counter of APDUs after which the static wearlevelling is
 *   triggered. if 0, static wearlevelling is disabled and will only be
 *   executed during startup. Any other value (range 1 ... 127) will count
 *   the incoming APDUs and trigger the wear levelling when this counter is
 *   reached
 *
 * - Bit 7: steers time dependent behavior when set to 1, Static
 *   Wearlevelling will also happen every 3.5 hours (about) when the active
 *   interface is T1I2C. It will not have any effect on TCL or CT
 *   interface.
 */
smStatus_t Se05x_API_Perso_Set_PRSWL_ENABLED(pSe05xSession_t session_ctx, uint8_t in_value);

/**
 * Get value of FIPS_MODE_ENABLED
 *
 * 1-byte value: 0x00 = FIPS disabled; 0x01 = FIPS enabled.
 */
smStatus_t Se05x_API_Perso_Get_FIPS_MODE_ENABLED(pSe05xSession_t session_ctx, uint8_t *out_value);

/**
 * Get value of CIP_I2C_IF_BYTES
 *
 * Byte array: ATR definition for I2C interface.
 */
smStatus_t Se05x_API_Perso_Get_CIP_I2C_IF_BYTES(pSe05xSession_t session_ctx, uint8_t *out_buf, size_t *out_bufLen);

/**
 * Configuration of CIP_I2C_IF_BYTES
 *
 * Byte array: ATR definition for I2C interface.
 */
smStatus_t Se05x_API_Perso_Set_CIP_I2C_IF_BYTES(pSe05xSession_t session_ctx, const uint8_t *in_buf, size_t in_bufLen);

/**
 * Get value of ATR_CIP_I2C_HIST_CHARS
 *
 * Byte array (max 25 bytes): ATR Historical Character definition for I2C
 * interface.
 */
smStatus_t Se05x_API_Perso_Get_ATR_CIP_I2C_HIST_CHARS(
    pSe05xSession_t session_ctx, uint8_t *out_buf, size_t *out_bufLen);

/**
 * Configuration of ATR_CIP_I2C_HIST_CHARS
 *
 * Byte array (max 25 bytes): ATR Historical Character definition for I2C
 * interface.
 */
smStatus_t Se05x_API_Perso_Set_ATR_CIP_I2C_HIST_CHARS(
    pSe05xSession_t session_ctx, const uint8_t *in_buf, size_t in_bufLen);

/**
 * Configuration of DELETE_OS_MODULE
 *
 * Byte array: AID of module to be deleted .
 */
smStatus_t Se05x_API_Perso_Set_DELETE_OS_MODULE(pSe05xSession_t session_ctx, const uint8_t *in_buf, size_t in_bufLen);

smStatus_t Se05x_API_Perso_Set_FIPS_MODE_ENABLED(pSe05xSession_t session_ctx, uint8_t in_value);
smStatus_t Se05x_API_Perso_Get_DELETE_OS_MODULE(pSe05xSession_t session_ctx, uint8_t *out_buf, size_t *out_bufLen);
#endif /* se05x_perso_API_h */
