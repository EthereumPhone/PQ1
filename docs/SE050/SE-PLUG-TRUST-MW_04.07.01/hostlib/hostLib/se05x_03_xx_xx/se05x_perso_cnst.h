/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file */

#ifndef se05x_perso_CNST_H
#define se05x_perso_CNST_H

/** Constants for the Config Applet */

/* + Machine Generated */

#define se05x_perso_APPLET_AID                                                                   \
    {                                                                                            \
        0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x40, 0x00, 0x00 \
    }

typedef enum
{

#if 0
    /** 1-byte value: SAK in case of incomplete UID, only used for CIU. */
    kSE05x_Cfg_TCL_SAK_COMPLETE_P1P2 = 0x8002,

    /** 1-byte value: L3 Activation Control Parameter. */
    kSE05x_Cfg_TCL_L3_ACTIVATION_CONTROL_P1P2 = 0x8003,

    /** Byte array (max 5 bytes): TCL Interface Bytes used for CIU. This
     * are the first bytes in the ATS before the Historical
     * Characters. (T0, [TA1], [TB1], [TC1]) The first byte defines the
     * length (excl. length byte). The IF-Length and T0 are always
     * present, all others are optional and depend on the content of
     * T0. */
    kSE05x_Cfg_TCL_ATS_IF_P1P2 = 0x8004,
#endif

    /** Length(1 bytes): Defines the actually used length of the
    historical characters in configuration item TCL_ATS_HISTCHARS */
    kSE05x_Cfg_TCL_ATS_CURRENT_HISTLEN_CHARS_P1P2 = 0x8005,

    /** Byte array (max 20 bytes): Historical characters used for T=CL. */
    kSE05x_Cfg_TCL_ATS_HISTCHARS_P1P2 = 0x8006,

#if 0
    /** 1-byte value: ATQA MSB byte only used for CIU */
    kSE05x_Cfg_TCL_ATQA_MSB_P1P2 = 0x8007,

    /** 1-byte value: ATQA LSB byte only used for CIU */
    kSE05x_Cfg_TCL_ATQA_LSB_P1P2 = 0x8008,
#endif

    /** Length(1 bytes): */
    kSE05x_Cfg_7816_ATR_COLD_HIST_LEN_CHARS_P1P2 = 0x8009,

    /** Byte array (max 15 bytes): Histchars for Cold Reset ISO7816 protocol  */
    kSE05x_Cfg_7816_ATR_COLD_HIST_P1P2 = 0x800A,

    /** Length(1 bytes): */
    kSE05x_Cfg_7816_ATR_WARM_HIST_LEN_CHARS_P1P2 = 0x800B,

    /** Byte array (max 15 bytes): Histchars for Warm Reset ISO7816 protocol.  */
    kSE05x_Cfg_7816_ATR_WARM_HIST_P1P2 = 0x800C,

    /** 1-byte value: I2C slave address of product. */
    kSE05x_Cfg_I2C_SLAVE_ADDRESS_P1P2 = 0x800D,

    /** 1-byte value: Bitmask to configure the I2C protocol Each bit
     * of the bitmask switches the feature: */
    kSE05x_Cfg_I2C_PARAMS_P1P2 = 0x800E,

    /** Byte array: ATR definition for I2C interface. See Table 15. */
    kSE05x_Cfg_ATR_I2C_IF_BYTES_P1P2 = 0x800F,

#if 0
    /** 2-byte value: values to initialize system timer A: b15 RFU */
    kSE05x_Cfg_OS_TIMER_INIT_P1P2 = 0x8010,

    /** 2-byte value: The counter timer interval between interrupts. The
     * resolution is defined by the chosen divider value in
     * NXCONF_OS_TIMER_INIT. */
    kSE05x_Cfg_OS_TIMER_UPDATE_THRESHOLD_P1P2 = 0x8011,

    /** 2-byte value: Bit mask stating GlobalPlatform features supported,
    see table 17. */
    kSE05x_Cfg_GP_CONFIG_P1P2 = 0x8012,

    /** 1-byte value: Configuration to enable/disable periodic Static
     * Wear Leveling - 0x00: Periodic static wear leveling is
     * disabled. Enable periodic Static Wear Leveling: */
    kSE05x_Cfg_PRSWL_ENABLED_P1P2 = 0x8013,
#endif

    /** 1-byte value: 0x00 = FIPS disabled; 0x01 = FIPS enabled. */
    kSE05x_Cfg_FIPS_MODE_ENABLED_P1P2 = 0x8014,

    /** Byte array: ATR definition for I2C interface. See Table 15. */
    kSE05x_Cfg_CIP_I2C_IF_BYTES_P1P2 = 0x8015,

    /** Byte array (max 25 bytes): ATR Historical Character definition
     * for I2C interface. See Table 16. */
    kSE05x_Cfg_ATR_CIP_I2C_HIST_CHARS_P1P2 = 0x8016,

    /** Byte array: AID of module to be deleted . */
    kSE05x_Cfg_DELETE_OS_MODULE_P1P2 = 0x8017,
} SE05x_Cfg_P1P2_t;

/*
 * Convention for I2C Params APIs
 *
 * - (1)   Read full 8 bits from Applet
 * - (2.a) If it's a 'set' value |= set_bit
 * - (2.b) If it's a 'msk' value &= set_bit
 * - (4)   Set value to Applet
 *
 */

/*
 *-bit 0 : Slave clock stretching(0 = clock stretching disabled, 1 = clock
 *   stretching enabled)
 */
#define SE05X_PERSO_I2C_PARAMS_SET_CLK_STRCH_ENABLED (1u << 0)
#define SE05X_PERSO_I2C_PARAMS_MSK_CLK_STRCH_DISABLED (~(SE05X_PERSO_I2C_PARAMS_SET_CLK_STRCH_ENABLED))
/*
 * -bit 1 : Enable power saving mode after sending End of APDU Session
 *          response(0 = power save mode disabled, 1 = power save mode enabled)
 */
#define SE05X_PERSO_I2C_PARAMS_SET_PWR_SAVE_ENABLED (1u << 1)
#define SE05X_PERSO_I2C_PARAMS_MSK_PWR_SAVE_DISABLED (~(SE05X_PERSO_I2C_PARAMS_SET_PWR_SAVE_ENABLED))

/*
 * -bit 2 : Select flavour of T1I2C protocol(0 = NXP flavour, 1 = GP flavour)
 */
#define SE05X_PERSO_I2C_PARAMS_SET_I2C_GP (1u << 2)
#define SE05X_PERSO_I2C_PARAMS_MSK_I2C_UM (~(SE05X_PERSO_I2C_PARAMS_SET_I2C_GP))
/*
 * -bit 3 : Select the T1I2C protocol communication mode(0 = Semi Non -
 *          Blocking Communication, 1 = Blocking Communication)
 */
#define SE05X_PERSO_I2C_PARAMS_SET_I2C_SEMI_BLOCKING (1u << 3)
#define SE05X_PERSO_I2C_PARAMS_MSK_I2C_NON_BLOCKING (~(SE05X_PERSO_I2C_PARAMS_SET_I2C_SEMI_BLOCKING))

/*
 * -bit 4 :
 * Select the protocol detection mode:
 * 0: Auto protocol detection: Either NXP legacy UM11225 protocol
 * or GP v1.0 protocol can be used (Bit2 is obsolete).
 * 1: Manual mode: Use the protocol, which is set with Bit2.
 */
#define SE05X_PERSO_I2C_PARAMS_SET_PROTO_SEL_MANUAL (1u << 4)
#define SE05X_PERSO_I2C_PARAMS_MSK_PROTO_DETECT_AUTO (~(SE05X_PERSO_I2C_PARAMS_SET_PROTO_SEL_MANUAL))

#endif /* se05x_perso_CNST_h */
