/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/

#include "ax_reset.h"
#include "board.h"
#include "fsl_gpio.h"
#include <nxEnsure.h>
#include <nxLog_App.h>
#include "pin_mux.h"
#include "se_reset_config.h"
#include "sm_timer.h"
#include "fsl_puf.h"
#include "fsl_power.h"
#include <puf_inject_scp03.h>

#if (SSS_HAVE_HOSTCRYPTO_MBEDTLS)
#include "ksdk_mbedtls.h"
#endif

/*******************************************************************************
 * Defines
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/* Insert PUF keys into Index 0 */
static status_t puf_insert_scp03_keys(uint8_t *PROV_KEY_ENC, uint8_t *PROV_KEY_MAC, uint8_t *PROV_KEY_DEK);

/*******************************************************************************
 * Global variables
 ******************************************************************************/

/*******************************************************************************
 * Functions
 ******************************************************************************/
int main(void)
{
    status_t retval = kStatus_Fail;

    POWER_SetBodVbatLevel(kPOWER_BodVbatLevel1650mv, kPOWER_BodHystLevel50mv, false);

    CLOCK_AttachClk(BOARD_DEBUG_UART_CLK_ATTACH);

    /* attach 12 MHz clock to FLEXCOMM8 (I2C master) */
    CLOCK_AttachClk(kFRO12M_to_FLEXCOMM4);

    /* reset FLEXCOMM for I2C */
    RESET_PeripheralReset(kFC4_RST_SHIFT_RSTn);

    BOARD_InitPins();
    BOARD_BootClockFROHF96M();
    BOARD_InitDebugConsole();

#if (SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    CRYPTO_InitHardware();
#if defined(FSL_FEATURE_SOC_SHA_COUNT) && (FSL_FEATURE_SOC_SHA_COUNT > 0)
    CLOCK_EnableClock(kCLOCK_Sha0);
    RESET_PeripheralReset(kSHA_RST_SHIFT_RSTn);
#endif /* SHA */
#endif /* defined(MBEDTLS) */

    sm_initSleep();

    /* doc:start:old-scp03-keys */
    /** New key material
      * These will be the static platform SCP03 keys
      * which will be provisioned on the SE and in PUF.
      */
    uint8_t PROV_KEY_ENC[PUF_INTRINSIC_KEY_SIZE] = SSS_AUTH_KEY_ENC;
    uint8_t PROV_KEY_MAC[PUF_INTRINSIC_KEY_SIZE] = SSS_AUTH_KEY_MAC;
    uint8_t PROV_KEY_DEK[PUF_INTRINSIC_KEY_SIZE] = SSS_AUTH_KEY_DEK;
    /* doc:end:old-scp03-keys */

    /** Insert the new keyCodes into PUF Index 0 (HW keys index) */
    retval = puf_insert_scp03_keys(PROV_KEY_ENC, PROV_KEY_MAC, PROV_KEY_DEK);
    if (retval != kStatus_Success) {
        LOG_E("Failed to inject new keys into PUF");
    }

    while (1) {
        /* This point should never be reached */
    }
}

/* doc:start:puf-insert-scp03-keys */
static status_t puf_insert_scp03_keys(uint8_t *PROV_KEY_ENC, uint8_t *PROV_KEY_MAC, uint8_t *PROV_KEY_DEK)
{
    status_t result = kStatus_Fail;
    uint8_t activationCode[PUF_ACTIVATION_CODE_SIZE];

    srand(0xbabadeda);

    puf_config_t conf;
    PUF_GetDefaultConfig(&conf);
    PUF_Deinit(PUF, &conf);

    result = PUF_Init(PUF, &conf);
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);

    result = PUF_Enroll(PUF, activationCode, sizeof(activationCode));
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);
    LOG_MAU8_I("ActivationCode", activationCode, sizeof(activationCode));
    PUF_Deinit(PUF, &conf);

    result = PUF_Init(PUF, &conf);
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);

    result = PUF_Start(PUF, activationCode, PUF_ACTIVATION_CODE_SIZE);
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);

    result = PUF_SetUserKey(PUF,
        kPUF_KeyIndex_00,
        PROV_KEY_ENC,
        PUF_INTRINSIC_KEY_SIZE,
        keyCodeENC_01,
        PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);
    LOG_MAU8_I("KeyCode_ENC", keyCodeENC_01, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    result = PUF_SetUserKey(PUF,
        kPUF_KeyIndex_00,
        PROV_KEY_MAC,
        PUF_INTRINSIC_KEY_SIZE,
        keyCodeMAC_01,
        PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);
    LOG_MAU8_I("KeyCode_MAC", keyCodeMAC_01, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    result = PUF_SetUserKey(PUF,
        kPUF_KeyIndex_00,
        PROV_KEY_DEK,
        PUF_INTRINSIC_KEY_SIZE,
        keyCodeDEK_01,
        PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));
    ENSURE_OR_GO_CLEANUP(result == kStatus_Success);
    LOG_MAU8_I("KeyCode_DEK", keyCodeDEK_01, PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE));

cleanup:
    PUF_Deinit(PUF, &conf);
    return result;
}
/* doc:end:puf-insert-scp03-keys */
