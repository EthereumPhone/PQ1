/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* THIS IS THE MAIN CODE TO BE RUN FROM SECURE ZONE
 *
 */

#if (__ARM_FEATURE_CMSE & 1) == 0
#error "Need ARMv8-M security extensions"
#elif (__ARM_FEATURE_CMSE & 2) == 0
#error "Compile with --cmse"
#endif

#include <nxLog_App.h>

#include "arm_cmse.h"
#include "ax_reset.h"
#include "board.h"
#include "clock_config.h"
#include "ex_sss_boot.h"
#include "fsl_debug_console.h"
#include "fsl_device_registers.h"
#include "fsl_puf.h"
#include "ksdk_mbedtls.h"
#include "nxEnsure.h"
#include "pin_mux.h"
#include "sm_timer.h"
#include "tzm_config.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa_alt_se_driver.h"
#include "psa_alt_flash.h"

#define NON_SECURE_START 0x00070000

#define MAX_STRING_LENGTH 0x400

typedef void (*funcptr_ns)(void) __attribute__((cmse_nonsecure_call));

#if defined(__arm__)
size_t strnlen(const char *s, size_t maxLength)
{
    size_t length = 0;
    while ((length <= maxLength) && (*s)) {
        s++;
        length++;
    }
    return length;
}
#endif

__attribute__((cmse_nonsecure_entry)) void DbgConsole_Printf_NSE(char const *s)
{
    size_t string_length;
    /* Access to non-secure memory from secure world has to be properly validated */
    /* Check whether string is properly terminated */
    string_length = strnlen(s, MAX_STRING_LENGTH);
    if ((string_length == MAX_STRING_LENGTH) && (s[string_length] != '\0')) {
        PRINTF("String too long or invalid string termination!\r\n");
        abort();
    }

    /* Check whether string is located in non-secure memory */
    if (cmse_check_address_range((void *)s, string_length, CMSE_NONSECURE | CMSE_MPU_READ) == NULL) {
        PRINTF("String is not located in normal world!\r\n");
        abort();
    }
    PRINTF(s);
}

/* Session Open from driver->p_init API */
int main()
{
    funcptr_ns ResetHandler_ns;

    /* Init board hardware. */
    /* attach main clock divide to FLEXCOMM0 (debug console) */
    CLOCK_AttachClk(BOARD_DEBUG_UART_CLK_ATTACH);

    /* attach 12 MHz clock to FLEXCOMM8 (I2C master) */
    CLOCK_AttachClk(kFRO12M_to_FLEXCOMM4);

    /* reset FLEXCOMM for I2C */
    RESET_PeripheralReset(kFC4_RST_SHIFT_RSTn);

    CLOCK_EnableClock(kCLOCK_Gpio0);
    CLOCK_EnableClock(kCLOCK_Gpio1);

    BOARD_InitPins();
    BOARD_BootClockFROHF96M();
    BOARD_InitDebugConsole();

    PRINTF("Hello from secure world (simw)!\r\n");

#if defined(MBEDTLS)
    CRYPTO_InitHardware();
#if defined(FSL_FEATURE_SOC_SHA_COUNT) && (FSL_FEATURE_SOC_SHA_COUNT > 0)
    CLOCK_EnableClock(kCLOCK_Sha0);
    RESET_PeripheralReset(kSHA_RST_SHIFT_RSTn);
#endif /* SHA */
#endif /* defined(MBEDTLS) */

    sm_initSleep();

    puf_config_t conf;
    PUF_GetDefaultConfig(&conf);
    srand(0xbabadeda);

    if (kStatus_Success != PUF_Init(PUF, &conf)) {
        LOG_E("PUF_Init failed");
        goto exit;
    }

    if (PSA_SUCCESS != psa_alt_register_se_driver()) {
        PRINTF("FAILED TO REGISTER SE DRIVER");
        goto exit;
    }

#if EX_SSS_BOOT_DO_ERASE
    bool reset = true;
#else
    bool reset = false;
#endif

    /* doc:start:psa-erase-keystore */

    /* NOTE: To erase PSA Keystore contents, reset=true
     * If psa_flash_ks_init fails due to flash error,
     * erase PSA Keystore and try again  */
    if (!psa_flash_ks_init(reset)) {
        PRINTF("FAILED TO LOAD KEYSTORE");
        goto exit;
    }
    /* doc:end:psa-erase-keystore */

    /* Set non-secure main stack (MSP_NS) */
    __TZ_set_MSP_NS(*((uint32_t *)(NON_SECURE_START)));

    /* Set non-secure vector table */
    SCB_NS->VTOR = NON_SECURE_START;

    /* Get non-secure reset handler */
    ResetHandler_ns = (funcptr_ns)(*((uint32_t *)((NON_SECURE_START) + 4U)));

    /* Call non-secure application */
    PRINTF("Entering normal world.\r\n");
    /* Jump to normal world */
    ResetHandler_ns();

exit:
    while (1) {
        /* This point should never be reached */
    }
}
