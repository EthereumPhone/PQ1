/* Copyright 2019,2020,2025 NXP
 *
 * This software is owned or controlled by NXP and may only be used
 * strictly in accordance with the applicable license terms.  By expressly
 * accepting such terms or by downloading, installing, activating and/or
 * otherwise using the software, you are agreeing that you have read, and
 * that you agree to comply with and are bound by, such license terms.  If
 * you do not agree to be bound by the applicable license terms, then you
 * may not retain, install, activate or otherwise use the software.
 */


#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "usb_device_config.h"
#include "usb.h"
#include "usb_device.h"

#include "usb_device_class.h"
#include "usb_device_ccid.h"
#include "usb_device_dci.h"

#include "usb_device_ch9.h"
#include "usb_device_descriptor.h"

#include "emvl1_interface.h"
#include "smart_card.h"

#include "fsl_device_registers.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_debug_console.h"
#include "fsl_smartcard_s05x.h"
#include "emvl1_core.h"

#include "smCom.h"
#include <ax_reset.h>
#include "se05x_reset_apis.h"

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#if (defined(FSL_FEATURE_SOC_SYSMPU_COUNT) && (FSL_FEATURE_SOC_SYSMPU_COUNT > 0U))
#include "fsl_sysmpu.h"
#endif /* FSL_FEATURE_SOC_SYSMPU_COUNT */

#if defined(USB_DEVICE_CONFIG_EHCI) && (USB_DEVICE_CONFIG_EHCI > 0U)
#include "usb_phy.h"
#endif

#if (USB_DEVICE_CONFIG_USE_TASK < 1U)
#error USB_DEVICE_CONFIG_USE_TASK need to > 0U, Please change the MARCO USB_DEVICE_CONFIG_USE_TASK in file "usb_device_config.h".
#endif

#include "pin_mux.h"
#include <fsl_smartcard.h>
#include "ex_sss_boot.h"
#include <sm_timer.h>

#if (SSS_HAVE_HOSTCRYPTO_MBEDTLS) && (SSS_HAVE_MBEDTLS_2_X)
#include <ksdk_mbedtls.h>
#endif

// If you want to enable debug in this file.
//#define NX_LOG_ENABLE_APP_DEBUG 1

#include <nxLog_App.h>
#include <PlugAndTrust_Pkg_Ver.h>

extern smartcard_context_t g_SmartCardContext;

#if LOG_DEBUG_ENABLED
static const char *DEF_smartcard_control(smartcard_control_t control);
static const char *DEF_smartcard_interface_control(smartcard_interface_control_t control);
static const char *DEF_smartcard_direction(smartcard_direction_t direction);
#endif

uint32_t gWtxCnt;
static ex_sss_boot_ctx_t gsssCCIDBootCtx;
static void *g_conn_ctx = NULL;
SE05x_CCID_Base_t gse05x_ccid_base;

void USB_DeviceClockInit(void)
{
    SystemCoreClockUpdate();
    CLOCK_EnableUsbfs0Clock(kCLOCK_UsbSrcIrc48M, 48000000U);
}
void USB_DeviceIsrEnable(void)
{
    uint8_t irqNumber;

    uint8_t usbDeviceKhciIrq[] = USB_IRQS;
    irqNumber = usbDeviceKhciIrq[CONTROLLER_ID - kUSB_ControllerKhci0];

    /* Install isr, set priority, and enable IRQ. */
    NVIC_SetPriority((IRQn_Type)irqNumber, USB_DEVICE_INTERRUPT_PRIORITY);
    EnableIRQ((IRQn_Type)irqNumber);
}
#if USB_DEVICE_CONFIG_USE_TASK
void USB_DeviceTaskFn(void *deviceHandle)
{
    USB_DeviceKhciTaskFunction(deviceHandle);
}
#endif

/*!
 * @brief Fills in the configuration structure with default values.
 *
 * @param config The Smart card user configuration structure which contains configuration structure of type
 * smartcard_interface_config_t.
 * Function fill in members:
 *      clockToResetDelay = 42000,
 *      vcc = kSmartcardVoltageClassB3_3V,
 * with default values.
 */
void SMARTCARD_PHY_GetDefaultConfig(smartcard_interface_config_t *config)
{
    assert((NULL != config));
    LOG_D("P:GetDefaultConfig");

    /* Initializes the configure structure to zero. */
    memset(config, 0, sizeof(*config));

    /* EMV default values */
    config->clockToResetDelay = SMARTCARD_INIT_DELAY_CLOCK_CYCLES;
    config->vcc = kSMARTCARD_VoltageClassB3_3V;

    return;
}

/*!
 * @brief Initializes a Smart card interface instance.
 *
 * @param base The Smart card peripheral base address.
 * @param config The user configuration structure of type smartcard_interface_config_t. Call the
 *  function SMARTCARD_PHY_GetDefaultConfig() to fill the configuration structure.
 * @param srcClock_Hz Smart card clock generation module source clock.
 *
 * @retval kStatus_SMARTCARD_Success or kStatus_SMARTCARD_OtherError in case of error.
 */
status_t SMARTCARD_SE05x_Init(SE05x_CCID_Base_t *base, smartcard_interface_config_t const *context)
{
    status_t retVal;
    sm_initSleep();
#if (AX_EMBEDDED) && (SSS_HAVE_HOSTCRYPTO_MBEDTLS) && (SSS_HAVE_MBEDTLS_2_X)
    CRYPTO_InitHardware();
#endif

    retVal = kStatus_SMARTCARD_Success;

    return retVal;
}

/*!
 * @brief De-initializes a Smart card interface, stops the Smart card clock, and disables the VCC.
 *
 * @param base The Smart card peripheral module base address.
 * @param config The user configuration structure of type smartcard_interface_config_t.
 */
void SMARTCARD_PHY_Deinit(SE05x_CCID_Base_t *base, smartcard_interface_config_t const *config)
{
    LOG_D("P:Deinit");
    ex_sss_session_close((&gsssCCIDBootCtx));
    return;
}

/*!
 * @brief Activates the Smart card IC.
 *
 * @param base The Smart card peripheral module base address.
 * @param context A pointer to a Smart card driver context structure.
 * @param resetType type of reset to be performed, possible values
 *                       = kSmartcardColdReset, kSmartcardWarmReset
 *
 * @retval kStatus_SMARTCARD_Success or kStatus_SMARTCARD_OtherError in case of error.
 */
status_t SMARTCARD_PHY_Activate(SE05x_CCID_Base_t *base, smartcard_context_t *context, smartcard_reset_type_t resetType)
{
    LOG_D("P:Activate");
    context->cardParams.atrValid = false;
    sss_status_t status = kStatus_SSS_Fail;

#if SSS_HAVE_APPLET_SE05X_IOT
    gsssCCIDBootCtx.se05x_open_ctx.skip_select_applet = 1;
#endif
    status = ex_sss_boot_open((&gsssCCIDBootCtx), NULL);
#if SSS_HAVE_APPLET_SE05X_IOT
    sss_se05x_session_t * se05x_session = (sss_se05x_session_t *) &gsssCCIDBootCtx.session;
    pSe05xSession_t se05xSession;
    se05xSession = &se05x_session->s_ctx;
    g_conn_ctx = (void *) se05xSession->conn_ctx;
#endif
    LOG_D("P:Init status=%X", status);
    if (status == kStatus_SSS_Success) {
        context->cardParams.t1Indicated = 1;
        context->cardParams.present = 1;
        context->cardParams.active = 1;
        return kStatus_SMARTCARD_Success;
    }
    else
    {
        return kStatus_SMARTCARD_CardNotActivated;
    }
}

/*!
 * @brief De-activates the Smart card IC.
 *
 * @param base The Smart card peripheral module base address.
 * @param context A pointer to a Smart card driver context structure.
 *
 * @retval kStatus_SMARTCARD_Success or kStatus_SMARTCARD_OtherError in case of error.
 */
status_t SMARTCARD_PHY_Deactivate(SE05x_CCID_Base_t *base, smartcard_context_t *context)
{
    LOG_D("P:Deactivate");
    ex_sss_session_close((&gsssCCIDBootCtx));
    return kStatus_SMARTCARD_Success;
}

static void smartcard_se05x_SetTransferType(
    SE05x_CCID_Base_t *base, smartcard_context_t *context, smartcard_control_t control)
{
    LOG_D("S:SetTransferType %s", DEF_smartcard_control(control));
}

/*!
 * @brief Controls the Smart card interface IC.
 *
 * @param base The Smart card peripheral module base address.
 * @param context A pointer to a Smart card driver context structure.
 * @param control A interface command type.
 * @param param Integer value specific to control type
 *
 * @retval kStatus_SMARTCARD_Success or kStatus_SMARTCARD_OtherError in case of error.
 */
status_t SMARTCARD_PHY_Control(
    SE05x_CCID_Base_t *base, smartcard_context_t *context, smartcard_interface_control_t control, uint32_t param)
{
    LOG_D("P:Control %s=%d", DEF_smartcard_interface_control(control), param);

    if ((NULL == context)) {
        return kStatus_SMARTCARD_InvalidInput;
    }

    if (kSMARTCARD_InterfaceReadStatus == control) {
        switch (param) {
        case kSMARTCARD_EnableADT:
            /* Do nothing, ADT counter has been loaded and started after reset
             * and during starting TS delay counter only. This is because, once
             * TS counter has been triggered with RCV_EN down-up, we should not
             * trigger again after TS is received(to avoid missing next character to
             * TS. Rather, after TS is received, the ATR duration counter should just
             * be restarted w/o re-triggering the counter. */
            //context->cardParams.atrValid = 1;
            context->cardParams.present = 1;
            context->cardParams.t1Indicated = 1;
            context->cardParams.present = true;
            context->cardParams.active = false;
            context->cardParams.faulty = false;
            context->IFSD = 0xFE;
            context->cardParams.status = 1; //SMARTCARD_SE05X_STATUS_PRES;
            break;
        case kSMARTCARD_DisableADT:
            // base->CTRL &= ~EMVSIM_CTRL_RCV_EN_MASK;
            /* Stop ADT specific counter and it's interrupt to occur */
            // base->CLKCFG &= ~EMVSIM_CLKCFG_GPCNT1_CLK_SEL_MASK;
            // base->TX_STATUS = EMVSIM_TX_STATUS_GPCNT1_TO_MASK;
            // base->INT_MASK |= EMVSIM_INT_MASK_GPCNT1_IM_MASK;
            break;
        case kSMARTCARD_EnableGTV:
            /* Enable GTV specific interrupt */
            // base->INT_MASK &= ~EMVSIM_INT_MASK_BGT_ERR_IM_MASK;
            break;
        case kSMARTCARD_DisableGTV:
            /* Disable GTV specific interrupt */
            // base->INT_MASK |= EMVSIM_INT_MASK_BGT_ERR_IM_MASK;
            break;
        case kSMARTCARD_ResetWWT:
            /* Reset WWT Timer */
            // base->CTRL &= ~(EMVSIM_CTRL_CWT_EN_MASK | EMVSIM_CTRL_BWT_EN_MASK);
            // base->CTRL |= (EMVSIM_CTRL_CWT_EN_MASK | EMVSIM_CTRL_BWT_EN_MASK);
            break;
        case kSMARTCARD_EnableWWT:
            /* BGT must be masked */
            // base->INT_MASK |= EMVSIM_INT_MASK_BGT_ERR_IM_MASK;
            /* Enable WWT Timer interrupt to occur */
            // base->INT_MASK &= (~EMVSIM_INT_MASK_CWT_ERR_IM_MASK & ~EMVSIM_INT_MASK_BWT_ERR_IM_MASK);
            break;
        case kSMARTCARD_DisableWWT:
            /* Disable WWT Timer interrupt to occur */
            // base->INT_MASK |= (EMVSIM_INT_MASK_CWT_ERR_IM_MASK | EMVSIM_INT_MASK_BWT_ERR_IM_MASK);
            break;
        case kSMARTCARD_ResetCWT:
            /* Reset CWT Timer */
            // base->CTRL &= ~EMVSIM_CTRL_CWT_EN_MASK;
            // base->CTRL |= EMVSIM_CTRL_CWT_EN_MASK;
            break;
        case kSMARTCARD_EnableCWT:
            // base->CTRL |= EMVSIM_CTRL_CWT_EN_MASK;
            /* Enable CWT Timer interrupt to occur */
            // base->INT_MASK &= ~EMVSIM_INT_MASK_CWT_ERR_IM_MASK;
            break;
        case kSMARTCARD_DisableCWT:
            /* CWT counter is for receive mode only */
            // base->CTRL &= ~EMVSIM_CTRL_CWT_EN_MASK;
            /* Disable CWT Timer interrupt to occur */
            // base->INT_MASK |= EMVSIM_INT_MASK_CWT_ERR_IM_MASK;
            break;
        case kSMARTCARD_ResetBWT:
            /* Reset BWT Timer */
            // base->CTRL &= ~EMVSIM_CTRL_BWT_EN_MASK;
            // base->CTRL |= EMVSIM_CTRL_BWT_EN_MASK;
            break;
        case kSMARTCARD_EnableBWT:
            // base->CTRL |= EMVSIM_CTRL_BWT_EN_MASK;
            /* Enable BWT Timer interrupt to occur */
            // base->INT_MASK &= ~EMVSIM_INT_MASK_BWT_ERR_IM_MASK;
            break;
        case kSMARTCARD_DisableBWT:
            /* Disable BWT Timer interrupt to occur */
            // base->INT_MASK |= EMVSIM_INT_MASK_BWT_ERR_IM_MASK;
            break;
        case kSMARTCARD_EnableInitDetect:
            /* Clear all ISO7816 interrupt flags */
            // base->RX_STATUS = 0xFFFFFFFFu;
            /* Enable initial character detection : hardware method */
            context->transferState = kSMARTCARD_WaitingForTSState;
            /* Enable initial character detection */
            // base->CTRL |= EMVSIM_CTRL_ICM_MASK;
            // base->CTRL |= EMVSIM_CTRL_RCV_EN_MASK;
            break;
        case kSMARTCARD_EnableAnack:
            /* Enable NACK-on-error interrupt to occur */
            // base->CTRL |= EMVSIM_CTRL_ANACK_MASK;
            break;
        case kSMARTCARD_DisableAnack:
            /* Disable NACK-on-error interrupt to occur */
            // base->CTRL &= ~EMVSIM_CTRL_ANACK_MASK;
            break;
        case kSMARTCARD_ConfigureBaudrate:
            /* Set default baudrate/ETU time based on EMV parameters and card clock */
            // base->DIVISOR = ((context->cardParams.Fi / context->cardParams.currentD) & 0x1FFu);
            break;
        case kSMARTCARD_SetupATRMode:
            /* Set in default ATR mode */
            smartcard_se05x_SetTransferType(base, context, kSMARTCARD_SetupATRMode);
            break;
        case kSMARTCARD_SetupT0Mode:
            /* Set transport protocol type to T=0 */
            smartcard_se05x_SetTransferType(base, context, kSMARTCARD_SetupT0Mode);
            break;
        case kSMARTCARD_SetupT1Mode:
            /* Set transport protocol type to T=1 */
            smartcard_se05x_SetTransferType(base, context, kSMARTCARD_SetupT1Mode);
            break;
        case kSMARTCARD_EnableReceiverMode:
            /* Enable receiver mode and switch to receive direction */
            // base->CTRL |= EMVSIM_CTRL_RCV_EN_MASK;
            /* Set receiver threshold value to 1 */
            // base->RX_THD = ((base->RX_THD & ~EMVSIM_RX_THD_RDT_MASK) | 1);
            /* Enable RDT interrupt */
            // base->INT_MASK &= ~EMVSIM_INT_MASK_RDT_IM_MASK;
            break;
        case kSMARTCARD_DisableReceiverMode:
            /* Disable receiver */
            // base->CTRL &= ~EMVSIM_CTRL_RCV_EN_MASK;
            break;
        case kSMARTCARD_EnableTransmitterMode:
            /* Enable transmitter mode and switch to transmit direction */
            // base->CTRL |= EMVSIM_CTRL_XMT_EN_MASK;
            break;
        case kSMARTCARD_DisableTransmitterMode:
            /* Disable transmitter */
            // base->CTRL &= ~EMVSIM_CTRL_XMT_EN_MASK;
            break;
        case kSMARTCARD_ResetWaitTimeMultiplier:
            // base->CTRL &= ~EMVSIM_CTRL_BWT_EN_MASK;
            /* Reset Wait Timer Multiplier
             * EMV Formula : WTX x (11 + ((2^BWI + 1) x 960 x D)) */
//            temp32 = ((uint8_t)param) *
//                     (11u + (((1 << context->cardParams.BWI) + 1u) * 960u * context->cardParams.currentD));
#ifdef CARDSIM_EXTRADELAY_USED
//            temp32 += context->cardParams.currentD * 50;
#endif
            // base->BWT_VAL = temp32;
            /* Set flag to SMARTCARD context accordingly */
            //if (param > 1u) {
                context->wtxRequested = true;
            //}
            //else {
            //    context->wtxRequested = false;
            //}
            // base->CTRL |= EMVSIM_CTRL_BWT_EN_MASK;
            break;
        default:
            return kStatus_SMARTCARD_InvalidInput;
        }
    }

    return kStatus_USB_Success;
}

#define RET_STR(var, enum_prfx, enum_sfx)  \
    if ((var) == (enum_prfx##_##enum_sfx)) \
        return #enum_sfx;

#if defined(__CC_ARM) || (defined(__ARMCC_VERSION)) || defined(__GNUC__)
int main(void)
#else
void main(void)
#endif
{
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();

    USB_DeviceApplicationInit();
    LOG_I(PLUGANDTRUST_PROD_NAME_VER_FULL);
    g_SmartCardContext.base = (void *)&gse05x_ccid_base;

    axReset_HostConfigure();
    axReset_PowerUp(SE_RESET_LOGIC);

    while (1U) {
#if USB_DEVICE_CONFIG_USE_TASK
        USB_DeviceTaskFn(g_UsbDeviceCcidSmartCard.deviceHandle);
#endif
    }

}

status_t SMARTCARD_SE05x_TransferNonBlocking(
    SE05x_CCID_Base_t *base, smartcard_context_t *context, smartcard_xfer_t *xfer)
{
    LOG_D("S:XFer d=%s sz=%d", DEF_smartcard_direction(xfer->direction), xfer->size);
    if (xfer->direction == kSMARTCARD_Receive) {
        if (context->cardParams.atrValid == false) {
            // https://www.javacardos.com/tools/atr
            /* clang-format off */
            const unsigned char atrU8[] = {
                //0x85, 0x81, 0x21, 0x4D, 0x11, 0x22, 0x33, 0x44, 0x55, 0x79
                //0x3B,
                //0xD3, 0x22, 0x03, 0x91, 0x11, 0x31, 0x31, 0x55, 0x70, 0x67, 0x68, 0x58
                //0xD3, 0x44, 0x04, 0x91, 0x01, 0x31, 0x2E, 0x66, 0x70, 0x67, 0x68, 0x05

                // 3B D3 44 01 91 81 31 2E 82 70 67 68 64
                //  0xD3, 0x44, 0x01, 0x91, 0x81, 0x31, 0x2E, 0x82, 0x70, 0x67, 0x68, 0x64

                // 3B 93 12 91 81 31 FE 31 70 67 68 10
                  0x93, 0x12, 0x91, 0x81, 0x31, 0xFE, 0x31, 0x70, 0x67, 0x68, 0x10,

                // with t=0
                // 3B D3 12 01 C0 02 31 FE 32 70 67 68 80
                //   0xD3, 0x12, 0x01, 0xC0, 0x02, 0x31, 0xFE, 0x32, 0x70, 0x67, 0x68, 0x80,
            };
            /* clang-format on */

            context->xBuff = xfer->buff;
            memcpy(context->xBuff, atrU8, sizeof(atrU8));
            if (xfer->size < sizeof(atrU8)) {
                return kStatus_SMARTCARD_OtherError;
            }
            context->xSize = xfer->size - sizeof(atrU8);
            context->tType = kSMARTCARD_T1Transport;
            context->resetType = kSMARTCARD_WarmReset;
            return kStatus_SMARTCARD_Success;
        }
    }
    return kStatus_SMARTCARD_OtherError;
}

int32_t SMARTCARD_SE05x_GetTransferRemainingBytes(SE05x_CCID_Base_t *base, smartcard_context_t *context)
{
    LOG_D("S:GetTransferRemainingBytes");
    if (context->xIsBusy) {
        return -1; //context->xSize;
    }
    return 0;
}

status_t SMARTCARD_SE05x_Control(
    SE05x_CCID_Base_t *base, smartcard_context_t *context, smartcard_control_t control, uint32_t param)
{
    LOG_D("S:Control %s=%d", DEF_smartcard_control(control), param);
    return kStatus_SMARTCARD_Success;
}

void SysTick_Handler_APP_CB(void)
{
    if (g_SmartCardContext.xIsBusy ) {

        if (kSMARTCARD_WaitingForTSState == g_SmartCardContext.transferState) {
            g_SmartCardContext.xIsBusy = 0;
            g_SmartCardContext.transferState = kSMARTCARD_IdleState;

        }
        if (g_SmartCardContext.transferState == kSMARTCARD_TransmittingState) {
            if ((UINT32_MAX - 1) < gWtxCnt) {
                LOG_E("gWtxCnt will wrap");
                return;
            }
            gWtxCnt++;
            if (gWtxCnt > 4000)
            {
                usb_status_t status;
                gWtxCnt = 0;
                status = USB_DeviceSendWtxRequest();
                if (status != kStatus_USB_Success) {
                    LOG_E("Bulk In Wtx request failed");
                }
            }
        }
    }
}

const char gp_select_applet[] = {0x00, 0xA4, 0x04, 0x00};

uint8_t EMVL1_SendApduCommand(
    uint8_t *commandApdu, uint32_t commandApduLength, uint8_t *ResponseApdu, uint32_t *ResponseApduLength)
{
    U32 status = SW_OK;
    g_SmartCardContext.direction = kSMARTCARD_Transmit;
    g_SmartCardContext.transferState = kSMARTCARD_TransmittingState;
    g_SmartCardContext.xIsBusy = 1;
    if ((UINT_MAX - commandApduLength) < 9) {
        return kStatus_CCID_EMV_Error;
    }
    if (((commandApduLength + 9) % 64) == 0)
    {
        uint8_t index = 4;
        uint32_t LcVal = commandApdu[index++];
        uint32_t CmdLenLe = commandApduLength;
        if (LcVal == 0) {
            CmdLenLe = commandApduLength - 2; // Last 2 bytes are Le not counted in Lc
            LcVal = commandApdu[index++] & 0xFF;
            LcVal = LcVal << 8;
            LcVal |= commandApdu[index++] & 0xFF;
        }

        if (CmdLenLe < index) {
            return kStatus_CCID_EMV_Error;
        }
        if (LcVal != (CmdLenLe - index)) {
            /*
             * USB 64 byte boundary
             * ===================================
             * Remove one extra byte added at the end by the application
             */
            commandApduLength -= 1;
        }
    }
    status = smCom_TransceiveRaw(g_conn_ctx, commandApdu, commandApduLength, ResponseApdu, ResponseApduLength);
    gWtxCnt = 0;
    if (status == SW_OK && (*ResponseApduLength) >= 2) {
        g_SmartCardContext.xIsBusy = 0;
        g_SmartCardContext.direction = kSMARTCARD_Receive;
        g_SmartCardContext.transferState = kSMARTCARD_IdleState;
        g_SmartCardContext.xSize = *ResponseApduLength;
        return kStatus_CCID_EMV_Success;
    }
    else {
        return kStatus_CCID_EMV_Error;
    }
}

#if LOG_DEBUG_ENABLED

static const char *DEF_smartcard_direction(smartcard_direction_t direction)
{
    RET_STR(direction, kSMARTCARD, Receive);
    RET_STR(direction, kSMARTCARD, Transmit);
    return "unknown: smartcard_direction_t";
}

static const char *DEF_smartcard_control(smartcard_control_t control)
{
    RET_STR(control, kSMARTCARD, EnableADT);
    RET_STR(control, kSMARTCARD, DisableADT);
    RET_STR(control, kSMARTCARD, EnableGTV);
    RET_STR(control, kSMARTCARD, DisableGTV);
    RET_STR(control, kSMARTCARD, ResetWWT);
    RET_STR(control, kSMARTCARD, EnableWWT);
    RET_STR(control, kSMARTCARD, DisableWWT);
    RET_STR(control, kSMARTCARD, ResetCWT);
    RET_STR(control, kSMARTCARD, EnableCWT);
    RET_STR(control, kSMARTCARD, DisableCWT);
    RET_STR(control, kSMARTCARD, ResetBWT);
    RET_STR(control, kSMARTCARD, EnableBWT);
    RET_STR(control, kSMARTCARD, DisableBWT);
    RET_STR(control, kSMARTCARD, EnableInitDetect);
    RET_STR(control, kSMARTCARD, EnableAnack);
    RET_STR(control, kSMARTCARD, DisableAnack);
    RET_STR(control, kSMARTCARD, ConfigureBaudrate);
    RET_STR(control, kSMARTCARD, SetupATRMode);
    RET_STR(control, kSMARTCARD, SetupT0Mode);
    RET_STR(control, kSMARTCARD, SetupT1Mode);
    RET_STR(control, kSMARTCARD, EnableReceiverMode);
    RET_STR(control, kSMARTCARD, DisableReceiverMode);
    RET_STR(control, kSMARTCARD, EnableTransmitterMode);
    RET_STR(control, kSMARTCARD, DisableTransmitterMode);
    RET_STR(control, kSMARTCARD, ResetWaitTimeMultiplier);
    return "unknown: smartcard_control_t";
}

static const char *DEF_smartcard_interface_control(smartcard_interface_control_t control)
{
    RET_STR(control, kSMARTCARD, InterfaceSetVcc);
    RET_STR(control, kSMARTCARD, InterfaceSetClockToResetDelay);
    RET_STR(control, kSMARTCARD, InterfaceReadStatus);

    return "unknown: smartcard_interface_control_t";
}
#endif
