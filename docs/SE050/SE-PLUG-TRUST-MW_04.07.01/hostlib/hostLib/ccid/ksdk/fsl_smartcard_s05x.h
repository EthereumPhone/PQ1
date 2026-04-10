/* Copyright 2019 NXP
 *
 * This software is owned or controlled by NXP and may only be used
 * strictly in accordance with the applicable license terms.  By expressly
 * accepting such terms or by downloading, installing, activating and/or
 * otherwise using the software, you are agreeing that you have read, and
 * that you agree to comply with and are bound by, such license terms.  If
 * you do not agree to be bound by the applicable license terms, then you
 * may not retain, install, activate or otherwise use the software.
 */

#ifndef HOSTLIB_HOSTLIB_CCID_KSDK_FSL_SMARTCARD_S05X_H_
#define HOSTLIB_HOSTLIB_CCID_KSDK_FSL_SMARTCARD_S05X_H_

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

// If enabling ISO7816_CARD_SUPPORT
// #define ISO7816_CARD_SUPPORT 1

#include "fsl_smartcard.h"

typedef struct {
	void * emptyCtx;
} SE05x_CCID_Base_t;

/*!
 * @brief This function disables the UART interrupts, disables the transmitter and receiver, and
 * flushes the FIFOs (for modules that support FIFOs) and gates UART clock in SIM.
 *
 * @param base The UART peripheral base address.
 */
void SMARTCARD_SE05x_Deinit(SE05x_CCID_Base_t * base);

/*!
 * @brief Returns whether the previous UART transfer has finished.
 *
 * When performing an async transfer, call this function to ascertain the context of the
 * current transfer: in progress (or busy) or complete (success). If the
 * transfer is still in progress, the user can obtain the number of words that have not been transferred
 * by reading xSize of smart card context structure.
 *
 * @param base The UART peripheral base address.
 * @param context A pointer to a Smart card driver context structure.
 *
 * @return The number of bytes not transferred.
 */
int32_t SMARTCARD_SE05x_GetTransferRemainingBytes(SE05x_CCID_Base_t * base, smartcard_context_t *context);

/*!
 * @brief Terminates an asynchronous UART transfer early.
 *
 * During an async UART transfer, the user can terminate the transfer early
 * if the transfer is still in progress.
 *
 * @param base The UART peripheral base address.
 * @param context A pointer to a Smart card driver context structure.
 *
 * @retval kStatus_SMARTCARD_Success The transfer abort was successful.
 * @retval kStatus_SMARTCARD_NoTransmitInProgress No transmission is currently in progress.
 */
status_t SMARTCARD_SE05x_AbortTransfer(SE05x_CCID_Base_t * base, smartcard_context_t *context);

/*!
 * @brief Transfers data using interrupts.
 *
 * A non-blocking (also known as asynchronous) function means that the function returns
 * immediately after initiating the transfer function. The application has to get the
 * transfer status to see when the transfer is complete. In other words, after calling non-blocking
 * (asynchronous) transfer function, the application must get the transfer status to check if transmit
 * is completed or not.
 *
 * @param base The UART peripheral base address.
 * @param context A pointer to a Smart card driver context structure.
 * @param xfer A pointer to Smart card transfer structure where the linked buffers and sizes are stored.
 *
 * @return An error code or kStatus_SMARTCARD_Success.
 */
status_t SMARTCARD_SE05x_TransferNonBlocking(SE05x_CCID_Base_t * base, smartcard_context_t *context, smartcard_xfer_t *xfer);



/*!
 * @brief Controls the UART module per different user requests.
 *
 * @param base The UART peripheral base address.
 * @param context A pointer to a smart card driver context structure.
 * @param control Smart card command type.
 * @param param Integer value specific to a control command.
 *
 * return An kStatus_SMARTCARD_OtherError in case of error
 * return kStatus_SMARTCARD_Success in success
 */
status_t SMARTCARD_SE05x_Control(SE05x_CCID_Base_t * base,
                                smartcard_context_t *context,
                                smartcard_control_t control,
                                uint32_t param);


status_t SMARTCARD_SE05x_Init(SE05x_CCID_Base_t * base, smartcard_interface_config_t const *context);

#endif /* HOSTLIB_HOSTLIB_CCID_KSDK_FSL_SMARTCARD_S05X_H_ */
