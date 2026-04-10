/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2018, 2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "usb.h"
#include "usb_device_config.h"

#include "usb_device.h"

#include "fsl_device_registers.h"

#if ((defined(USB_DEVICE_CONFIG_DWC3)) && (USB_DEVICE_CONFIG_DWC3 > 0U))

#include "usb_device_dci.h"

#include "usb_device_dwc3.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
static usb_status_t USB_DeviceDwc3EndpointPrimeTrb(usb_device_dwc3_state_struct_t *dwc3State,
                                                   uint8_t endpointAddress,
                                                   uint8_t *buffer,
                                                   uint32_t length,
                                                   uint32_t frame,
                                                   uint8_t trb_control);
static void USB_DeviceDwc3SetDefaultState(usb_device_dwc3_state_struct_t *dwc3State);
static usb_status_t USB_DeviceDwc3EndpointInit(usb_device_dwc3_state_struct_t *dwc3State,
                                               usb_device_endpoint_init_struct_t *epInit);
static usb_status_t USB_DeviceDwc3EndpointDeinit(usb_device_dwc3_state_struct_t *dwc3State, uint8_t ep);
static usb_status_t USB_DeviceDwc3EndpointStall(usb_device_dwc3_state_struct_t *dwc3State, uint8_t ep);
static usb_status_t USB_DeviceDwc3EndpointUnstall(usb_device_dwc3_state_struct_t *dwc3State, uint8_t ep);
static usb_status_t USB_DeviceDwc3EndpointSpecificCommand(usb_device_dwc3_state_struct_t *dwc3State,
                                                          usb_device_dwc3_ep_specific_command_struct_t *command);
extern usb_status_t USB_DeviceNotificationTrigger(void *handle, void *msg);

/*******************************************************************************
 * Variables
 ******************************************************************************/

/* Apply for QH buffer, 16-byte alignment */
USB_RAM_ADDRESS_ALIGNMENT(16)
static usb_device_dwc3_trb_struct_t s_UsbDeviceDwc3Trb[USB_DEVICE_CONFIG_DWC3][USB_DEVICE_CONFIG_ENDPOINTS * 2];
USB_RAM_ADDRESS_ALIGNMENT(8)
static uint8_t s_UsbDeviceDwc3EventBuffer[USB_DEVICE_CONFIG_DWC3][USB_DEVICE_CONFIG_DWC3_EVENT_COUNT]
                                         [USB_DEVICE_DWC3_EVENT_BUFFER_COUNT * USB_DEVICE_DWC3_EVENT_BUFFER_SIZE];
USB_RAM_ADDRESS_ALIGNMENT(4) static uint8_t s_UsbDeviceDwc3SetupBuffer[USB_DEVICE_CONFIG_DWC3][USB_SETUP_PACKET_SIZE];
USB_RAM_ADDRESS_ALIGNMENT(4)
static uint8_t s_UsbDeviceDwc3ScratchpadBuffer[USB_DEVICE_CONFIG_DWC3][USB_DEVICE_CONFIG_DWC3_SCRATCHPAD_BUFFER_SIZE];
static uint8_t s_UsbDeviceDwc3EpBuffer[USB_DEVICE_CONFIG_DWC3][USB_DEVICE_CONFIG_ENDPOINTS * 1024 - 512];
/* Apply for dwc3 device state structure */
static usb_device_dwc3_state_struct_t g_UsbDeviceDwc3Sate[USB_DEVICE_CONFIG_DWC3];

/*******************************************************************************
 * Code
 ******************************************************************************/

static usb_status_t USB_DeviceDwc3EndpointPrimeTrb(usb_device_dwc3_state_struct_t *dwc3State,
                                                   uint8_t endpointAddress,
                                                   uint8_t *buffer,
                                                   uint32_t length,
                                                   uint32_t frame,
                                                   uint8_t trb_control)
{
    usb_device_dwc3_ep_specific_command_struct_t command;
    uint32_t primedLength = length;
    usb_status_t status;
    uint8_t endpoint  = (endpointAddress & USB_ENDPOINT_NUMBER_MASK);
    uint8_t direction = (endpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) >>
                        USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT;
    uint8_t index = (endpoint << 1) | direction;
    uint32_t currentframe;
    OSA_SR_ALLOC();

    if (dwc3State->endpointState[index].stateUnion.stateBitField.transferring)
    {
        return kStatus_USB_Error;
    }

    if ((dwc3State->endpointState[index].stateUnion.stateBitField.transferPending) &&
        ((buffer != dwc3State->endpointState[index].transferBuffer) ||
         (length != dwc3State->endpointState[index].transferLength)))
    {
        return kStatus_USB_Busy;
    }

    /*
        if (dwc3State->endpointState[index].stateUnion.stateBitField.stalled)
        {
            return 1;
        }
    */

    dwc3State->endpointState[index].stateUnion.stateBitField.need2Copy = 0U;

    if ((!direction) && ((endpoint) || ((!endpoint) && (USB_TRB_TRBCTL_CONTROL_DATA == trb_control))))
    {
        primedLength = ((primedLength) / dwc3State->endpointState[index].stateUnion.stateBitField.maxPacketSize) *
                       dwc3State->endpointState[index].stateUnion.stateBitField.maxPacketSize;
        if (!primedLength)
        {
            buffer       = dwc3State->endpointBuffer[endpoint];
            primedLength = dwc3State->endpointState[index].stateUnion.stateBitField.maxPacketSize;
            dwc3State->endpointState[index].stateUnion.stateBitField.need2Copy = 1U;
        }
    }

    dwc3State->endpointState[index].trb->BPTRH   = (uint32_t)(((uint64_t)buffer) >> 32);
    dwc3State->endpointState[index].trb->BPTRL   = (uint32_t)((uint64_t)buffer);
    dwc3State->endpointState[index].trb->status  = 0U;
    dwc3State->endpointState[index].trb->BUFSIZE = primedLength;
    dwc3State->endpointState[index].trb->control = 0U;
    dwc3State->endpointState[index].trb->LST     = 1U;
    dwc3State->endpointState[index].trb->TRBCTL  = trb_control;
    dwc3State->endpointState[index].trb->IOC     = 1U;
    dwc3State->endpointState[index].trb->SID_SOF = 0U;

    if (USB_ENDPOINT_ISOCHRONOUS == dwc3State->endpointState[index].stateUnion.stateBitField.type)
    {
        dwc3State->endpointState[index].trb->ISP_IMI = 1U;
        dwc3State->endpointState[index].trb->CSP     = 1U;
        dwc3State->endpointState[index].trb->SID_SOF = 0U;
        dwc3State->endpointState[index].trb->LST     = 0U;
        if (!dwc3State->endpointState[index].transferDone)
        {
            dwc3State->endpointState[index].trb->TRBCTL = USB_TRB_TRBCTL_CONTROL_ISO_FIRST;
        }
        else
        {
            dwc3State->endpointState[index].trb->TRBCTL = USB_TRB_TRBCTL_CONTROL_ISO;
        }
        if (0U == frame)
        {
            frame = (USB_DSTS & USB_DSTS_SOFFN_MASK) >> USB_DSTS_SOFFN_SHIFT;
            frame += dwc3State->endpointState[index].interval;
            frame = (frame / dwc3State->endpointState[index].interval) * dwc3State->endpointState[index].interval;
        }
        else
        {
            frame        = frame + dwc3State->endpointState[index].interval;
            currentframe = (USB_DSTS & USB_DSTS_SOFFN_MASK) >> USB_DSTS_SOFFN_SHIFT;
            if (frame <= currentframe)
            {
                frame = (currentframe / dwc3State->endpointState[index].interval + 1) *
                        dwc3State->endpointState[index].interval;
            }
        }
    }

    if (dwc3State->endpointState[index].stateUnion.stateBitField.streamCapable)
    {
        dwc3State->endpointState[index].trb->SID_SOF = 0U;
    }
    dwc3State->endpointState[index].trb->HWO = 1U;

    /*
    dwc3State->endpointState[index].transferBuffer = buffer;
    dwc3State->endpointState[index].transferLength = length;
    */
    dwc3State->endpointState[index].transferPrimedLength = primedLength;

    command.commandParmeter.parameter0 = (uint32_t)(((uint64_t)dwc3State->endpointState[index].trb) >> 32);
    command.commandParmeter.parameter1 = (uint32_t)((uint64_t)dwc3State->endpointState[index].trb);
    command.commandParmeter.parameter2 = 0U;
    command.commandParmeter.index      = index;

    command.commandParmeter.commandCode = ((frame) << 16) | USB_DEPCMD_CMDTYP_START_TRANSFER;

    /* Enter critical */
    OSA_ENTER_CRITICAL();
    status = USB_DeviceDwc3EndpointSpecificCommand(dwc3State, &command);

    if (kStatus_USB_Success != status)
    {
        if (USB_ENDPOINT_ISOCHRONOUS == dwc3State->endpointState[index].stateUnion.stateBitField.type)
        {
            dwc3State->endpointState[index].stateUnion.stateBitField.resourceIndexNumber =
                (USB_DEPCMD(index) & USB_DEPCMD_COMMANDPARAM_MASK) >> USB_DEPCMD_COMMANDPARAM_SHIFT;
            command.commandParmeter.parameter0 = 0U;
            command.commandParmeter.parameter1 = 0U;
            command.commandParmeter.parameter2 = 0U;

            command.commandParmeter.commandCode =
                USB_DEPCMD_CMDTYP_END_TRANSFER | USB_DEPCMD_HIPRI_FORCERM_MASK |
                USB_DEPCMD_COMMANDPARAM(dwc3State->endpointState[index].stateUnion.stateBitField.resourceIndexNumber);
            USB_DeviceDwc3EndpointSpecificCommand(dwc3State, &command);
        }
        dwc3State->endpointState[index].stateUnion.stateBitField.resourceIndexNumber = 0U;
        dwc3State->endpointState[index].stateUnion.stateBitField.transferPending     = 1U;
    }
    else
    {
        dwc3State->endpointState[index].stateUnion.stateBitField.resourceIndexNumber =
            (USB_DEPCMD(index) & USB_DEPCMD_COMMANDPARAM_MASK) >> USB_DEPCMD_COMMANDPARAM_SHIFT;
        dwc3State->endpointState[index].stateUnion.stateBitField.transferring    = 1U;
        dwc3State->endpointState[index].stateUnion.stateBitField.transferPending = 0U;
    }
    OSA_EXIT_CRITICAL();
    return kStatus_USB_Success;
}

/*!
 * @brief Set device controller state to default state.
 *
 * The function is used to set device controller state to default state.
 * The function will be called when USB_DeviceDwc3Init called or the control type kUSB_DeviceControlGetEndpointStatus
 * received in USB_DeviceDwc3Control.
 *
 * @param dwc3State       Pointer of the device XHCI state structure.
 *
 */
static void USB_DeviceDwc3SetDefaultState(usb_device_dwc3_state_struct_t *dwc3State)
{
    usb_device_endpoint_init_struct_t epOutInit = {
        dwc3State->endpointState[0].stateUnion.stateBitField.maxPacketSize,
        0U,
        USB_ENDPOINT_CONTROL,
        0U,
    };
    usb_device_endpoint_init_struct_t epInInit = {
        dwc3State->endpointState[1].stateUnion.stateBitField.maxPacketSize,
        0x80U,
        USB_ENDPOINT_CONTROL,
        0U,
    };

    USB_DeviceDwc3EndpointInit(dwc3State, &epOutInit);
    USB_DeviceDwc3EndpointInit(dwc3State, &epInInit);
}

static usb_status_t USB_DeviceDwc3EndpointSpecificCommand(usb_device_dwc3_state_struct_t *dwc3State,
                                                          usb_device_dwc3_ep_specific_command_struct_t *command)
{
    if (!command)
    {
        return kStatus_USB_Error;
    }

    USB_DEPCMDPAR0(command->commandParmeter.index) = command->commandParmeter.parameter0;
    USB_DEPCMDPAR1(command->commandParmeter.index) = command->commandParmeter.parameter1;
    USB_DEPCMDPAR2(command->commandParmeter.index) = command->commandParmeter.parameter2;

    USB_DEPCMD(command->commandParmeter.index) = command->commandParmeter.commandCode | USB_DEPCMD_CMDACT_MASK;

    while (USB_DEPCMD(command->commandParmeter.index) & USB_DEPCMD_CMDACT_MASK)
    {
    }

    if (USB_DEPCMD(command->commandParmeter.index) & USB_DEPCMD_CMDSTATUS_MASK)
    {
        return kStatus_USB_Busy;
    }
    return kStatus_USB_Success;
}

static void USB_DeviceDwc3EndpointPrimeTrbForSetup(usb_device_dwc3_state_struct_t *dwc3State)
{
    dwc3State->endpointState[0].transferDone = 0U;
    dwc3State->endpointState[0].transferBuffer =
        (uint8_t *)&s_UsbDeviceDwc3SetupBuffer[dwc3State->controllerId - kUSB_ControllerDwc30][0];
    dwc3State->endpointState[0].transferLength = USB_SETUP_PACKET_SIZE;

    if (kStatus_USB_Success ==
        USB_DeviceDwc3EndpointPrimeTrb(
            dwc3State, 0x00U, (uint8_t *)&s_UsbDeviceDwc3SetupBuffer[dwc3State->controllerId - kUSB_ControllerDwc30][0],
            USB_SETUP_PACKET_SIZE, 0U, USB_TRB_TRBCTL_CONTROL_SETUP))
    {
        dwc3State->controlPipeStage    = USB_DEVICE_DWC3_CONTROL_PIPE_SETUP_STAGE;
        dwc3State->controlPipeWithData = 0;
    }
}
/*!
 * @brief Initialize a specified endpoint.
 *
 * The function is used to initialize a specified endpoint.
 *
 * @param dwc3State       Pointer of the device XHCI state structure.
 * @param epInit          The endpoint initialization structure pointer.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceDwc3EndpointInit(usb_device_dwc3_state_struct_t *dwc3State,
                                               usb_device_endpoint_init_struct_t *epInit)
{
    usb_device_dwc3_ep_specific_command_struct_t command;
    uint16_t maxPacketSize = epInit->maxPacketSize & USB_DESCRIPTOR_ENDPOINT_MAXPACKETSIZE_SIZE_MASK;
    uint8_t endpoint       = (epInit->endpointAddress & USB_ENDPOINT_NUMBER_MASK);
    uint8_t direction      = (epInit->endpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) >>
                        USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT;
    uint8_t index        = ((uint8_t)((uint32_t)endpoint << 1U)) | direction;
    uint8_t transferType = epInit->transferType & USB_DESCRIPTOR_ENDPOINT_ATTRIBUTE_TYPE_MASK;

    /* Cancel pending transfer of the endpoint */
    USB_DeviceDwc3Cancel((usb_device_controller_handle)dwc3State, epInit->endpointAddress);

    command.commandParmeter.parameter0 = 0U;
    command.commandParmeter.parameter1 = 0U;
    command.commandParmeter.parameter2 = 0U;
    command.commandParmeter.index      = index;

    if ((index == 0) && (!dwc3State->endpointState[index].stateUnion.stateBitField.configured))
    {
        command.commandParmeter.commandCode = USB_DEPCMD_CMDTYP_START_NEW_CONFIGURATION;

        USB_DeviceDwc3EndpointSpecificCommand(dwc3State, &command);
        /*Issue a DEPSTARTCFG command with DEPCMD0.XferRscIdx set to 2 to re-initialize the transfer resource
         * allocation.*/
        command.commandParmeter.commandCode |= USB_DEPCMD_COMMANDPARAM(0x02U);
        USB_DeviceDwc3EndpointSpecificCommand(dwc3State, &command);
    }

    dwc3State->endpointState[index].stateUnion.stateBitField.burst         = 0U;
    dwc3State->endpointState[index].stateUnion.stateBitField.streamCapable = 0U;
    /* Make the endpoint max packet size align with USB Specification 3.0. */
    if (USB_SPEED_SUPER == dwc3State->speed)
    {
        if (USB_ENDPOINT_CONTROL != transferType)
        {
            dwc3State->endpointState[index].stateUnion.stateBitField.burst = 15U;
        }
        else
        {
            maxPacketSize = USB_DEVICE_MAX_SS_CONTROL_MAX_PACKET_SIZE;
        }
    }
    else
    {
        if (USB_ENDPOINT_CONTROL != transferType)
        {
        }
        else
        {
            maxPacketSize = USB_DEVICE_MAX_NONE_SS_CONTROL_MAX_PACKET_SIZE;
        }
    }

    dwc3State->endpointState[index].stateUnion.stateBitField.type          = transferType;
    dwc3State->endpointState[index].stateUnion.stateBitField.maxPacketSize = maxPacketSize;

    command.DEPCFG.endpointType  = dwc3State->endpointState[index].stateUnion.stateBitField.type;
    command.DEPCFG.maxPacketSize = dwc3State->endpointState[index].stateUnion.stateBitField.maxPacketSize;
    command.DEPCFG.burstSize     = dwc3State->endpointState[index].stateUnion.stateBitField.burst;
    if (USB_ENDPOINT_CONTROL != transferType)
    {
        /*control Burst Size = 0 refer to 8.1.1*/
        command.DEPCFG.burstSize = 1;
    }

    if (USB_ENDPOINT_ISOCHRONOUS == transferType)
    {
        /* command.DEPCFG.fifoBased = 1; */
    }

    /*
     * For control endpoints, the FIFONum value in the OUT direction must be programmed to
     * the same value as the IN direction. This field should be set to 0 for all other OUT
     * endpoints.
     * Even though there may be more than 16 TxFIFOs in DRD mode, the device mode must use
     * lower 16 TxFIFOs.
     */
    if (direction)
    {
        command.DEPCFG.fifoNumber = endpoint;
    }

    /* Set ZLT bit. */
    dwc3State->endpointState[index].stateUnion.stateBitField.zlt = !epInit->zlt;

    command.DEPCFG.endpointNumber    = endpoint;
    command.DEPCFG.endpointDirection = (direction > 0U) ? 1U : 0U;

    command.DEPCFG.bInterval                 = 0U;
    dwc3State->endpointState[index].interval = epInit->interval;
    if ((USB_SPEED_SUPER == dwc3State->speed) || (USB_SPEED_HIGH == dwc3State->speed))
    {
        if (epInit->interval)
        {
            /*The bInterval value is reported in the endpoint descriptor. When the core is operating in Full-Speed mode,
             * this field must be set to 0.*/
            command.DEPCFG.bInterval                 = epInit->interval - 1;
            dwc3State->endpointState[index].interval = 1 << (epInit->interval - 1);
        }
    }

    command.DEPCFG.eventEnableXferComplete = 1U;
    command.DEPCFG.eventEnableXferNotReady = 1U;
    if (USB_ENDPOINT_CONTROL != transferType)
    {
        command.DEPCFG.eventEnableXferInProgress = 1U;
    }

    command.commandParmeter.commandCode = USB_DEPCMD_CMDTYP_SET_ENDPOINT_CONFIGURATION;

    USB_DeviceDwc3EndpointSpecificCommand(dwc3State, &command);

    if (!dwc3State->endpointState[index].stateUnion.stateBitField.configured)
    {
        command.commandParmeter.parameter0 = 1U;
        command.commandParmeter.parameter1 = 0U;
        command.commandParmeter.parameter2 = 0U;

        command.commandParmeter.commandCode = USB_DEPCMD_CMDTYP_SET_ENDPOINT_TRANSFER_RESOURCE_CONFIGURATION;
        USB_DeviceDwc3EndpointSpecificCommand(dwc3State, &command);
    }

    USB_DALEPENA |= 1U << index;

    dwc3State->endpointState[index].stateUnion.stateBitField.configured          = 1U;
    dwc3State->endpointState[index].stateUnion.stateBitField.resourceIndexNumber = 0U;
    dwc3State->endpointState[index].stateUnion.stateBitField.initialized         = 1U;
    dwc3State->endpointState[index].currentFrame                                 = 0U;

    if (!index)
    {
        USB_DeviceDwc3EndpointPrimeTrbForSetup(dwc3State);
    }

    return kStatus_USB_Success;
}

/*!
 * @brief De-initialize a specified endpoint.
 *
 * The function is used to de-initialize a specified endpoint.
 * Current transfer of the endpoint will be cancelled and the specified endpoint will be disabled.
 *
 * @param dwc3State       Pointer of the device XHCI state structure.
 * @param ep               The endpoint address, Bit7, 0U - USB_OUT, 1U - USB_IN.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceDwc3EndpointDeinit(usb_device_dwc3_state_struct_t *dwc3State, uint8_t ep)
{
    uint8_t endpoint = (ep & USB_ENDPOINT_NUMBER_MASK);
    uint8_t direction =
        (ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) >> USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT;
    uint8_t index = ((uint8_t)((uint32_t)endpoint << 1U)) | direction;

    dwc3State->endpointState[index].stateUnion.stateBitField.initialized = 0U;

    /* Cancel the transfer of the endpoint */
    USB_DeviceDwc3Cancel((usb_device_controller_handle)dwc3State, ep);

    USB_DALEPENA &= ~(1U << index);

    return kStatus_USB_Success;
}

static usb_status_t USB_DeviceDwc3EndpointStallState(usb_device_dwc3_state_struct_t *dwc3State,
                                                     uint8_t ep,
                                                     uint8_t enable)
{
    usb_device_dwc3_ep_specific_command_struct_t command;
    uint8_t endpoint = ep & USB_ENDPOINT_NUMBER_MASK;
    uint8_t direction =
        (ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) >> USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT;
    uint8_t index = ((uint8_t)((uint32_t)endpoint << 1U)) | direction;

    if (0 == endpoint)
    {
        direction = USB_OUT;
        index     = 0U;
    }

    if (enable == dwc3State->endpointState[index].stateUnion.stateBitField.stalled)
    {
        return kStatus_USB_Success;
    }

    dwc3State->endpointState[index].stateUnion.stateBitField.stalled = enable;
    if (0 == endpoint)
    {
        dwc3State->endpointState[1].stateUnion.stateBitField.stalled = enable;
    }

    command.commandParmeter.index      = index;
    command.commandParmeter.parameter0 = 0U;
    command.commandParmeter.parameter1 = 0U;
    command.commandParmeter.parameter2 = 0U;

    if (enable)
    {
        command.commandParmeter.commandCode = USB_DEPCMD_CMDTYP_SET_ENDPOINT_STALL;
    }
    else
    {
        /* Cancel the transfer of the endpoint */
        USB_DeviceDwc3Cancel((usb_device_controller_handle)dwc3State, ep);
        command.commandParmeter.commandCode = USB_DEPCMD_CMDTYP_CLEAR_ENDPOINT_STALL;
    }

    USB_DeviceDwc3EndpointSpecificCommand(dwc3State, &command);

    if ((enable) && (!endpoint))
    {
        USB_DeviceDwc3EndpointPrimeTrbForSetup(dwc3State);
    }
    return kStatus_USB_Success;
}

/*!
 * @brief Stall a specified endpoint.
 *
 * The function is used to stall a specified endpoint.
 * Current transfer of the endpoint will be cancelled and the specified endpoint will be stalled.
 *
 * @param dwc3State       Pointer of the device XHCI state structure.
 * @param ep               The endpoint address, Bit7, 0U - USB_OUT, 1U - USB_IN.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceDwc3EndpointStall(usb_device_dwc3_state_struct_t *dwc3State, uint8_t ep)
{
    return USB_DeviceDwc3EndpointStallState(dwc3State, ep, 1);
}

/*!
 * @brief Un-stall a specified endpoint.
 *
 * The function is used to un-stall a specified endpoint.
 * Current transfer of the endpoint will be cancelled and the specified endpoint will be un-stalled.
 *
 * @param dwc3State       Pointer of the device XHCI state structure.
 * @param ep               The endpoint address, Bit7, 0U - USB_OUT, 1U - USB_IN.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
static usb_status_t USB_DeviceDwc3EndpointUnstall(usb_device_dwc3_state_struct_t *dwc3State, uint8_t ep)
{
    return USB_DeviceDwc3EndpointStallState(dwc3State, ep, 0);
}

static void USB_DeviceDwc3InterruptEp0OutCompleted(usb_device_dwc3_state_struct_t *dwc3State,
                                                   usb_device_dwc3_event_struct_t *event)
{
    usb_device_callback_message_struct_t message;

    if (dwc3State->endpointState[0].stateUnion.stateBitField.stalled)
    {
        dwc3State->endpointState[0].stateUnion.stateBitField.stalled = 0;
        dwc3State->endpointState[1].stateUnion.stateBitField.stalled = 0;
    }
    if (USB_DEVICE_DWC3_CONTROL_PIPE_SETUP_STAGE == dwc3State->controlPipeStage)
    {
        message.code    = (0U) | (USB_OUT << 0x07U);
        message.buffer  = (uint8_t *)&s_UsbDeviceDwc3SetupBuffer[dwc3State->controllerId - kUSB_ControllerDwc30][0];
        message.length  = USB_SETUP_PACKET_SIZE;
        message.isSetup = 1U;
        /* Notify the up layer the XHCI status changed. */
        USB_DeviceNotificationTrigger(dwc3State->deviceHandle, &message);
    }
    else if (USB_DEVICE_DWC3_CONTROL_PIPE_DATA_STAGE == dwc3State->controlPipeStage)
    {
        message.code    = (0U) | (USB_OUT << 0x07U);
        message.buffer  = (uint8_t *)dwc3State->endpointState[event->DEPEVT.epNumber].transferBuffer;
        message.length  = dwc3State->endpointState[event->DEPEVT.epNumber].transferDone;
        message.isSetup = 0U;
        /* Notify the up layer the XHCI status changed. */
        USB_DeviceNotificationTrigger(dwc3State->deviceHandle, &message);
    }
    else if (USB_DEVICE_DWC3_CONTROL_PIPE_STATUS_STAGE == dwc3State->controlPipeStage)
    {
        dwc3State->controlPipeStage = USB_DEVICE_DWC3_CONTROL_PIPE_IDLE;
        dwc3State->setupPending     = 0U;
        USB_DeviceDwc3EndpointPrimeTrbForSetup(dwc3State);

        message.code    = (0U) | (USB_OUT << 0x07U);
        message.buffer  = NULL;
        message.length  = 0U;
        message.isSetup = 0U;
        /* Notify the up layer the XHCI status changed. */
        USB_DeviceNotificationTrigger(dwc3State->deviceHandle, &message);
    }
    else
    {
    }
}

static void USB_DeviceDwc3InterruptEp0InCompleted(usb_device_dwc3_state_struct_t *dwc3State,
                                                  usb_device_dwc3_event_struct_t *event)
{
    usb_device_callback_message_struct_t message;

    if (USB_DEVICE_DWC3_CONTROL_PIPE_STATUS_STAGE == dwc3State->controlPipeStage)
    {
        dwc3State->controlPipeStage = USB_DEVICE_DWC3_CONTROL_PIPE_IDLE;
        dwc3State->setupPending     = 0U;
        USB_DeviceDwc3EndpointPrimeTrbForSetup(dwc3State);

        message.code    = (0U) | (USB_OUT << 0x07U);
        message.buffer  = NULL;
        message.length  = 0U;
        message.isSetup = 0U;
        /* Notify the up layer the XHCI status changed. */
        USB_DeviceNotificationTrigger(dwc3State->deviceHandle, &message);
    }
    else if (USB_DEVICE_DWC3_CONTROL_PIPE_DATA_STAGE == dwc3State->controlPipeStage)
    {
        message.code    = (0U) | (USB_OUT << 0x07U);
        message.buffer  = (uint8_t *)dwc3State->endpointState[event->DEPEVT.epNumber].transferBuffer;
        message.length  = dwc3State->endpointState[event->DEPEVT.epNumber].transferDone;
        message.isSetup = 0U;
        /* Notify the up layer the XHCI status changed. */
        USB_DeviceNotificationTrigger(dwc3State->deviceHandle, &message);
    }
    else
    {
    }
}

static void USB_DeviceDwc3InterruptEpCompleted(usb_device_dwc3_state_struct_t *dwc3State,
                                               usb_device_dwc3_event_struct_t *event)
{
    usb_device_callback_message_struct_t message;
    uint32_t i;
    uint32_t transferredLength = 0U;
    usb_status_t errorCode     = kStatus_USB_Error;
    uint8_t ep                 = event->DEPEVT.epNumber;
    uint8_t direction          = ep & 0x01;
    uint8_t endpoint           = ep >> 1;

    if (!dwc3State->endpointState[ep].stateUnion.stateBitField.transferring)
    {
        return;
    }

    transferredLength = dwc3State->endpointState[ep].transferPrimedLength - dwc3State->endpointState[ep].trb->BUFSIZE;
    if (dwc3State->endpointState[ep].stateUnion.stateBitField.need2Copy)
    {
        for (i = 0; i < transferredLength; i++)
        {
            dwc3State->endpointState[ep].transferBuffer[dwc3State->endpointState[ep].transferDone + i] =
                dwc3State->endpointBuffer[endpoint][i];
        }
    }
    else
    {
    }
    dwc3State->endpointState[ep].transferDone += transferredLength;
    dwc3State->endpointState[ep].stateUnion.stateBitField.need2Copy           = 0;
    dwc3State->endpointState[ep].stateUnion.stateBitField.resourceIndexNumber = 0U;

    dwc3State->endpointState[ep].stateUnion.stateBitField.transferring = 0;
    if ((transferredLength) &&
        (!(transferredLength % dwc3State->endpointState[ep].stateUnion.stateBitField.maxPacketSize)) &&
        (dwc3State->endpointState[ep].transferLength > dwc3State->endpointState[ep].transferDone))
    {
        errorCode = USB_DeviceDwc3EndpointPrimeTrb(
            dwc3State, endpoint | (direction << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT),
            &dwc3State->endpointState[ep].transferBuffer[dwc3State->endpointState[ep].transferDone],
            dwc3State->endpointState[ep].transferLength - dwc3State->endpointState[ep].transferDone, 0U,
            dwc3State->endpointState[ep].trb->TRBCTL);
    }

    if (kStatus_USB_Success != errorCode)
    {
        if (0 == ep)
        {
            USB_DeviceDwc3InterruptEp0OutCompleted(dwc3State, event);
        }
        else if (1 == ep)
        {
            USB_DeviceDwc3InterruptEp0InCompleted(dwc3State, event);
        }
        else
        {
            message.code = endpoint | (uint8_t)((uint32_t)direction << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT);
            message.isSetup = 0U;
            message.buffer  = (uint8_t *)dwc3State->endpointState[ep].transferBuffer;
            message.length  = dwc3State->endpointState[ep].transferDone;
            USB_DeviceNotificationTrigger(dwc3State->deviceHandle, &message);
        }
    }
}

static void USB_DeviceDwc3InterruptEp0OutNotReady(usb_device_dwc3_state_struct_t *dwc3State,
                                                  usb_device_dwc3_event_struct_t *event)
{
    uint32_t eventStatus = event->DEPEVT.eventStatus & 0x3;

    dwc3State->setupPending = 1U;
    if (0x02 == eventStatus)
    {
        if (dwc3State->endpointState[0].stateUnion.stateBitField.stalled)
        {
        }
        else
        {
            if (dwc3State->controlPipeWithData)
            {
                USB_DeviceDwc3EndpointPrimeTrb(dwc3State, 0U, 0U, 0U, 0U, USB_TRB_TRBCTL_CONTROL_STATUS3);
            }
            else
            {
                USB_DeviceDwc3EndpointPrimeTrb(dwc3State, 0U, 0U, 0U, 0U, USB_TRB_TRBCTL_CONTROL_STATUS2);
            }
            dwc3State->controlPipeStage = USB_DEVICE_DWC3_CONTROL_PIPE_STATUS_STAGE;
        }
    }
    else if (0x01 == eventStatus)
    {
        /*
        if (dwc3State->controlPipeWithData)
        {
        }
        else
        {
            USB_DeviceDwc3EndpointStallState(dwc3State, 0x00U);
        }
        */
    }
    else
    {
    }
}

static void USB_DeviceDwc3InterruptEp0InNotReady(usb_device_dwc3_state_struct_t *dwc3State,
                                                 usb_device_dwc3_event_struct_t *event)
{
    uint32_t eventStatus = event->DEPEVT.eventStatus & 0x3;

    dwc3State->setupPending = 1U;
    if (0x02 == eventStatus)
    {
        if (dwc3State->endpointState[1].stateUnion.stateBitField.stalled)
        {
        }
        else
        {
            if (dwc3State->controlPipeWithData)
            {
                USB_DeviceDwc3EndpointPrimeTrb(dwc3State, 0x80U, 0U, 0U, 0U, USB_TRB_TRBCTL_CONTROL_STATUS3);
            }
            else
            {
                USB_DeviceDwc3EndpointPrimeTrb(dwc3State, 0x80U, 0U, 0U, 0U, USB_TRB_TRBCTL_CONTROL_STATUS2);
            }
            dwc3State->controlPipeStage = USB_DEVICE_DWC3_CONTROL_PIPE_STATUS_STAGE;
        }
    }
    else if (0x01 == eventStatus)
    {
        /*
        if (dwc3State->controlPipeWithData)
        {
        }
        else
        {
            USB_DeviceDwc3EndpointStallState(dwc3State, 0x80U);
        }
        */
    }
    else
    {
    }
}

static void USB_DeviceDwc3InterruptEpNotReady(usb_device_dwc3_state_struct_t *dwc3State,
                                              usb_device_dwc3_event_struct_t *event)
{
    uint8_t ep = event->DEPEVT.epNumber;

    if (0 == ep)
    {
        USB_DeviceDwc3InterruptEp0OutNotReady(dwc3State, event);
    }
    else if (1 == ep)
    {
        USB_DeviceDwc3InterruptEp0InNotReady(dwc3State, event);
    }
    else
    {
        if (dwc3State->endpointState[ep].stateUnion.stateBitField.transferPending)
        {
            USB_DeviceDwc3EndpointPrimeTrb(
                dwc3State, ((ep >> 1) | ((ep & 0x01U) << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT)),
                dwc3State->endpointState[ep].transferBuffer, dwc3State->endpointState[ep].transferLength,
                dwc3State->endpointState[ep].currentFrame, dwc3State->endpointState[ep].trb->TRBCTL);
        }
    }
}

static void USB_DeviceDwc3InterruptEp(usb_device_dwc3_state_struct_t *dwc3State, usb_device_dwc3_event_struct_t *event)
{
    uint32_t commandParam = event->DEPEVT.eventParam;
    uint8_t ep            = event->DEPEVT.epNumber;

    if ((USB_EVENT_ENDPOINT_XferComplete == event->DEPEVT.transferResult) ||
        (USB_EVENT_ENDPOINT_XferInProgress == event->DEPEVT.transferResult) ||
        (USB_EVENT_ENDPOINT_XferNotReady == event->DEPEVT.transferResult))
    {
        if (USB_ENDPOINT_ISOCHRONOUS == dwc3State->endpointState[ep].stateUnion.stateBitField.type)
        {
            dwc3State->endpointState[ep].currentFrame = commandParam & 0xFFFF;
        }
    }

    switch (event->DEPEVT.transferResult)
    {
        case USB_EVENT_ENDPOINT_XferComplete:
            USB_DeviceDwc3InterruptEpCompleted(dwc3State, event);
            break;
        case USB_EVENT_ENDPOINT_XferInProgress:
            USB_DeviceDwc3InterruptEpCompleted(dwc3State, event);
            break;
        case USB_EVENT_ENDPOINT_XferNotReady:
            USB_DeviceDwc3InterruptEpNotReady(dwc3State, event);
            break;
        case USB_EVENT_ENDPOINT_StreamEvt:
            break;
        case USB_EVENT_ENDPOINT_EPCmdCmplt:
            break;
        default:
            break;
    }
}

void USB_DeviceDwc3InterruptDeviceDisconnect(usb_device_dwc3_state_struct_t *dwc3State)
{
    /* Clear the device status */
    USB_DCTL &= ~(USB_DCTL_INITU1ENA_MASK | USB_DCTL_INITU2ENA_MASK | USB_DCTL_TSTCTL_MASK);
    USB_DCTL = (USB_DCTL | (USB_DCTL_ULSTCHNGREQ(5U)));

    dwc3State->isConnected = 0;
}

void USB_DeviceDwc3InterruptDeviceReset(usb_device_dwc3_state_struct_t *dwc3State)
{
    uint32_t i;

    dwc3State->isResetting = 1U;

    for (i = 2U; i < USB_DEVICE_CONFIG_ENDPOINTS * 2; i++)
    {
        USB_DeviceDwc3Cancel((usb_device_controller_handle)dwc3State, ((i & 0x01U) << 7) | (i >> 1));
    }

    for (i = 2U; i < USB_DEVICE_CONFIG_ENDPOINTS * 2; i++)
    {
        USB_DeviceDwc3EndpointUnstall(dwc3State, ((i & 0x01U) << 7) | (i >> 1));
    }

    /* Clear the device status */
    USB_DCTL &= ~(USB_DCTL_INITU1ENA_MASK | USB_DCTL_INITU2ENA_MASK | USB_DCTL_TSTCTL_MASK);

    /* Clear the device address */
    USB_DCFG = (USB_DCFG & (~USB_DCFG_DEVADDR_MASK));

    if (dwc3State->setupPending)
    {
        dwc3State->setupPending = 0U;
        USB_DeviceDwc3InterruptDeviceDisconnect(dwc3State);
    }
}

void USB_DeviceDwc3InterruptDeviceConnectDone(usb_device_dwc3_state_struct_t *dwc3State)
{
    usb_device_callback_message_struct_t message;

    dwc3State->isConnected = 1;
    /* get the device port speed */
    dwc3State->speed = USB_DSTS & USB_DSTS_CONNECTSPD_MASK;

    /* update the endpoint */
    if (USB_DSTS_CONNECTSPD_SS == dwc3State->speed)
    {
        dwc3State->endpointState[0].stateUnion.stateBitField.maxPacketSize = USB_DEVICE_MAX_SS_CONTROL_MAX_PACKET_SIZE;
        dwc3State->endpointState[1].stateUnion.stateBitField.maxPacketSize = USB_DEVICE_MAX_SS_CONTROL_MAX_PACKET_SIZE;
        dwc3State->speed                                                   = USB_SPEED_SUPER;
    }
    else if (USB_DSTS_CONNECTSPD_HS == dwc3State->speed)
    {
        dwc3State->endpointState[0].stateUnion.stateBitField.maxPacketSize =
            USB_DEVICE_MAX_NONE_SS_CONTROL_MAX_PACKET_SIZE;
        dwc3State->endpointState[1].stateUnion.stateBitField.maxPacketSize =
            USB_DEVICE_MAX_NONE_SS_CONTROL_MAX_PACKET_SIZE;
        dwc3State->speed = USB_SPEED_HIGH;
    }
    else if (USB_DSTS_CONNECTSPD_LS == dwc3State->speed)
    {
        dwc3State->endpointState[0].stateUnion.stateBitField.maxPacketSize = 8;
        dwc3State->endpointState[1].stateUnion.stateBitField.maxPacketSize = 8;
        dwc3State->speed                                                   = USB_SPEED_LOW;
    }
    else if ((USB_DSTS_CONNECTSPD_FS_30MHz_60MHz == dwc3State->speed) ||
             (USB_DSTS_CONNECTSPD_FS_48MHz == dwc3State->speed))
    {
        dwc3State->endpointState[0].stateUnion.stateBitField.maxPacketSize =
            USB_DEVICE_MAX_NONE_SS_CONTROL_MAX_PACKET_SIZE;
        dwc3State->endpointState[1].stateUnion.stateBitField.maxPacketSize =
            USB_DEVICE_MAX_NONE_SS_CONTROL_MAX_PACKET_SIZE;
        dwc3State->speed = USB_SPEED_FULL;
    }
    else
    {
    }

    message.buffer  = (uint8_t *)NULL;
    message.code    = kUSB_DeviceNotifyBusReset;
    message.length  = 0U;
    message.isSetup = 0U;

    USB_DeviceNotificationTrigger(dwc3State->deviceHandle, &message);
}

void USB_DeviceDwc3InterruptDeviceLinkStateChange(usb_device_dwc3_state_struct_t *dwc3State)
{
}

static void USB_DeviceDwc3InterruptDevice(usb_device_dwc3_state_struct_t *dwc3State,
                                          usb_device_dwc3_event_struct_t *event)
{
    switch (event->DEVT.deviceStatus)
    {
        case USB_EVENT_DEVICE_DISCONNECT_DETECTED:
            USB_DeviceDwc3InterruptDeviceDisconnect(dwc3State);
            break;

        case USB_EVENT_DEVICE_RESET:
            USB_DeviceDwc3InterruptDeviceReset(dwc3State);
            break;

        case USB_EVENT_DEVICE_CONNECTION_DONE:
            USB_DeviceDwc3InterruptDeviceConnectDone(dwc3State);
            break;

        case USB_EVENT_DEVICE_LINK_STATE_CHANGE:
            USB_DeviceDwc3InterruptDeviceLinkStateChange(dwc3State);
            break;

        case USB_EVENT_DEVICE_RESEUM_DETECTED:
            break;

        case USB_EVENT_DEVICE_HIBERNATION_REQUEST:
            break;

        case USB_EVENT_DEVICE_SUSPEND_ENTRY:
            break;

        case USB_EVENT_DEVICE_SOF:
            break;

        case USB_EVENT_DEVICE_L1_SUSPEND:
            break;

        case USB_EVENT_DEVICE_ERRATIC_ERROR:
            break;

        case USB_EVENT_DEVICE_GENERIC_COMMAND_COMPLETE:
            break;

        case USB_EVENT_DEVICE_EVENT_BUFFER_OVERFLOW:
            break;

        case USB_EVENT_DEVICE_VENDOR_DEVICE_TEST_LPM_RECEIVED:
            break;

        case USB_EVENT_DEVICE_STOPPED_ON_DISCONNECT:
            break;

        case USB_EVENT_DEVICE_L1_RESEUM_DETECTED:
            break;

        default:
            break;
    }
}

/*!
 * @brief Initialize the USB device XHCI instance.
 *
 * This function initializes the USB device XHCI module specified by the controllerId.
 *
 * @param controllerId The controller id of the USB IP. Please refer to enumeration type usb_controller_index_t.
 * @param handle        Pointer of the device handle, used to identify the device object is belonged to.
 * @param dwc3Handle   It is out parameter, is used to return pointer of the device XHCI handle to the caller.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceDwc3Init(uint8_t controllerId,
                                usb_device_handle handle,
                                usb_device_controller_handle *dwc3Handle)
{
    usb_device_dwc3_state_struct_t *dwc3State;
    volatile uint32_t i;
    uint64_t dwc3Base[] = USBSS_BASE_ADDRS;

    if ((controllerId < kUSB_ControllerDwc30) ||
        ((uint32_t)(controllerId - kUSB_ControllerDwc30) >= USB_DEVICE_CONFIG_DWC3) ||
        ((uint32_t)(controllerId - kUSB_ControllerDwc30) >= (sizeof(dwc3Base) / sizeof(uint32_t))))
    {
        return kStatus_USB_ControllerNotFound;
    }

    dwc3State = &g_UsbDeviceDwc3Sate[controllerId - kUSB_ControllerDwc30];

    dwc3State->controllerId = controllerId;

    dwc3State->registerBase = dwc3Base[controllerId - kUSB_ControllerDwc30];

    dwc3State->eventCount = ((USB_GHWPARAMS1 & USB_GHWPARAMS1_DWC_USB3_DEVICE_NUM_INT_MASK) >>
                             USB_GHWPARAMS1_DWC_USB3_DEVICE_NUM_INT_SHIFT);

    if (dwc3State->eventCount > USB_DEVICE_CONFIG_DWC3_EVENT_COUNT)
    {
        return kStatus_USB_Error;
    }
    /* dwc3State->eventCount = USB_DEVICE_CONFIG_DWC3_EVENT_COUNT; */
    /* Get the HW's endpoint count */
    dwc3State->endpointCount =
        (uint8_t)((USB_GHWPARAMS3 & USB_GHWPARAMS3_DWC_USB3_NUM_EPS_MASK) >> USB_GHWPARAMS3_DWC_USB3_NUM_EPS_SHIFT);

    if (dwc3State->endpointCount < USB_DEVICE_CONFIG_ENDPOINTS)
    {
        return kStatus_USB_Error;
    }
    dwc3State->deviceHandle = (usb_device_struct_t *)handle;

    for (i = 0; i < (USB_DEVICE_CONFIG_ENDPOINTS * 2); i++)
    {
        dwc3State->endpointState[i].trb =
            (usb_device_dwc3_trb_struct_t *)(&s_UsbDeviceDwc3Trb[dwc3State->controllerId - kUSB_ControllerDwc30][i]);
    }

    /* Disbale the device controller */
    USB_DCTL &= ~USB_DCTL_RUN_STOP_MASK;

    /* Reset device controller */
    USB_DCTL |= USB_DCTL_CSFTRST_MASK;

    while (USB_DCTL & USB_DCTL_CSFTRST_MASK)
    {
    }
    /* Reset PHY */
    /* 1. Reset the global controller */
    USB_GCTL |= USB_GCTL_CORESOFTRESET_MASK;

    /* 2.1 Reset the USB2.0 PHY */
    USB_GUSB2PHYCFG(0) |= USB_GUSB2PHYCFG_PHYSOFTRST_MASK;

    /* 2.2 Reset the USB3.x PHY */
    USB_GUSB3PIPECTL(0) |= USB_GUSB3PIPECTL_PHYSoftRst_MASK;

    for (i = 0; i < 0xFFFFF; i++)
    {
    }

    /* 3.1 Stop the USB3.x PHY reset */
    USB_GUSB3PIPECTL(0) &= ~USB_GUSB3PIPECTL_PHYSoftRst_MASK;

    /* 3.2 Stop the USB2.0 PHY reset */
    USB_GUSB2PHYCFG(0) &= ~USB_GUSB2PHYCFG_PHYSOFTRST_MASK;

    for (i = 0; i < 0xFFFFF; i++)
    {
    }

    /* 4. Stop the global controller reset */
    USB_GCTL &= ~USB_GCTL_CORESOFTRESET_MASK;

    dwc3State->eventBuffer =
        (uint8_t *)&s_UsbDeviceDwc3EventBuffer[dwc3State->controllerId - kUSB_ControllerDwc30][0][0];
    for (i = 0; i < dwc3State->eventCount; i++)
    {
        USB_GEVNTADRLO(i)               = (uint32_t)((uint64_t)dwc3State->eventBuffer +
                                       i * USB_DEVICE_DWC3_EVENT_BUFFER_SIZE * USB_DEVICE_DWC3_EVENT_BUFFER_COUNT);
        USB_GEVNTADRHI(i)               = (uint32_t)(((uint64_t)dwc3State->eventBuffer +
                                        i * USB_DEVICE_DWC3_EVENT_BUFFER_SIZE * USB_DEVICE_DWC3_EVENT_BUFFER_COUNT) >>
                                       32);
        USB_GEVNTSIZ(i)                 = USB_DEVICE_DWC3_EVENT_BUFFER_SIZE * USB_DEVICE_DWC3_EVENT_BUFFER_COUNT;
        USB_GEVNTCOUNT(i)               = 0U;
        dwc3State->currentEventIndex[i] = 0U;
    }

    USB_GCTL &= ~USB_GCTL_SCALEDOWN_MASK;
    if (USB_GHWPARAMS1_DWC_USB3_EN_PWROPT(0x01U) == (USB_GHWPARAMS1 & USB_GHWPARAMS1_DWC_USB3_EN_PWROPT_MASK))
    {
        USB_GCTL &= ~USB_GCTL_DSBLCLKGTNG_MASK;
    }
    USB_GCTL &= ~USB_GCTL_DISSCRAMBLE_MASK;

    /* Set the Scratchpad Buffer Array */
    /* set the Scratchpad Buffer Array Lo regsiter */
    USB_DGCMDPAR =
        (uint32_t)((uint64_t)&s_UsbDeviceDwc3ScratchpadBuffer[dwc3State->controllerId - kUSB_ControllerDwc30][0]);
    USB_DGCMD = USB_DGCMD_CMDACT_MASK | USB_DGCMD_CMDTYP(0x04U);

    while (USB_DGCMD & USB_DGCMD_CMDACT_MASK)
    {
    }

    /* set the Scratchpad Buffer Array Hi regsiter */
    USB_DGCMDPAR = (uint32_t)(
        ((uint64_t)&s_UsbDeviceDwc3ScratchpadBuffer[dwc3State->controllerId - kUSB_ControllerDwc30][0]) >> 32);
    USB_DGCMD = USB_DGCMD_CMDACT_MASK | USB_DGCMD_CMDTYP(0x05U);

    while (USB_DGCMD & USB_DGCMD_CMDACT_MASK)
    {
    }

    USB_GCTL = (USB_GCTL & (~USB_GCTL_PRTCAPDIR_MASK)) | USB_GCTL_PRTCAPDIR_DEVICE;

    USB_DCFG = (USB_DCFG & (~USB_DCFG_DEVSPD_MASK)) | USB_DCFG_DEVSPD_SS;

    /* Enbale the interrupt */
    USB_DEVTEN = USB_DEVTEN_DISSCONNEVTEN_MASK | USB_DEVTEN_USBRSTEVTEN_MASK | USB_DEVTEN_CONNECTDONEEVTEN_MASK |
                 USB_DEVTEN_ULSTCNGEN_MASK;

    dwc3State->endpointBuffer[0] =
        (uint8_t *)(&s_UsbDeviceDwc3EpBuffer[dwc3State->controllerId - kUSB_ControllerDwc30][0]);

    for (i = 1; i < (USB_DEVICE_CONFIG_ENDPOINTS); i++)
    {
        dwc3State->endpointBuffer[i] =
            (uint8_t *)(&s_UsbDeviceDwc3EpBuffer[dwc3State->controllerId - kUSB_ControllerDwc30][i * 1024 - 512]);
    }

    dwc3State->speed                                                   = USB_SPEED_SUPER;
    dwc3State->endpointState[0].stateUnion.stateBitField.maxPacketSize = USB_DEVICE_MAX_SS_CONTROL_MAX_PACKET_SIZE;
    dwc3State->endpointState[1].stateUnion.stateBitField.maxPacketSize = USB_DEVICE_MAX_SS_CONTROL_MAX_PACKET_SIZE;

    /* Set the DWC3 to default status. */
    USB_DeviceDwc3SetDefaultState(dwc3State);
    *dwc3Handle = (usb_device_controller_handle)dwc3State;

    return kStatus_USB_Success;
}

/*!
 * @brief De-initialize the USB device XHCI instance.
 *
 * This function de-initializes the USB device XHCI module.
 *
 * @param dwc3Handle   Pointer of the device XHCI handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceDwc3Deinit(usb_device_controller_handle dwc3Handle)
{
    usb_device_dwc3_state_struct_t *dwc3State = (usb_device_dwc3_state_struct_t *)dwc3Handle;
    volatile uint32_t i;

    if (!dwc3Handle)
    {
        return kStatus_USB_InvalidHandle;
    }

    USB_DEVTEN = 0U;
    /* Disbale the device controller */
    USB_DCTL &= ~USB_DCTL_RUN_STOP_MASK;

    /* Reset device controller */
    USB_DCTL |= USB_DCTL_CSFTRST_MASK;

    while (USB_DCTL & USB_DCTL_CSFTRST_MASK)
    {
    }
    /* Reset PHY */
    /* 1. Reset the global controller */
    USB_GCTL |= USB_GCTL_CORESOFTRESET_MASK;

    /* 2.1 Reset the USB2.0 PHY */
    USB_GUSB2PHYCFG(0) |= USB_GUSB2PHYCFG_PHYSOFTRST_MASK;

    /* 2.2 Reset the USB3.x PHY */
    USB_GUSB3PIPECTL(0) |= USB_GUSB3PIPECTL_PHYSoftRst_MASK;

    for (i = 0; i < 0xFFFFF; i++)
    {
    }

    /* 3.1 Stop the USB3.x PHY reset */
    USB_GUSB3PIPECTL(0) &= ~USB_GUSB3PIPECTL_PHYSoftRst_MASK;

    /* 3.2 Stop the USB2.0 PHY reset */
    USB_GUSB2PHYCFG(0) &= ~USB_GUSB2PHYCFG_PHYSOFTRST_MASK;

    for (i = 0; i < 0xFFFFF; i++)
    {
    }

    /* 4. Stop the global controller reset */
    USB_GCTL &= ~USB_GCTL_CORESOFTRESET_MASK;

    return kStatus_USB_Success;
}

/*!
 * @brief Send data through a specified endpoint.
 *
 * This function sends data through a specified endpoint.
 *
 * @param dwc3Handle      Pointer of the device XHCI handle.
 * @param endpointAddress Endpoint index.
 * @param buffer           The memory address to hold the data need to be sent.
 * @param length           The data length need to be sent.
 *
 * @return A USB error code or kStatus_USB_Success.
 *
 * @note The return value just means if the sending request is successful or not; the transfer done is notified by the
 * corresponding callback function.
 * Currently, only one transfer request can be supported for one specific endpoint.
 * If there is a specific requirement to support multiple transfer requests for one specific endpoint, the application
 * should implement a queue in the application level.
 * The subsequent transfer could begin only when the previous transfer is done (get notification through the endpoint
 * callback).
 */
usb_status_t USB_DeviceDwc3Send(usb_device_controller_handle dwc3Handle,
                                uint8_t endpointAddress,
                                uint8_t *buffer,
                                uint32_t length)
{
    usb_device_dwc3_state_struct_t *dwc3State = (usb_device_dwc3_state_struct_t *)dwc3Handle;
    uint32_t frame                            = 0U;
    usb_status_t status                       = kStatus_USB_Success;

    endpointAddress =
        (endpointAddress & USB_ENDPOINT_NUMBER_MASK) | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT);

    dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK) << 1) | USB_IN].transferDone   = 0U;
    dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK) << 1) | USB_IN].transferBuffer = buffer;
    dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK) << 1) | USB_IN].transferLength = length;

    if (0 == (endpointAddress & USB_ENDPOINT_NUMBER_MASK))
    {
        if (length)
        {
            status = USB_DeviceDwc3EndpointPrimeTrb(dwc3State, endpointAddress, buffer, length, 0U,
                                                    USB_TRB_TRBCTL_CONTROL_DATA);
            dwc3State->controlPipeWithData = 1U;
            dwc3State->controlPipeStage    = USB_DEVICE_DWC3_CONTROL_PIPE_DATA_STAGE;
        }
        else
        {
        }
    }
    else
    {
        if (USB_ENDPOINT_ISOCHRONOUS ==
            dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK) << 1) | USB_IN]
                .stateUnion.stateBitField.type)
        {
            frame = dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK) << 1) | USB_IN].currentFrame;
        }

        /*
                if (USB_ENDPOINT_ISOCHRONOUS == dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK)
           << 1) | USB_IN].stateUnion.stateBitField.type)
                {
                    dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK) << 1) |
           USB_IN].stateUnion.stateBitField.transferPending = 1U;
                }
                else
        */
        {
            status = USB_DeviceDwc3EndpointPrimeTrb(dwc3State, endpointAddress, buffer, length, frame,
                                                    USB_TRB_TRBCTL_NORMAL);
        }
    }

    return status;
}

/*!
 * @brief Receive data through a specified endpoint.
 *
 * This function Receives data through a specified endpoint.
 *
 * @param dwc3Handle      Pointer of the device XHCI handle.
 * @param endpointAddress Endpoint index.
 * @param buffer           The memory address to save the received data.
 * @param length           The data length want to be received.
 *
 * @return A USB error code or kStatus_USB_Success.
 *
 * @note The return value just means if the receiving request is successful or not; the transfer done is notified by the
 * corresponding callback function.
 * Currently, only one transfer request can be supported for one specific endpoint.
 * If there is a specific requirement to support multiple transfer requests for one specific endpoint, the application
 * should implement a queue in the application level.
 * The subsequent transfer could begin only when the previous transfer is done (get notification through the endpoint
 * callback).
 */
usb_status_t USB_DeviceDwc3Recv(usb_device_controller_handle dwc3Handle,
                                uint8_t endpointAddress,
                                uint8_t *buffer,
                                uint32_t length)
{
    usb_device_dwc3_state_struct_t *dwc3State = (usb_device_dwc3_state_struct_t *)dwc3Handle;
    uint32_t frame                            = 0U;
    usb_status_t status                       = kStatus_USB_Success;

    endpointAddress =
        (endpointAddress & USB_ENDPOINT_NUMBER_MASK) | (USB_OUT << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT);

    dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK) << 1) | USB_OUT].transferDone   = 0U;
    dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK) << 1) | USB_OUT].transferBuffer = buffer;
    dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK) << 1) | USB_OUT].transferLength = length;

    if (0 == (endpointAddress & USB_ENDPOINT_NUMBER_MASK))
    {
        if (length)
        {
            status = USB_DeviceDwc3EndpointPrimeTrb(dwc3State, endpointAddress, buffer, length, 0U,
                                                    USB_TRB_TRBCTL_CONTROL_DATA);
            dwc3State->controlPipeWithData = 1U;
            dwc3State->controlPipeStage    = USB_DEVICE_DWC3_CONTROL_PIPE_DATA_STAGE;
        }
        else
        {
        }
    }
    else
    {
        if (USB_ENDPOINT_ISOCHRONOUS ==
            dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK) << 1) | USB_OUT]
                .stateUnion.stateBitField.type)
        {
            frame =
                dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK) << 1) | USB_OUT].currentFrame;
        }

        /*
                if (USB_ENDPOINT_ISOCHRONOUS == dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK)
           << 1) | USB_OUT].stateUnion.stateBitField.type)
                {
                    dwc3State->endpointState[((endpointAddress & USB_ENDPOINT_NUMBER_MASK) << 1) |
           USB_OUT].stateUnion.stateBitField.transferPending = 1U;
                }
                else
        */
        {
            status = USB_DeviceDwc3EndpointPrimeTrb(dwc3State, endpointAddress, buffer, length, frame,
                                                    USB_TRB_TRBCTL_NORMAL);
        }
    }

    return status;
}

/*!
 * @brief Cancel the pending transfer in a specified endpoint.
 *
 * The function is used to cancel the pending transfer in a specified endpoint.
 *
 * @param dwc3Handle      Pointer of the device XHCI handle.
 * @param ep               Endpoint address, bit7 is the direction of endpoint, 1U - IN, 0U - OUT.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceDwc3Cancel(usb_device_controller_handle dwc3Handle, uint8_t ep)
{
    usb_device_dwc3_state_struct_t *dwc3State = (usb_device_dwc3_state_struct_t *)dwc3Handle;
    usb_device_dwc3_ep_specific_command_struct_t command;
    uint8_t endpoint = (ep & USB_ENDPOINT_NUMBER_MASK);
    uint8_t direction =
        (ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) >> USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT;
    uint8_t index = ((uint8_t)((uint32_t)endpoint << 1U)) | direction;
    if (!dwc3State->endpointState[index].stateUnion.stateBitField.transferring)
    {
        return kStatus_USB_Success;
    }

    if (!dwc3State->endpointState[index].stateUnion.stateBitField.resourceIndexNumber)
    {
        return kStatus_USB_Success;
    }

    dwc3State->endpointState[index].stateUnion.stateBitField.transferring = 0U;

    command.commandParmeter.parameter0 = 0U;
    command.commandParmeter.parameter1 = 0U;
    command.commandParmeter.parameter2 = 0U;
    command.commandParmeter.index      = index;

    command.commandParmeter.commandCode =
        USB_DEPCMD_CMDTYP_END_TRANSFER | USB_DEPCMD_HIPRI_FORCERM_MASK | USB_DEPCMD_CMDIOC_MASK |
        USB_DEPCMD_COMMANDPARAM(dwc3State->endpointState[index].stateUnion.stateBitField.resourceIndexNumber);
    USB_DeviceDwc3EndpointSpecificCommand(dwc3State, &command);
    dwc3State->endpointState[index].stateUnion.stateBitField.resourceIndexNumber = 0U;

    return kStatus_USB_Success;
}

/*!
 * @brief Control the status of the selected item.
 *
 * The function is used to control the status of the selected item.
 *
 * @param dwc3Handle      Pointer of the device XHCI handle.
 * @param type             The selected item. Please refer to enumeration type usb_device_control_type_t.
 * @param param            The param type is determined by the selected item.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceDwc3Control(usb_device_controller_handle dwc3Handle, usb_device_control_type_t type, void *param)
{
    usb_device_dwc3_state_struct_t *dwc3State = (usb_device_dwc3_state_struct_t *)dwc3Handle;
    usb_status_t error                        = kStatus_USB_Error;
    uint16_t *temp16;
    uint8_t *temp8;
    uint8_t count;

    if (!dwc3Handle)
    {
        return kStatus_USB_InvalidHandle;
    }

    switch (type)
    {
        case kUSB_DeviceControlRun:
            /* Enable the device controller */
            USB_DCTL |= USB_DCTL_RUN_STOP_MASK;
            error = kStatus_USB_Success;
            break;
        case kUSB_DeviceControlStop:
            /* Enable the device controller */
            USB_DCTL &= ~USB_DCTL_RUN_STOP_MASK;
            error = kStatus_USB_Success;
            break;
        case kUSB_DeviceControlEndpointInit:
            if (param)
            {
                error = USB_DeviceDwc3EndpointInit(dwc3State, (usb_device_endpoint_init_struct_t *)param);
            }
            break;
        case kUSB_DeviceControlEndpointDeinit:
            if (param)
            {
                temp8 = (uint8_t *)param;
                error = USB_DeviceDwc3EndpointDeinit(dwc3State, *temp8);
            }
            break;
        case kUSB_DeviceControlEndpointStall:
            if (param)
            {
                temp8 = (uint8_t *)param;
                error = USB_DeviceDwc3EndpointStall(dwc3State, *temp8);
            }
            break;
        case kUSB_DeviceControlEndpointUnstall:
            if (param)
            {
                temp8 = (uint8_t *)param;
                error = USB_DeviceDwc3EndpointUnstall(dwc3State, *temp8);
            }
            break;
        case kUSB_DeviceControlGetDeviceStatus:
            if (param)
            {
                temp16  = (uint16_t *)param;
                *temp16 = (USB_DEVICE_CONFIG_SELF_POWER << (USB_REQUEST_STANDARD_GET_STATUS_DEVICE_SELF_POWERED_SHIFT))
#if ((defined(USB_DEVICE_CONFIG_REMOTE_WAKEUP)) && (USB_DEVICE_CONFIG_REMOTE_WAKEUP > 0U))
                          | (deviceHandle->remotewakeup << (USB_REQUEST_STANDARD_GET_STATUS_DEVICE_REMOTE_WARKUP_SHIFT))
#endif
                    ;
                error = kStatus_USB_Success;
            }
            break;
        case kUSB_DeviceControlGetEndpointStatus:
            if (param)
            {
                usb_device_endpoint_status_struct_t *endpointStatus = (usb_device_endpoint_status_struct_t *)param;
                uint8_t ep = (endpointStatus->endpointAddress) & USB_ENDPOINT_NUMBER_MASK;
                uint8_t direction =
                    ((endpointStatus->endpointAddress) & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) >>
                    USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT;

                if (ep < USB_DEVICE_CONFIG_ENDPOINTS)
                {
                    endpointStatus->endpointStatus =
                        (dwc3State->endpointState[(ep << 1) | direction].stateUnion.stateBitField.stalled) ?
                            kUSB_DeviceEndpointStateStalled :
                            kUSB_DeviceEndpointStateIdle;
                    error = kStatus_USB_Success;
                }
            }
            break;
        case kUSB_DeviceControlPreSetDeviceAddress:
            if (param)
            {
                temp8    = (uint8_t *)param;
                USB_DCFG = (USB_DCFG & (~USB_DCFG_DEVADDR_MASK)) | (USB_DCFG_DEVADDR(((uint32_t)(*temp8)) & 0x7FU));

                error = kStatus_USB_Success;
            }
            break;
        case kUSB_DeviceControlSetDeviceAddress:
            if (param)
            {
                error = kStatus_USB_Success;
            }
            break;
        case kUSB_DeviceControlGetSynchFrame:
            break;
#if (defined(USB_DEVICE_CONFIG_LOW_POWER_MODE) && (USB_DEVICE_CONFIG_LOW_POWER_MODE > 0U))
#if defined(USB_DEVICE_CONFIG_REMOTE_WAKEUP) && (USB_DEVICE_CONFIG_REMOTE_WAKEUP > 0U)
        case kUSB_DeviceControlResume:
            USB_USBGENCTRL &= ~USBHS_USBGENCTRL_WU_IE_MASK;
            USB_PORTSC1 &= ~USBHS_PORTSC1_PHCD_MASK;
            USB_PORTSC1 |= USBHS_PORTSC1_FPR_MASK;
            startTick = deviceHandle->hwTick;
            while ((deviceHandle->hwTick - startTick) < 10)
            {
                __NOP();
            }
            USB_PORTSC1 &= ~USBHS_PORTSC1_FPR_MASK;
            error = kStatus_USB_Success;
            break;
#endif /* USB_DEVICE_CONFIG_REMOTE_WAKEUP */
        case kUSB_DeviceControlSuspend:
            USB_OTGSC |= 0x007F0000U;
            dwc3State->registerPhyBase->PWD = 0xFFFFFFFF;
            /* USB_OTGCTL |= ((1U<<10) | (1U<<17) | (1U<<16)); */
            while (dwc3State->registerPhyBase->CTRL & (USBPHY_CTRL_UTMI_SUSPENDM_MASK))
            {
                __NOP();
            }
            /* dwc3State->registerPhyBase->CTRL |= ((1U << 21) | (1U << 22) | (1U << 23)); */
            USB_USBSTS |= USBHS_USBSTS_SRI_MASK;
            USB_PORTSC1 |= USBHS_PORTSC1_PHCD_MASK;
            USB_USBGENCTRL = USBHS_USBGENCTRL_WU_IE_MASK;
            dwc3State->registerPhyBase->CTRL |= USBPHY_CTRL_CLKGATE_MASK;
            dwc3State->isSuspending = 1U;
            error                   = kStatus_USB_Success;
            break;
#endif /* USB_DEVICE_CONFIG_LOW_POWER_MODE */
        case kUSB_DeviceControlSetDefaultStatus:
            for (count = 0U; count < USB_DEVICE_CONFIG_ENDPOINTS; count++)
            {
                USB_DeviceDwc3EndpointDeinit(dwc3State, (count | (USB_IN << 0x07U)));
                USB_DeviceDwc3EndpointDeinit(dwc3State, (count | (USB_OUT << 0x07U)));
            }
            USB_DeviceDwc3SetDefaultState(dwc3State);
            error = kStatus_USB_Success;
            break;
        case kUSB_DeviceControlGetSpeed:
            if (param)
            {
                temp8  = (uint8_t *)param;
                *temp8 = dwc3State->speed;
                error  = kStatus_USB_Success;
            }
            break;
        case kUSB_DeviceControlGetOtgStatus:
            break;
        case kUSB_DeviceControlSetOtgStatus:
            break;
#if (defined(USB_DEVICE_CONFIG_DWC3_TEST_MODE) && (USB_DEVICE_CONFIG_DWC3_TEST_MODE > 0U))
        case kUSB_DeviceControlSetTestMode:
            if (param)
            {
                temp8 = (uint8_t *)param;
                USB_PORTSC1 |= ((uint32_t)(*temp8) << 16U);
                error = kStatus_USB_Success;
            }
            break;
#endif
#if (defined(USB_DEVICE_CHARGER_DETECT_ENABLE) && (USB_DEVICE_CHARGER_DETECT_ENABLE > 0U)) && \
    (defined(FSL_FEATURE_USBHSDCD_HSDCD) && (FSL_FEATURE_USBHSDCD_HSDCD > 0U))
        case kUSB_DeviceControlGetDeviceAttachStatus:
            if (USB_OTGSC & USBHS_OTGSC_BSV_MASK)
            {
                error = kStatus_USB_XHCIAttached;
            }
            else
            {
                error = kStatus_USB_XHCIDetached;
            }
            break;

        case kUSB_DeviceControlDcdInitModule:
            dcdHSState->dcdRegisterBase->CONTROL |= USBDCD_CONTROL_SR_MASK;
            dcdHSState->dcdRegisterBase->TIMER0 = USBDCD_TIMER0_TSEQ_INIT(deviceDcdTimingConfig->dcdSeqInitTime);
            dcdHSState->dcdRegisterBase->TIMER1 = USBDCD_TIMER1_TDCD_DBNC(deviceDcdTimingConfig->dcdDbncTime);
            dcdHSState->dcdRegisterBase->TIMER1 |= USBDCD_TIMER1_TVDPSRC_ON(deviceDcdTimingConfig->dcdDpSrcOnTime);
            dcdHSState->dcdRegisterBase->TIMER2_BC12 =
                USBDCD_TIMER2_BC12_TWAIT_AFTER_PRD(deviceDcdTimingConfig->dcdTimeWaitAfterPrD);
            dcdHSState->dcdRegisterBase->TIMER2_BC12 |=
                USBDCD_TIMER2_BC12_TVDMSRC_ON(deviceDcdTimingConfig->dcdTimeDMSrcOn);
            dcdHSState->dcdRegisterBase->CONTROL |= USBDCD_CONTROL_IE_MASK;
            dcdHSState->dcdRegisterBase->CONTROL |= USBDCD_CONTROL_BC12_MASK;
            dcdHSState->dcdRegisterBase->CONTROL |= USBDCD_CONTROL_START_MASK;
            break;
        case kUSB_DeviceControlDcdDeinitModule:
            dcdHSState->dcdRegisterBase->CONTROL |= USBDCD_CONTROL_SR_MASK;
            break;
#endif

        default:
            break;
    }

    return error;
}

/*!
 * @brief Handle the XHCI device interrupt.
 *
 * The function is used to handle the XHCI device interrupt.
 *
 * @param deviceHandle    The device handle got from USB_DeviceInit.
 *
 */
void USB_DeviceDwc3IsrFunction(void *deviceHandle)
{
    volatile usb_device_struct_t *handle = (usb_device_struct_t *)deviceHandle;
    volatile usb_device_dwc3_state_struct_t *dwc3State;
    usb_device_dwc3_event_struct_t event;
    uint32_t eventCount;
    uint32_t i;

    if (NULL == deviceHandle)
    {
        return;
    }

    dwc3State = (usb_device_dwc3_state_struct_t *)(handle->controllerHandle);

    for (i = 0; i < dwc3State->eventCount; i++)
    {
        eventCount = USB_GEVNTCOUNT(i) & USB_GEVNTCOUNT_EVNTCOUNT_MASK;
        if (eventCount)
        {
            USB_GEVNTSIZ(i) |= USB_GEVNTSIZ_EVNTINTRPTMASK_MASK;

            while (eventCount)
            {
                event.event = *((uint32_t *)(&dwc3State->eventBuffer[i * USB_DEVICE_DWC3_EVENT_BUFFER_SIZE *
                                                                         USB_DEVICE_DWC3_EVENT_BUFFER_COUNT +
                                                                     dwc3State->currentEventIndex[i]]));

                if (event.commonState.eventType)
                {
                    USB_DeviceDwc3InterruptDevice(dwc3State, &event);
                }
                else
                {
                    USB_DeviceDwc3InterruptEp(dwc3State, &event);
                }
                dwc3State->currentEventIndex[i] += sizeof(usb_device_dwc3_event_struct_t);
                dwc3State->currentEventIndex[i] =
                    dwc3State->currentEventIndex[i] %
                    (USB_DEVICE_DWC3_EVENT_BUFFER_SIZE * USB_DEVICE_DWC3_EVENT_BUFFER_COUNT);
                USB_GEVNTCOUNT(i) = sizeof(usb_device_dwc3_event_struct_t);
                eventCount -= sizeof(usb_device_dwc3_event_struct_t);
            }

            USB_GEVNTSIZ(i) &= ~USB_GEVNTSIZ_EVNTINTRPTMASK_MASK;
        }
    }
}

#endif /* USB_DEVICE_CONFIG_DWC3 */
