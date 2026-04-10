/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2018 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_DEVICE_DWC3_H__
#define __USB_DEVICE_DWC3_H__

/*!
 * @addtogroup usb_device_controller_dwc3_driver
 * @{
 */

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define USB_DEVICE_DWC3_EVENT_BUFFER_COUNT (16U * 2U * 2U)
#define USB_DEVICE_DWC3_EVENT_BUFFER_SIZE (0x04U)

#define USB_DEVICE_CONFIG_DWC3_SCRATCHPAD_BUFFER_SIZE (0x1000U)

/*! @brief The maximum value of ISO type maximum packet size for HS in USB specification 3.0 */
#define USB_DEVICE_MAX_SS_ISO_MAX_PACKET_SIZE (1024U)

/*! @brief The maximum value of interrupt type maximum packet size for HS in USB specification 3.0 */
#define USB_DEVICE_MAX_SS_INTERUPT_MAX_PACKET_SIZE (1024U)

/*! @brief The maximum value of bulk type maximum packet size for HS in USB specification 3.0 */
#define USB_DEVICE_MAX_SS_BULK_MAX_PACKET_SIZE (1024U)

/*! @brief The maximum value of control type maximum packet size for HS in USB specification 3.0 */
#define USB_DEVICE_MAX_SS_CONTROL_MAX_PACKET_SIZE (512U)
#define USB_DEVICE_MAX_NONE_SS_CONTROL_MAX_PACKET_SIZE (64U)

#define USBSS_BASE_ADDRS \
    {                    \
        USB1_BASE        \
    }
#define USB_GCTL_OFFSET (0xC110U)
#define USB_GHWPARAMS1_OFFSET (0xC144U)
#define USB_GHWPARAMS3_OFFSET (0xC14CU)
#define USB_GUSB2PHYCFG_OFFSET(n) (0xC200U + n * 4U)
#define USB_GUSB3PIPECTL_OFFSET(n) (0xC2C0U + n * 4U)
#define USB_GEVNTADRLO_OFFSET(n) (0xC400U + n * 0x10U)
#define USB_GEVNTADRHI_OFFSET(n) (0xC404U + n * 0x10U)
#define USB_GEVNTSIZ_OFFSET(n) (0xC408U + n * 0x10U)
#define USB_GEVNTCOUNT_OFFSET(n) (0xC40CU + n * 0x10U)
#define USB_DCFG_OFFSET (0xC700U)
#define USB_DCTL_OFFSET (0xC704U)
#define USB_DEVTEN_OFFSET (0xC708U)
#define USB_DSTS_OFFSET (0xC70CU)
#define USB_DGCMDPAR_OFFSET (0xC710U)
#define USB_DGCMD_OFFSET (0xC714U)
#define USB_DALEPENA_OFFSET (0xC720U)
#define USB_DEPCMDPAR2_OFFSET(n) (0xC800U + n * 0x10U)
#define USB_DEPCMDPAR1_OFFSET(n) (0xC804U + n * 0x10U)
#define USB_DEPCMDPAR0_OFFSET(n) (0xC808U + n * 0x10U)
#define USB_DEPCMD_OFFSET(n) (0xC80CU + n * 0x10U)
#define USB_OEVT_OFFSET (0xCC08U)
#define USB_OSTS_OFFSET (0xCC10U)

#define USB_GCTL (*((volatile uint32_t *)(((uint64_t)(USB_GCTL_OFFSET + (dwc3State->registerBase))))))
#define USB_GCTL_PRTCAPDIR_SHIFT (12U)
#define USB_GCTL_PRTCAPDIR_MASK (0x03U << USB_GCTL_PRTCAPDIR_SHIFT)
#define USB_GCTL_PRTCAPDIR(n) ((n) << USB_GCTL_PRTCAPDIR_SHIFT)
#define USB_GCTL_PRTCAPDIR_HOST USB_GCTL_PRTCAPDIR(0x01U)
#define USB_GCTL_PRTCAPDIR_DEVICE USB_GCTL_PRTCAPDIR(0x02U)
#define USB_GCTL_PRTCAPDIR_OTG USB_GCTL_PRTCAPDIR(0x03U)
#define USB_GCTL_PWRDNSCALE_SHIFT (19U)
#define USB_GCTL_PWRDNSCALE_MASK (0x1FFFFFU << USB_GCTL_PWRDNSCALE_SHIFT)
#define USB_GCTL_SCALEDOWN_SHIFT (4U)
#define USB_GCTL_SCALEDOWN_MASK (0x3U << USB_GCTL_SCALEDOWN_SHIFT)
#define USB_GCTL_CORESOFTRESET_MASK (1U << 11)
#define USB_GCTL_DISSCRAMBLE_MASK (1U << 3)
#define USB_GCTL_DSBLCLKGTNG_MASK (1U << 0)

#define USB_GHWPARAMS1 (*((volatile uint32_t *)(((uint64_t)(USB_GHWPARAMS1_OFFSET + (dwc3State->registerBase))))))
#define USB_GHWPARAMS1_DWC_USB3_DEVICE_NUM_INT_SHIFT (15)
#define USB_GHWPARAMS1_DWC_USB3_DEVICE_NUM_INT_MASK (0x3FU << USB_GHWPARAMS1_DWC_USB3_DEVICE_NUM_INT_SHIFT)
#define USB_GHWPARAMS1_DWC_USB3_EN_PWROPT_SHIFT (24)
#define USB_GHWPARAMS1_DWC_USB3_EN_PWROPT_MASK (0x3U << USB_GHWPARAMS1_DWC_USB3_EN_PWROPT_SHIFT)
#define USB_GHWPARAMS1_DWC_USB3_EN_PWROPT(n) ((n) << USB_GHWPARAMS1_DWC_USB3_EN_PWROPT_SHIFT)

#define USB_GHWPARAMS3 (*((volatile uint32_t *)(((uint64_t)(USB_GHWPARAMS3_OFFSET + (dwc3State->registerBase))))))
#define USB_GHWPARAMS3_DWC_USB3_NUM_EPS_SHIFT (12)
#define USB_GHWPARAMS3_DWC_USB3_NUM_EPS_MASK (0x3FU << USB_GHWPARAMS3_DWC_USB3_NUM_EPS_SHIFT)
#define USB_GHWPARAMS3_DWC_USB3_NUM_IN_EPS_SHIFT (18)
#define USB_GHWPARAMS3_DWC_USB3_NUM_IN_EPS_MASK (0x1FU << USB_GHWPARAMS3_DWC_USB3_NUM_IN_EPS_SHIFT)

#define USB_GUSB2PHYCFG(n) \
    (*((volatile uint32_t *)(((uint64_t)(USB_GUSB2PHYCFG_OFFSET(n) + (dwc3State->registerBase))))))
#define USB_GUSB2PHYCFG_PHYSOFTRST_MASK (1U << 31)

#define USB_GUSB3PIPECTL(n) \
    (*((volatile uint32_t *)(((uint64_t)(USB_GUSB3PIPECTL_OFFSET(n) + (dwc3State->registerBase))))))
#define USB_GUSB3PIPECTL_PHYSoftRst_MASK (1U << 31)

#define USB_GEVNTADRLO(n) (*((volatile uint32_t *)(((uint64_t)(USB_GEVNTADRLO_OFFSET(n) + (dwc3State->registerBase))))))
#define USB_GEVNTADRHI(n) (*((volatile uint32_t *)(((uint64_t)(USB_GEVNTADRHI_OFFSET(n) + (dwc3State->registerBase))))))
#define USB_GEVNTSIZ(n) (*((volatile uint32_t *)(((uint64_t)(USB_GEVNTSIZ_OFFSET(n) + (dwc3State->registerBase))))))
#define USB_GEVNTSIZ_EVENTSIZ_MASK (0xFFFFU)
#define USB_GEVNTSIZ_EVNTINTRPTMASK_MASK (1U << 31)
#define USB_GEVNTCOUNT(n) (*((volatile uint32_t *)(((uint64_t)(USB_GEVNTCOUNT_OFFSET(n) + (dwc3State->registerBase))))))
#define USB_GEVNTCOUNT_EVNTCOUNT_MASK (0xFFFFU)

#define USB_DCTL (*((volatile uint32_t *)(((uint64_t)(USB_DCTL_OFFSET + (dwc3State->registerBase))))))
#define USB_DCTL_RUN_STOP_MASK (1U << 31)
#define USB_DCTL_CSFTRST_MASK (1U << 30)
#define USB_DCTL_INITU1ENA_MASK (1U << 10)
#define USB_DCTL_INITU2ENA_MASK (1U << 12)
#define USB_DCTL_ULSTCHNGREQ_SHIFT (5U)
#define USB_DCTL_ULSTCHNGREQ_MASK (0xFU << USB_DCTL_ULSTCHNGREQ_SHIFT)
#define USB_DCTL_ULSTCHNGREQ(n) ((n) << USB_DCTL_ULSTCHNGREQ_SHIFT)
#define USB_DCTL_TSTCTL_MASK (0xFU << 1)

#define USB_DCFG (*((volatile uint32_t *)(((uint64_t)(USB_DCFG_OFFSET + (dwc3State->registerBase))))))
#define USB_DCFG_DEVADDR_SHIFT (3U)
#define USB_DCFG_DEVADDR_MASK (0x7FU << USB_DCFG_DEVADDR_SHIFT)
#define USB_DCFG_DEVADDR(n) ((n) << USB_DCFG_DEVADDR_SHIFT)
#define USB_DCFG_DEVSPD_MASK (0x7U << 0)
#define USB_DCFG_DEVSPD_SS (0x4U << 0)
#define USB_DCFG_DEVSPD_HS (0x0U << 0)

#define USB_DEVTEN (*((volatile uint32_t *)(((uint64_t)(USB_DEVTEN_OFFSET + (dwc3State->registerBase))))))
#define USB_DEVTEN_DISSCONNEVTEN_MASK (1U << 0)
#define USB_DEVTEN_USBRSTEVTEN_MASK (1U << 1)
#define USB_DEVTEN_CONNECTDONEEVTEN_MASK (1U << 2)
#define USB_DEVTEN_ULSTCNGEN_MASK (1U << 3)
#define USB_DEVTEN_WKUPEVTEN_MASK (1U << 4)
#define USB_DEVTEN_U3L2L1SuspEn_MASK (1U << 6)
#define USB_DEVTEN_SOFTEVTEN_MASK (1U << 7)
#define USB_DEVTEN_ERRTICERREVTEN_MASK (1U << 9)
#define USB_DEVTEN_VENDEVTSTRCVDEN_MASK (1U << 12)

#define USB_DSTS (*((volatile uint32_t *)(((uint64_t)(USB_DSTS_OFFSET + (dwc3State->registerBase))))))
#define USB_DSTS_DCNRD_MASK (1U << 29)
#define USB_DSTS_SRE_MASK (1U << 28)
#define USB_DSTS_RSS_MASK (1U << 25)
#define USB_DSTS_SSS_MASK (1U << 24)
#define USB_DSTS_COREIDLE_MASK (1U << 23)
#define USB_DSTS_DEVCTRLHLT_MASK (1U << 22)
#define USB_DSTS_USBLNKST_SHIFT (18)
#define USB_DSTS_USBLNKST_MASK (0xFU << USB_DSTS_USBLNKST_SHIFT)
#define USB_DSTS_USBLNKST(n) ((n) << USB_DSTS_USBLNKST_SHIFT)
#define USB_DSTS_RXFIFOEMPTY_MASK (1U << 17)
#define USB_DSTS_SOFFN_SHIFT (3)
#define USB_DSTS_SOFFN_MASK (0x3FFFU << USB_DSTS_SOFFN_SHIFT)
#define USB_DSTS_SOFFN(n) ((n) << USB_DSTS_SOFFN_SHIFT)
#define USB_DSTS_CONNECTSPD_SHIFT (0)
#define USB_DSTS_CONNECTSPD_MASK (0x7U << USB_DSTS_CONNECTSPD_SHIFT)
#define USB_DSTS_CONNECTSPD(n) ((n) << USB_DSTS_CONNECTSPD_SHIFT)
#define USB_DSTS_CONNECTSPD_SS (0x04U << USB_DSTS_CONNECTSPD_SHIFT)
#define USB_DSTS_CONNECTSPD_HS (0x00U << USB_DSTS_CONNECTSPD_SHIFT)
#define USB_DSTS_CONNECTSPD_FS_30MHz_60MHz (0x01U << USB_DSTS_CONNECTSPD_SHIFT)
#define USB_DSTS_CONNECTSPD_LS (0x02U << USB_DSTS_CONNECTSPD_SHIFT)
#define USB_DSTS_CONNECTSPD_FS_48MHz (0x03U << USB_DSTS_CONNECTSPD_SHIFT)

#define USB_DGCMDPAR (*((volatile uint32_t *)(((uint64_t)(USB_DGCMDPAR_OFFSET + (dwc3State->registerBase))))))

#define USB_DGCMD (*((volatile uint32_t *)(((uint64_t)(USB_DGCMD_OFFSET + (dwc3State->registerBase))))))
#define USB_DGCMD_CMDTYP_SHIFT (0U)
#define USB_DGCMD_CMDTYP_MASK (0xFFU << USB_DGCMD_CMDTYP_SHIFT)
#define USB_DGCMD_CMDTYP(n) ((n) << USB_DGCMD_CMDTYP_SHIFT)
#define USB_DGCMD_CMDACT_MASK (0x01U << 10)

#define USB_DEPCMDPAR2(n) (*((volatile uint32_t *)(((uint64_t)(USB_DEPCMDPAR2_OFFSET(n) + (dwc3State->registerBase))))))
#define USB_DEPCMDPAR1(n) (*((volatile uint32_t *)(((uint64_t)(USB_DEPCMDPAR1_OFFSET(n) + (dwc3State->registerBase))))))
#define USB_DEPCMDPAR0(n) (*((volatile uint32_t *)(((uint64_t)(USB_DEPCMDPAR0_OFFSET(n) + (dwc3State->registerBase))))))
#define USB_DEPCMD(n) (*((volatile uint32_t *)(((uint64_t)(USB_DEPCMD_OFFSET(n) + (dwc3State->registerBase))))))
#define USB_DEPCMD_COMMANDPARAM_SHIFT (16U)
#define USB_DEPCMD_COMMANDPARAM_MASK (0xFFFFU << USB_DEPCMD_COMMANDPARAM_SHIFT)
#define USB_DEPCMD_COMMANDPARAM(n) ((n) << USB_DEPCMD_COMMANDPARAM_SHIFT)
#define USB_DEPCMD_CMDSTATUS_SHIFT (12U)
#define USB_DEPCMD_CMDSTATUS_MASK (0x0FU << USB_DEPCMD_CMDSTATUS_SHIFT)
#define USB_DEPCMD_HIPRI_FORCERM_MASK (0x01U << 11)
#define USB_DEPCMD_CMDACT_MASK (0x01U << 10)
#define USB_DEPCMD_CMDIOC_MASK (0x01U << 8)
#define USB_DEPCMD_CMDTYP_SHIFT (0U)
#define USB_DEPCMD_CMDTYP_MASK (0xFU << USB_DEPCMD_CMDTYP_SHIFT)
#define USB_DEPCMD_CMDTYP(n) ((n) << USB_DEPCMD_CMDTYP_SHIFT)
#define USB_DEPCMD_CMDTYP_SET_ENDPOINT_CONFIGURATION USB_DEPCMD_CMDTYP(1U)
#define USB_DEPCMD_CMDTYP_SET_ENDPOINT_TRANSFER_RESOURCE_CONFIGURATION USB_DEPCMD_CMDTYP(2U)
#define USB_DEPCMD_CMDTYP_GET_ENDPOINT_STATE USB_DEPCMD_CMDTYP(3U)
#define USB_DEPCMD_CMDTYP_SET_ENDPOINT_STALL USB_DEPCMD_CMDTYP(4U)
#define USB_DEPCMD_CMDTYP_CLEAR_ENDPOINT_STALL USB_DEPCMD_CMDTYP(5U)
#define USB_DEPCMD_CMDTYP_START_TRANSFER USB_DEPCMD_CMDTYP(6U)
#define USB_DEPCMD_CMDTYP_UPDATE_TRANSFER USB_DEPCMD_CMDTYP(7U)
#define USB_DEPCMD_CMDTYP_END_TRANSFER USB_DEPCMD_CMDTYP(8U)
#define USB_DEPCMD_CMDTYP_START_NEW_CONFIGURATION USB_DEPCMD_CMDTYP(9U)

#define USB_DALEPENA (*((volatile uint32_t *)(((uint64_t)(USB_DALEPENA_OFFSET + (dwc3State->registerBase))))))

#define USB_OEVT (*((volatile uint32_t *)(((uint64_t)(USB_OEVT_OFFSET + (dwc3State->registerBase))))))

#define USB_OSTS (*((volatile uint32_t *)(((uint64_t)(USB_OSTS_OFFSET + (dwc3State->registerBase))))))

#define USB_EVENT_DEVICE_DISCONNECT_DETECTED (0U)
#define USB_EVENT_DEVICE_RESET (1U)
#define USB_EVENT_DEVICE_CONNECTION_DONE (2U)
#define USB_EVENT_DEVICE_LINK_STATE_CHANGE (3U)
#define USB_EVENT_DEVICE_RESEUM_DETECTED (4U)
#define USB_EVENT_DEVICE_HIBERNATION_REQUEST (5U)
#define USB_EVENT_DEVICE_SUSPEND_ENTRY (6U)
#define USB_EVENT_DEVICE_SOF (7U)
#define USB_EVENT_DEVICE_L1_SUSPEND (8U)
#define USB_EVENT_DEVICE_ERRATIC_ERROR (9U)
#define USB_EVENT_DEVICE_GENERIC_COMMAND_COMPLETE (0xAU)
#define USB_EVENT_DEVICE_EVENT_BUFFER_OVERFLOW (0xBU)
#define USB_EVENT_DEVICE_VENDOR_DEVICE_TEST_LPM_RECEIVED (0xCU)
#define USB_EVENT_DEVICE_STOPPED_ON_DISCONNECT (0xDU)
#define USB_EVENT_DEVICE_L1_RESEUM_DETECTED (0xEU)

#define USB_EVENT_ENDPOINT_XferComplete (0x01U)
#define USB_EVENT_ENDPOINT_XferInProgress (0x02U)
#define USB_EVENT_ENDPOINT_XferNotReady (0x03U)
#define USB_EVENT_ENDPOINT_StreamEvt (0x06U)
#define USB_EVENT_ENDPOINT_EPCmdCmplt (0x07U)

#define USB_TRB_TRBCTL_NORMAL (1U)
#define USB_TRB_TRBCTL_CONTROL_SETUP (2U)
#define USB_TRB_TRBCTL_CONTROL_STATUS2 (3U)
#define USB_TRB_TRBCTL_CONTROL_STATUS3 (4U)
#define USB_TRB_TRBCTL_CONTROL_DATA (5U)
#define USB_TRB_TRBCTL_CONTROL_ISO_FIRST (6U)
#define USB_TRB_TRBCTL_CONTROL_ISO (7U)
#define USB_TRB_TRBCTL_LINK_TRB (8U)
#define USB_TRB_TRBCTL_NORMAL_ZLP_FOR_BULK_IN (9U)

typedef struct _usb_device_dwc3_trb_struct
{
    volatile uint32_t BPTRL;
    volatile uint32_t BPTRH;
    union
    {
        volatile uint32_t status;
        struct
        {
            volatile uint32_t BUFSIZE : 24U;
            volatile uint32_t PCM1 : 2U;
            volatile uint32_t reserved1 : 2U;
            volatile uint32_t TRBSTS : 4U;
        };
    };
    union
    {
        volatile uint32_t control;
        struct
        {
            volatile uint32_t HWO : 1U;
            volatile uint32_t LST : 1U;
            volatile uint32_t CHN : 1U;
            volatile uint32_t CSP : 1U;
            volatile uint32_t TRBCTL : 6U;
            volatile uint32_t ISP_IMI : 1U;
            volatile uint32_t IOC : 1U;
            volatile uint32_t reserved2 : 2U;
            volatile uint32_t SID_SOF : 16U;
            volatile uint32_t reserved3 : 2U;
        };
    };
} usb_device_dwc3_trb_struct_t;

typedef union _usb_device_dwc3_ep_specific_command_struct
{
    struct
    {
        uint32_t parameter0;
        uint32_t parameter1;
        uint32_t parameter2;
        uint32_t commandCode;
        uint32_t index;
    } commandParmeter;
    struct
    {
        union
        {
            uint32_t parameter0;
            struct
            {
                uint32_t reserved1 : 1U;
                uint32_t endpointType : 2U;
                uint32_t maxPacketSize : 11U;
                uint32_t reserved2 : 3U;
                uint32_t fifoNumber : 5U;
                uint32_t burstSize : 4U;
                uint32_t reserved3 : 4U;
                uint32_t configAction : 2U;
            };
        };
        union
        {
            uint32_t parameter1;
            struct
            {
                uint32_t interruptNumber : 5U;
                uint32_t reserved4 : 3U;
                uint32_t eventEnableXferComplete : 1U;
                uint32_t eventEnableXferInProgress : 1U;
                uint32_t eventEnableXferNotReady : 1U;
                uint32_t eventEnableReserved1 : 1U;
                uint32_t eventEnableReserved2 : 1U;
                uint32_t eventEnableStream : 1U;
                uint32_t reserved5 : 1U;
                uint32_t externalBufferControlMode4BulkEp : 1U;
                uint32_t bInterval : 8U;
                uint32_t streamCapable : 1U;
                uint32_t endpointDirection : 1U;
                uint32_t endpointNumber : 4U;
                uint32_t bulkBased : 1U;
                uint32_t fifoBased : 1U;
            };
        };
        uint32_t reserved;
        uint32_t commandCode;
        uint32_t index;
    } DEPCFG;
} usb_device_dwc3_ep_specific_command_struct_t;

typedef union _usb_device_dwc3_event_struct
{
    volatile uint32_t event;
    struct
    {
        volatile uint32_t eventType : 1U;
        volatile uint32_t reserved : 31U;
    } commonState;
    struct
    {
        volatile uint32_t eventType : 1U;
        volatile uint32_t epNumber : 5U;
        volatile uint32_t transferResult : 4U;
        volatile uint32_t reserved : 2U;
        volatile uint32_t eventStatus : 4U;
        volatile uint32_t eventParam : 16U;
    } DEPEVT;
    struct
    {
        volatile uint32_t eventType : 1U;
        volatile uint32_t deviceSpecificEvent : 7U;
        volatile uint32_t deviceStatus : 4U;
        volatile uint32_t reserved : 4U;
        volatile uint32_t eventInfoBits : 9U;
        volatile uint32_t reserved2 : 7U;
    } DEVT;
} usb_device_dwc3_event_struct_t;

typedef struct _usb_device_dwc3_ep_state
{
    uint32_t interval;
    uint8_t *transferBuffer; /*!< Address of buffer containing the data to be transmitted */
    usb_device_dwc3_trb_struct_t *trb;
    uint32_t transferLength;       /*!< Length of data to transmit. */
    uint32_t transferDone;         /*!< The data length has been transferred*/
    uint32_t transferPrimedLength; /*!< The data length has been primed*/
    uint32_t currentFrame;         /*!< Current frame*/
    union
    {
        uint32_t state; /*!< The state of the endpoint */
        struct
        {
            uint32_t maxPacketSize : 11U;      /*!< The maximum packet size of the endpoint */
            uint32_t type : 2U;                /*!< the pipe type */
            uint32_t burst : 4U;               /*!< burst numbers */
            uint32_t configured : 1U;          /*!< whether is configured */
            uint32_t initialized : 1U;         /*!< whether is initialized */
            uint32_t stalled : 1U;             /*!< The endpoint is stalled or not */
            uint32_t transferring : 1U;        /*!< The endpoint is transferring */
            uint32_t transferPending : 1U;     /*!< The transfer of the endpoint is pending */
            uint32_t zlt : 1U;                 /*!< zlt flag */
            uint32_t resourceIndexNumber : 7U; /*!< Transfer Resource Index (XferRscIdx) */
            uint32_t streamCapable : 1U;       /*!< The ep is stream capable  */
            uint32_t need2Copy : 1U;           /*!< Whether need to do memory copy?  */
        } stateBitField;
    } stateUnion;
} usb_device_dwc3_ep_state_t;

enum
{
    USB_DEVICE_DWC3_CONTROL_PIPE_IDLE = 0,
    USB_DEVICE_DWC3_CONTROL_PIPE_SETUP_STAGE,
    USB_DEVICE_DWC3_CONTROL_PIPE_DATA_STAGE,
    USB_DEVICE_DWC3_CONTROL_PIPE_STATUS_STAGE,
};

/*! @brief dwc3 state structure */
typedef struct _usb_device_dwc3_state_struct
{
    usb_device_struct_t *deviceHandle; /*!< Device handle used to identify the device object is belonged to */
    uint64_t registerBase;             /*!< The base address of the register */
    usb_device_dwc3_ep_state_t endpointState[USB_DEVICE_CONFIG_ENDPOINTS * 2]; /*!< Endpoint state structures */
    uint8_t *eventBuffer;                                                      /*!< Current event index */
    uint8_t *endpointBuffer[USB_DEVICE_CONFIG_ENDPOINTS];           /*!< The ep buffer to fix max packet size issue */
    uint32_t currentEventIndex[USB_DEVICE_CONFIG_DWC3_EVENT_COUNT]; /*!< Current event index */
    uint8_t controlPipeWithData;                                    /*!< Whether the setup request has the data stage */
    uint8_t controlPipeStage;                                       /*!< The stage of the control pipe */
    uint8_t eventCount;                                             /*!< The event number of dwc3 */
    uint8_t endpointCount;                                          /*!< The endpoint number of dwc3 */
    uint8_t endpointInCount;                                        /*!< The IN endpoint number of dwc3 */
    uint8_t endpointOutCount;                                       /*!< The OUT endpoint number of dwc3 */
    uint8_t isResetting;                                            /*!< Whether a PORT reset is occurring or not  */
    uint8_t controllerId;                                           /*!< Controller ID */
    uint8_t speed;                                                  /*!< Current speed of dwc3 */
    uint8_t isConnected;                                            /*!< is connected */
    uint8_t setupPending; /*!< the setup of the control pipe is not completed */
    uint8_t isSuspending; /*!< Is suspending of the PORT */
} usb_device_dwc3_state_struct_t;

#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @name USB device dwc3 functions
 * @{
 */

/*******************************************************************************
 * API
 ******************************************************************************/

/*!
 * @brief Initializes the USB device dwc3 instance.
 *
 * This function initializes the USB device dwc3 module specified by the controllerId.
 *
 * @param[in] controllerId The controller ID of the USB IP. See the enumeration type usb_controller_index_t.
 * @param[in] handle        Pointer of the device handle used to identify the device object is belonged to.
 * @param[out] dwc3Handle   An out parameter used to return the pointer of the device dwc3 handle to the caller.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceDwc3Init(uint8_t controllerId,
                                usb_device_handle handle,
                                usb_device_controller_handle *dwc3Handle);

/*!
 * @brief Deinitializes the USB device dwc3 instance.
 *
 * This function deinitializes the USB device dwc3 module.
 *
 * @param[in] dwc3Handle   Pointer of the device dwc3 handle.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceDwc3Deinit(usb_device_controller_handle dwc3Handle);

/*!
 * @brief Sends data through a specified endpoint.
 *
 * This function sends data through a specified endpoint.
 *
 * @param[in] dwc3Handle      Pointer of the device dwc3 handle.
 * @param[in] endpointAddress Endpoint index.
 * @param[in] buffer           The memory address to hold the data need to be sent.
 * @param[in] length           The data length to be sent.
 *
 * @return A USB error code or kStatus_USB_Success.
 *
 * @note The return value means whether the sending request is successful or not. The transfer completion is indicated
 * by the
 * corresponding callback function.
 * Currently, only one transfer request can be supported for a specific endpoint.
 * If there is a specific requirement to support multiple transfer requests for a specific endpoint, the application
 * should implement a queue in the application level.
 * The subsequent transfer can begin only when the previous transfer is done (a notification is received through the
 * endpoint
 * callback).
 */
usb_status_t USB_DeviceDwc3Send(usb_device_controller_handle dwc3Handle,
                                uint8_t endpointAddress,
                                uint8_t *buffer,
                                uint32_t length);

/*!
 * @brief Receive data through a specified endpoint.
 *
 * This function Receives data through a specified endpoint.
 *
 * @param[in] dwc3Handle      Pointer of the device dwc3 handle.
 * @param[in] endpointAddress Endpoint index.
 * @param[in] buffer           The memory address to save the received data.
 * @param[in] length           The data length want to be received.
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
                                uint32_t length);

/*!
 * @brief Cancels the pending transfer in a specified endpoint.
 *
 * The function is used to cancel the pending transfer in a specified endpoint.
 *
 * @param[in] dwc3Handle      Pointer of the device dwc3 handle.
 * @param[in] ep               Endpoint address, bit7 is the direction of endpoint, 1U - IN, 0U - OUT.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceDwc3Cancel(usb_device_controller_handle dwc3Handle, uint8_t ep);

/*!
 * @brief Controls the status of the selected item.
 *
 * The function is used to control the status of the selected item.
 *
 * @param[in] dwc3Handle      Pointer of the device dwc3 handle.
 * @param[in] type             The selected item. See enumeration type usb_device_control_type_t.
 * @param[in,out] param            The parameter type is determined by the selected item.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceDwc3Control(usb_device_controller_handle dwc3Handle,
                                   usb_device_control_type_t type,
                                   void *param);

/*! @} */

#if defined(__cplusplus)
}
#endif

/*! @} */

#endif /* __USB_DEVICE_dwc3_H__ */
