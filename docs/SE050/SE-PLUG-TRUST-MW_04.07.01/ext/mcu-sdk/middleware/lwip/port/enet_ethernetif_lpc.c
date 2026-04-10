/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

/*
 * Copyright (c) 2013-2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2023 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/sys.h"
#include "lwip/ethip6.h"
#include "netif/etharp.h"
#include "netif/ppp/pppoe.h"
#include "lwip/igmp.h"
#include "lwip/mld6.h"

#if !NO_SYS
#include "FreeRTOS.h"
#include "event_groups.h"
#include "lwip/tcpip.h"
#endif /* !NO_SYS */

#include "board.h"

#include "ethernetif.h"
#include "ethernetif_priv.h"

#include "fsl_enet.h"
#include "fsl_phy.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#if defined(FSL_SDK_ENABLE_DRIVER_CACHE_CONTROL) && FSL_SDK_ENABLE_DRIVER_CACHE_CONTROL
#if defined(FSL_FEATURE_L2CACHE_LINESIZE_BYTE) && \
    ((!defined(FSL_SDK_DISBLE_L2CACHE_PRESENT)) || (FSL_SDK_DISBLE_L2CACHE_PRESENT == 0))
#if defined(FSL_FEATURE_L1DCACHE_LINESIZE_BYTE)
#define FSL_CACHE_LINESIZE_MAX  MAX(FSL_FEATURE_L1DCACHE_LINESIZE_BYTE, FSL_FEATURE_L2CACHE_LINESIZE_BYTE)
#define FSL_ENET_BUFF_ALIGNMENT MAX(ENET_BUFF_ALIGNMENT, FSL_CACHE_LINESIZE_MAX)
#else
#define FSL_ENET_BUFF_ALIGNMENT MAX(ENET_BUFF_ALIGNMENT, FSL_FEATURE_L2CACHE_LINESIZE_BYTE)
#endif
#elif defined(FSL_FEATURE_L1DCACHE_LINESIZE_BYTE)
#define FSL_ENET_BUFF_ALIGNMENT MAX(ENET_BUFF_ALIGNMENT, FSL_FEATURE_L1DCACHE_LINESIZE_BYTE)
#else
#define FSL_ENET_BUFF_ALIGNMENT ENET_BUFF_ALIGNMENT
#endif
#else
#define FSL_ENET_BUFF_ALIGNMENT ENET_BUFF_ALIGNMENT
#endif

#if MEM_ALIGNMENT != FSL_ENET_BUFF_ALIGNMENT
/* These two has to match for zero-copy functionality */
#error "MEM_ALIGNMENT != FSL_ENET_BUFF_ALIGNMENT"
#endif /* MEM_ALIGNMENT != FSL_ENET_BUFF_ALIGNMENT */

#ifndef ENET_RXBD_NUM
#define ENET_RXBD_NUM (5)
#endif

#ifndef ENET_TXBD_NUM
#define ENET_TXBD_NUM (5)
#endif

/* The maximum length of lwIP frame to transmit. */
#define MAX_TX_FRAMELEN (ENET_FRAME_MAX_FRAMELEN - ENET_FCS_LEN)

#ifndef ENET_RXBUFF_SIZE
#define ENET_RXBUFF_SIZE (ENET_FRAME_MAX_FRAMELEN + ETH_PAD_SIZE)
#endif

#define USABLE_RXBUFF_SIZE (CONSTANT_SIZEALIGN(ENET_RXBUFF_SIZE, FSL_ENET_BUFF_ALIGNMENT))

/* The number of ENET buffers needed to receive frame of maximum length. */
#define MAX_BUFFERS_PER_FRAME                                            \
    (((ENET_FRAME_MAX_FRAMELEN + ETH_PAD_SIZE) / (USABLE_RXBUFF_SIZE)) + \
     (((ENET_FRAME_MAX_FRAMELEN + ETH_PAD_SIZE) % USABLE_RXBUFF_SIZE == 0) ? 0 : 1))

#if ETH_PAD_SIZE && (USABLE_RXBUFF_SIZE < (ENET_FRAME_MAX_FRAMELEN + ETH_PAD_SIZE))
#warning \
    "Padding is used, but RX buffer size cannot fit frame of maximum length plus padding. \
The behavior can be undefined."
#endif

/* Ring should be able to receive at least 1 frame with maximum length. */
#if ENET_RXBD_NUM < MAX_BUFFERS_PER_FRAME
#error "ENET_RXBD_NUM < MAX_BUFFERS_PER_FRAME"
#endif

/* The number of RX buffers. ENET_RXBD_NUM is always held by ENET driver,
 * so a couple more are needed to pass zero-copy data into lwIP. */
#ifndef ENET_RXBUFF_NUM
#define ENET_RXBUFF_NUM (ENET_RXBD_NUM * 2)
#endif

/* At least ENET_RXBD_NUM number of buffers is always held by ENET driver for RX.
 * Some additional buffers are needed to pass at least one frame zero-copy data to lwIP. */
#if ENET_RXBUFF_NUM < (ENET_RXBD_NUM + MAX_BUFFERS_PER_FRAME)
#error "ENET_RXBUFF_NUM < (ENET_RXBD_NUM + MAX_BUFFERS_PER_FRAME)"
#endif

typedef struct mem_range
{
    uint32_t start;
    uint32_t end;
} mem_range_t;

/* Configured memory regions not usable by ENET DMA. */
#ifndef BOARD_ENET_NON_DMA_MEMORY_ARRAY
#warning \
    "BOARD_ENET_NON_DMA_MEMORY_ARRAY is not set in board.h or on a command line. \
LwIP transmit over ethernet will not use zero-copy."
/* The following default will make it work without zero-copy for TX: */
#define BOARD_ENET_NON_DMA_MEMORY_ARRAY                         \
    {                                                           \
        {0x00000000U, 0xFFFFFFFFU}, {0x00000000U, 0x00000000U}, \
    }
#endif /* BOARD_ENET_NON_DMA_MEMORY_ARRAY */

#include "enet_configchecks.h"

#define ENET_HW_CHKSUM (CHECKSUM_GEN_IP == 0)

typedef uint8_t rx_buffer_t[SDK_SIZEALIGN(ETH_PAD_SIZE, FSL_ENET_BUFF_ALIGNMENT) +
                            SDK_SIZEALIGN(ENET_RXBUFF_SIZE, FSL_ENET_BUFF_ALIGNMENT)];

/*!
 * @brief Used to wrap received data in a pbuf to be passed into lwIP
 *        without copying.
 * Once last reference is released, buffer can be used by ENET RX DMA again.
 */
typedef struct rx_pbuf_wrapper
{
    struct pbuf_custom p;      /*!< Pbuf wrapper. Has to be first. */
    void *buffer;              /*!< Original buffer wrapped by p. */
    volatile bool buffer_used; /*!< Wrapped buffer is used by ENET or lwIP. */
    struct netif *netif;       /*!< Network interface context data. */
} rx_pbuf_wrapper_t;

/*!
 * @brief Helper struct to hold private data used to operate
 *        your ethernet interface.
 */
struct ethernetif
{
    ENET_Type *base;
    enet_handle_t handle;
#if !NO_SYS
    EventGroupHandle_t enetTransmitAccessEvent;
    EventBits_t txFlag;
#endif /* !NO_SYS */
    enet_rx_bd_struct_t *RxBuffDescrip;
    enet_tx_bd_struct_t *TxBuffDescrip;
    enet_tx_reclaim_info_t txDirty[ENET_TXBD_NUM];
    uint32_t rxBufferStartAddr[ENET_RXBD_NUM];
    rx_buffer_t *RxDataBuff;
    rx_pbuf_wrapper_t rxPbufs[ENET_RXBUFF_NUM];
    phy_handle_t *phyHandle;
    phy_speed_t last_speed;
    phy_duplex_t last_duplex;
    bool last_link_up;

    uint32_t intGpioHdl[((HAL_GPIO_HANDLE_SIZE + sizeof(uint32_t) - 1U) / sizeof(uint32_t))];
};

static void ethernetif_tx_release(struct pbuf *p);
static void ethernetif_rx_release(struct pbuf *p);

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*!
 * @brief Memory regions which cannot be accessed by DMA.
 */
static const mem_range_t s_non_dma_memory[] = BOARD_ENET_NON_DMA_MEMORY_ARRAY;

/*******************************************************************************
 * Code
 ******************************************************************************/

/**
 * Called from ENET ISR.
 */
static void ethernet_callback(ENET_Type *base,
                              enet_handle_t *handle,
                              enet_event_t event,
                              uint8_t channel,
                              enet_tx_reclaim_info_t *txReclaimInfo,
                              void *userData)
#if NO_SYS
{
    if (event == kENET_TxIntEvent)
    {
        ethernetif_tx_release((struct pbuf *)txReclaimInfo->context);
    }
}
#else
{
    struct netif *netif           = (struct netif *)userData;
    struct ethernetif *ethernetif = netif->state;
    BaseType_t xResult;

    switch (event)
    {
        case kENET_RxIntEvent:
            ethernetif_input(netif);
            break;
        case kENET_TxIntEvent:
        {
            portBASE_TYPE taskToWake = pdFALSE;

            ethernetif_tx_release((struct pbuf *)txReclaimInfo->context);

#ifdef __CA7_REV
            if (SystemGetIRQNestingLevel())
#else
            if (__get_IPSR())
#endif
            {
                xResult =
                    xEventGroupSetBitsFromISR(ethernetif->enetTransmitAccessEvent, ethernetif->txFlag, &taskToWake);
                if ((pdPASS == xResult) && (pdTRUE == taskToWake))
                {
                    portYIELD_FROM_ISR(taskToWake);
                }
            }
            else
            {
                xEventGroupSetBits(ethernetif->enetTransmitAccessEvent, ethernetif->txFlag);
            }

            break;
        }
        default:
            break;
    }
}
#endif /* NO_SYS */

#if LWIP_IPV4 && LWIP_IGMP
err_t ethernetif_igmp_mac_filter(struct netif *netif, const ip4_addr_t *group, enum netif_mac_filter_action action)
{
    struct ethernetif *ethernetif = netif->state;
    err_t result;

    switch (action)
    {
        case IGMP_ADD_MAC_FILTER:
            /* LPC ENET does not accept multicast selectively,
             * so all multicast has to be passed through. */
            ENET_AcceptAllMulticast(ethernetif->base);
            result = ERR_OK;
            break;
        case IGMP_DEL_MAC_FILTER:
            /*
             * Moves the ENET device from a multicast group.
             * Since we don't keep track of which multicast groups
             * are still to enabled, the call is commented out.
             */
            /* ENET_RejectAllMulticast(ethernetif->base); */
            result = ERR_OK;
            break;
        default:
            result = ERR_IF;
            break;
    }

    return result;
}
#endif

#if LWIP_IPV6 && LWIP_IPV6_MLD
err_t ethernetif_mld_mac_filter(struct netif *netif, const ip6_addr_t *group, enum netif_mac_filter_action action)
{
    struct ethernetif *ethernetif = netif->state;
    err_t result;

    switch (action)
    {
        case NETIF_ADD_MAC_FILTER:
            /* LPC ENET does not accept multicast selectively,
             * so all multicast has to be passed through. */
            ENET_AcceptAllMulticast(ethernetif->base);
            result = ERR_OK;
            break;
        case NETIF_DEL_MAC_FILTER:
            /*
             * Moves the ENET device from a multicast group.
             * Since we don't keep track of which multicast groups
             * are still to enabled, the call is commented out.
             */
            /* ENET_RejectAllMulticast(ethernetif->base); */
            result = ERR_OK;
            break;
        default:
            result = ERR_IF;
            break;
    }

    return result;
}
#endif

/**
 * Gets the RX descriptor by its index.
 */
static inline enet_rx_bd_struct_t *ethernetif_get_rx_desc(struct ethernetif *ethernetif, uint32_t index)
{
    return &(ethernetif->RxBuffDescrip[index]);
}

/**
 * Gets the TX descriptor by its index.
 */
static inline enet_tx_bd_struct_t *ethernetif_get_tx_desc(struct ethernetif *ethernetif, uint32_t index)
{
    return &(ethernetif->TxBuffDescrip[index]);
}

/**
 * Callback to acquire RX zero-copy buffer for ENET driver.
 */
static void *ethernetif_rx_alloc(ENET_Type *base, void *userData, uint8_t ringId)
{
    struct netif *netif           = (struct netif *)userData;
    struct ethernetif *ethernetif = netif->state;
    uint8_t *buffer               = NULL;
    int i;
    (void)ringId;

    SYS_ARCH_DECL_PROTECT(old_level);
    SYS_ARCH_PROTECT(old_level);

    for (i = 0; i < ENET_RXBUFF_NUM; i++)
    {
        if (!ethernetif->rxPbufs[i].buffer_used)
        {
            ethernetif->rxPbufs[i].buffer_used = true;
            buffer                             = (uint8_t *)&ethernetif->RxDataBuff[i];
            buffer += ETH_PAD_SIZE;

            break;
        }
    }

#if ENET_DISABLE_RX_INT_WHEN_OUT_OF_BUFFERS
    if (buffer == NULL)
    {
        ENET_DisableInterrupts(base, (uint32_t)kENET_DmaRx);
    }
#else
    (void)base;
#endif
    SYS_ARCH_UNPROTECT(old_level);

    return (void *)buffer;
}

static inline void ethernetif_release_rx_wrapper(rx_pbuf_wrapper_t *wrapper)
{
    SYS_ARCH_DECL_PROTECT(old_level);
    SYS_ARCH_PROTECT(old_level);

    LWIP_ASSERT("ethernetif_release_rx_wrapper: freeing unallocated buffer", wrapper->buffer_used);
    wrapper->buffer_used = false;

#if ENET_DISABLE_RX_INT_WHEN_OUT_OF_BUFFERS
    ENET_EnableInterrupts(((struct ethernetif *)wrapper->netif->state)->base, (uint32_t)kENET_DmaRx);
#endif

    SYS_ARCH_UNPROTECT(old_level);
}

/**
 * Callback for release of RX zero-copy buffer from ENET driver.
 */
static void ethernetif_rx_free(ENET_Type *base, void *buffer, void *userData, uint8_t ringId)
{
    struct netif *netif           = (struct netif *)userData;
    struct ethernetif *ethernetif = netif->state;
    uint8_t *bufferAddr           = ((uint8_t *)buffer) - ETH_PAD_SIZE;
    int idx                       = ((rx_buffer_t *)bufferAddr) - ethernetif->RxDataBuff;
    (void)ringId;
    (void)base;

    LWIP_ASSERT("Freed buffer out of range", ((idx >= 0) && (idx < ENET_RXBUFF_NUM)));
    LWIP_ASSERT("bufferAddr not pointing to RxDataBuff array",
                (uint8_t *)bufferAddr == (uint8_t *)&(ethernetif->RxDataBuff[idx][0]));

    ethernetif_release_rx_wrapper(&ethernetif->rxPbufs[idx]);
}

/**
 * Initializes ENET driver.
 */
void ethernetif_plat_init(struct netif *netif,
                          struct ethernetif *ethernetif,
                          const ethernetif_config_t *ethernetifConfig)
{
    enet_config_t config;
    enet_buffer_config_t buffCfg[ETHERNETIF_RING_NUM];
    uint32_t i;
    status_t status;

    /* prepare the buffer configuration. */
    buffCfg[0].rxRingLen = ENET_RXBD_NUM;                  /* The length of receive buffer descriptor ring. */
    buffCfg[0].txRingLen = ENET_TXBD_NUM;                  /* The length of transmit buffer descriptor ring. */
    buffCfg[0].txDescStartAddrAlign =
        ethernetif_get_tx_desc(ethernetif, 0U);            /* Aligned transmit descriptor start address. */
    buffCfg[0].txDescTailAddrAlign =
        ethernetif_get_tx_desc(ethernetif, 0U);            /* Aligned transmit descriptor tail address. */
    buffCfg[0].txDirtyStartAddr = &ethernetif->txDirty[0]; /* Start address of the dirty tx frame information. */
    buffCfg[0].rxDescStartAddrAlign =
        ethernetif_get_rx_desc(ethernetif, 0U);            /* Aligned receive descriptor start address. */
    buffCfg[0].rxDescTailAddrAlign =
        ethernetif_get_rx_desc(ethernetif, ENET_RXBD_NUM); /* Aligned receive descriptor tail address. */
    buffCfg[0].rxBufferStartAddr = &ethernetif->rxBufferStartAddr[0]; /* Holds addresses of the rx buffers. */
    buffCfg[0].rxBuffSizeAlign =
        SDK_SIZEALIGN(ENET_RXBUFF_SIZE, FSL_ENET_BUFF_ALIGNMENT);     /* Aligned receive data buffer size. */

    ENET_GetDefaultConfig(&config);
    config.multiqueueCfg = NULL;
    config.rxBuffAlloc   = ethernetif_rx_alloc;
    config.rxBuffFree    = ethernetif_rx_free;

#if ENET_HW_CHKSUM == 1
    config.specialControl |= kENET_RxChecksumOffloadEnable;
#endif

    /* Used for detection of change.
       Initilize to value different than any possible enum value. */
    ethernetif->last_speed   = (phy_speed_t)0xa5a5;
    ethernetif->last_duplex  = (phy_duplex_t)0x5a5a;
    ethernetif->last_link_up = false;

    ethernetif_phy_init(ethernetif, ethernetifConfig);

#if NO_SYS
    config.interrupt = kENET_DmaTx;
#else
    config.interrupt = kENET_DmaTx | kENET_DmaRx;

    /* Create the Event for transmit busy release trigger. */
    ethernetif->enetTransmitAccessEvent = xEventGroupCreate();
    ethernetif->txFlag                  = 0x1;
#endif /* NO_SYS */
    NVIC_SetPriority(ETHERNET_IRQn, ENET_PRIORITY);

    for (i = 0; i < ENET_RXBUFF_NUM; i++)
    {
        ethernetif->rxPbufs[i].p.custom_free_function = ethernetif_rx_release;
        ethernetif->rxPbufs[i].buffer                 = &(ethernetif->RxDataBuff[i][0]);
        ethernetif->rxPbufs[i].buffer_used            = false;
        ethernetif->rxPbufs[i].netif                  = netif;
    }

    ENET_Init(ethernetif->base, &config, netif->hwaddr, ethernetifConfig->srcClockHz);

    status = ENET_DescriptorInit(ethernetif->base, &config, &buffCfg[0]);
    LWIP_ASSERT("ENET_DescriptorInit() failed", status == kStatus_Success);

#if defined(LPC54018_SERIES)
    /* Workaround for receive issue on lpc54018 */
    ethernetif->base->MAC_FRAME_FILTER |= ENET_MAC_FRAME_FILTER_RA_MASK;
#endif

    /* Create the handler. */
    ENET_CreateHandler(ethernetif->base, &ethernetif->handle, &config, &buffCfg[0], ethernet_callback, netif);

    status = ENET_RxBufferAllocAll(ethernetif->base, &ethernetif->handle);
    LWIP_ASSERT("ENET_RxBufferAllocAll() failed", status == kStatus_Success);

    /* Active TX/RX. */
    ENET_StartRxTx(ethernetif->base, 1, 1);
}

phy_handle_t *ethernetif_get_phy(struct netif *netif_)
{
    struct ethernetif *eif = netif_->state;
    return eif->phyHandle;
}

hal_gpio_handle_t ethernetif_get_int_gpio_hdl(struct netif *netif_)
{
    struct ethernetif *eif = netif_->state;
    return (hal_gpio_handle_t)eif->intGpioHdl;
}

phy_speed_t ethernetif_get_link_speed(struct netif *netif_)
{
    struct ethernetif *eif = netif_->state;
    return eif->last_speed;
}

phy_duplex_t ethernetif_get_link_duplex(struct netif *netif_)
{
    struct ethernetif *eif = netif_->state;
    return eif->last_duplex;
}

void ethernetif_on_link_up(struct netif *netif_, phy_speed_t speed, phy_duplex_t duplex)
{
    struct ethernetif *eif = netif_->state;

    if (!eif->last_link_up || (speed != eif->last_speed) || (duplex != eif->last_duplex))
    {
        ENET_SetMII(eif->base, (enet_mii_speed_t)speed, (enet_mii_duplex_t)duplex);
        eif->last_speed   = speed;
        eif->last_duplex  = duplex;
        eif->last_link_up = true;
    }
}

void ethernetif_on_link_down(struct netif *netif_)
{
    struct ethernetif *eif = netif_->state;
    eif->last_link_up      = false;
}

void **ethernetif_base_ptr(struct ethernetif *ethernetif)
{
    return (void **)&(ethernetif->base);
}

/**
 * Reclaims pbuf after its data has been sent out.
 */
static void ethernetif_tx_release(struct pbuf *p)
{
#if NO_SYS && !LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT
#error "Bare metal requires LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT=1 because pbuf_free() is being called from an ISR"
#endif /* NO_SYS && !LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT */

    if (p == NULL)
    {
        return;
    }

#if ETH_PAD_SIZE
    /* Reclaim the padding, force because it may be REF pbuf. */
    pbuf_header_force(p, ETH_PAD_SIZE);
#endif

    ethernetif_pbuf_free_safe(p);
}

/**
 * Reclaims RX pbuf.
 */
static void ethernetif_rx_release(struct pbuf *p)
{
    rx_pbuf_wrapper_t *wrapper = (rx_pbuf_wrapper_t *)p;

    ethernetif_release_rx_wrapper(wrapper);
}

/** Wraps received buffer(s) into a pbuf or a pbuf chain and returns it. */
static struct pbuf *ethernetif_rx_frame_to_pbufs(struct ethernetif *ethernetif, enet_rx_frame_struct_t *rxFrame)
{
    void *buffer;
    uint16_t bufferLength;
#if ETH_PAD_SIZE
    uint16_t paddingAdjust = 0U;
#endif
    rx_pbuf_wrapper_t *wrapper;
    uint16_t len   = 0U;
    struct pbuf *p = NULL;
    struct pbuf *q = NULL;
    int idx;
    int i;

    for (i = 0; ((i < MAX_BUFFERS_PER_FRAME) && (len < rxFrame->totLen)); i++)
    {
        buffer       = rxFrame->rxBuffArray[i].buffer;
        bufferLength = rxFrame->rxBuffArray[i].length;

        /* Find pbuf wrapper for the actually read byte buffer */
        idx = ((rx_buffer_t *)(((uint8_t *)buffer) - ETH_PAD_SIZE)) - ethernetif->RxDataBuff;
        LWIP_ASSERT("Buffer returned by ENET_GetRxFrame() doesn't match any RX buffer descriptor",
                    ((idx >= 0) && (idx < ENET_RXBUFF_NUM)));
        wrapper = &ethernetif->rxPbufs[idx];
        LWIP_ASSERT("Buffer returned by ENET_GetRxFrame() doesn't match wrapper buffer",
                    wrapper->buffer == ((void *)(((uint8_t *)buffer) - ETH_PAD_SIZE)));
        LWIP_ASSERT("buffer returned by ENET is not marked as used by ENET/lwIP", wrapper->buffer_used);

        /* Wrap the received buffer in pbuf. */
        if (p == NULL)
        {
#if ETH_PAD_SIZE
            if (rxFrame->totLen > (SDK_SIZEALIGN(ENET_RXBUFF_SIZE, FSL_ENET_BUFF_ALIGNMENT) - ETH_PAD_SIZE))
            {
                /* Since we are receiving at non-aligned position, the data of up to ETH_PAD_SIZE will overflow
                 * to the next buffer, before the ETH_PAD_SIZE offset. Therefore we trim this buffer
                 * and we add the length to the last buffer later. */
                paddingAdjust =
                    bufferLength - (SDK_SIZEALIGN(ENET_RXBUFF_SIZE, FSL_ENET_BUFF_ALIGNMENT) - ETH_PAD_SIZE);
                bufferLength = (SDK_SIZEALIGN(ENET_RXBUFF_SIZE, FSL_ENET_BUFF_ALIGNMENT) - ETH_PAD_SIZE);
            }
#endif
            p = pbuf_alloced_custom(PBUF_RAW, bufferLength, PBUF_REF, &wrapper->p, buffer, bufferLength);
            LWIP_ASSERT("pbuf_alloced_custom() failed", p);
#if ETH_PAD_SIZE
            /* Add the padding header, force because it is a REF type buffer. */
            pbuf_header_force(p, ETH_PAD_SIZE);
#endif
        }
        else
        {
#if ETH_PAD_SIZE
            /* When padding is used, bytes before non-aligned start position contain data which did not fit
             * into the previous buffer (no matter if it directly precedes the current buffer in memory or not).
             * Therefore the start of the buffer is corrected back to the aligned position. */
            buffer = wrapper->buffer;

            if ((rxFrame->totLen - len) <= SDK_SIZEALIGN(ENET_RXBUFF_SIZE, FSL_ENET_BUFF_ALIGNMENT))
            {
                /* Last buffer, add legth missing in the first buffer */
                bufferLength += paddingAdjust;
            }
            else
            {
                /* This buffer must already be adjusted for the bytes missing from first buffer's length.
                 * Remaining byte(s) will be in the next buffer. */
                paddingAdjust -= SDK_SIZEALIGN(ENET_RXBUFF_SIZE, FSL_ENET_BUFF_ALIGNMENT) - bufferLength;
                bufferLength = SDK_SIZEALIGN(ENET_RXBUFF_SIZE, FSL_ENET_BUFF_ALIGNMENT);
            }
#endif
            q = pbuf_alloced_custom(PBUF_RAW, bufferLength, PBUF_REF, &wrapper->p, buffer, bufferLength);
            LWIP_ASSERT("pbuf_alloced_custom() failed", q);

            pbuf_cat(p, q);
        }

        len += bufferLength;
    }

    LWIP_ASSERT("p->tot_len != (rxFrame->totLen + ETH_PAD_SIZE)", p->tot_len == (rxFrame->totLen + ETH_PAD_SIZE));

    MIB2_STATS_NETIF_ADD(netif, ifinoctets, p->tot_len);
    if (((u8_t *)p->payload)[0] & 1)
    {
        /* broadcast or multicast packet */
        MIB2_STATS_NETIF_INC(netif, ifinnucastpkts);
    }
    else
    {
        /* unicast packet */
        MIB2_STATS_NETIF_INC(netif, ifinucastpkts);
    }

    LINK_STATS_INC(link.recv);

    return p;
}

/**
 * Attempts to read a frame from ENET and returns it wrapped in a pbuf
 * or returns NULL when no frame is received. Discards invalid frames.
 */
struct pbuf *ethernetif_linkinput(struct netif *netif)
{
    struct ethernetif *ethernetif                       = netif->state;
    enet_buffer_struct_t buffers[MAX_BUFFERS_PER_FRAME] = {{0}};
    enet_rx_frame_struct_t rxFrame                      = {.rxBuffArray = &buffers[0]};
    struct pbuf *p                                      = NULL;
    status_t status;

    /* Read frame. */
    status = ENET_GetRxFrame(ethernetif->base, &ethernetif->handle, &rxFrame, 0);

    switch (status)
    {
        case kStatus_Success:
            /* Frame read, process it into pbufs. */
            p = ethernetif_rx_frame_to_pbufs(ethernetif, &rxFrame);
            break;

        case kStatus_ENET_RxFrameEmpty:
            /* Frame not available. */
            break;

        case kStatus_ENET_RxFrameError:
            /* Error receiving frame */
            LWIP_DEBUGF(NETIF_DEBUG, ("ethernetif_linkinput: RxFrameError\n"));
            LINK_STATS_INC(link.drop);
            MIB2_STATS_NETIF_INC(netif, ifindiscards);
            break;

        case kStatus_ENET_RxFrameDrop:
            /* Frame received, but it had to be dropped
             * because new buffer(s) allocation failed in the ENET driver. */
            LINK_STATS_INC(link.drop);
            MIB2_STATS_NETIF_INC(netif, ifindiscards);
            break;

        default:
            LWIP_ASSERT("Unhandled return value.", 0);
            break;
    }

    return p;
}

/**
 * Attempts to output a frame from ENET. The function avoids copying of
 * p's payload when possible. In such situation it increases p's reference count
 * and decreases it (and possibly releases p) after the payload is sent.
 */
err_t ethernetif_linkoutput(struct netif *netif, struct pbuf *p)
{
    struct ethernetif *ethernetif = netif->state;
    struct pbuf *q;
    struct pbuf *p_copy;
    uint16_t len;
    uint16_t clen;
    bool copy = false;
    const mem_range_t *non_dma_memory;
    err_t err;
    uint32_t cnt = 0U;
    enet_buffer_struct_t txBuffArray[ENET_TXBD_NUM * 2];
    enet_tx_frame_struct_t txFrame = {
        .txBuffArray        = &txBuffArray[0],
        .txBuffNum          = 0U,
        .txConfig.intEnable = 1U,
        .txConfig.tsEnable  = 0U,
        .txConfig.slotNum   = 0U,
        .context            = NULL,
    };
    status_t result;

#if ENET_HW_CHKSUM == 1
    txFrame.txConfig.txOffloadOps = kENET_TxOffloadAll;
#endif

    LWIP_ASSERT("Output packet buffer empty", p);

    if ((p->tot_len - ETH_PAD_SIZE) > MAX_TX_FRAMELEN)
    {
        return ERR_BUF;
    }

    /* Check if relocation is needed */

    len  = 0U;
    clen = 0U;

    for (q = p; (q != NULL) && (len < p->tot_len); q = q->next)
    {
        /*
         * Check if payload is aligned is not desired: lwIP creates RAM pbufs
         * in a way that the data coming after the headers are aligned, but not
         * the beginning of the ethernet header. LPC ENET DMA will read from
         * the aligned address, which is ok, because there is additional space
         * before the headers to make up for alignment - so DMA will not read
         * from invalid address or unrelated data.
         */

        /* Check payload address is usable by ENET DMA */
        for (non_dma_memory = s_non_dma_memory;
             (!copy) && ((non_dma_memory->start != 0U) || (non_dma_memory->end != 0U)); non_dma_memory++)
        {
            if ((q->payload >= (void *)non_dma_memory->start) && (q->payload <= (void *)non_dma_memory->end))
            {
                copy = true;
            }
        }

        /*
         * Count the length of pbuf chain of first packet.
         * Don't count it using pbuf_clen, since it could count pbufs of the entire packet queue,
         * not only the first packet chain.
         */
        clen++;

        /* Track the length of first packet, so we can ignore the rest of packet queue. */
        len += q->len;
    }

    if (clen > (ENET_TXBD_NUM * 2U))
    {
        /*
         * Pbuf chain is too long to be prepared for DMA at once.
         * Each LPC ENET TX descriptor allows to set up to two buffers to be sent.
         */
        copy = true;
    }

    if (copy)
    {
        /* Pbuf needs to be copied. */

        p_copy = pbuf_alloc(PBUF_RAW, (uint16_t)p->tot_len, PBUF_POOL);
        if (p_copy == NULL)
        {
            return ERR_MEM;
        }

        clen = pbuf_clen(p_copy);
        if (clen > (ENET_TXBD_NUM * 2U))
        {
            /* Could happen when PBUF_POOL_BUFSIZE is small. */
            ethernetif_pbuf_free_safe(p_copy);
            return ERR_IF;
        }

        err = pbuf_copy(p_copy, p);
        if (err != ERR_OK)
        {
            ethernetif_pbuf_free_safe(p_copy);
            return ERR_IF;
        }

        p = p_copy;
    }
    else
    {
        /*
         * Increase reference count so p is released only after it is sent.
         * For copied pbuf, ref is already 1 after pbuf_alloc().
         */
        pbuf_ref(p);
    }

#if ETH_PAD_SIZE
    /* Drop the padding. */
    pbuf_header(p, -ETH_PAD_SIZE);
#endif

    /* Prepare transfer info. */
    txFrame.context = p;

    for (q = p; (q != NULL) && (clen > 0U); q = q->next)
    {
        txBuffArray[txFrame.txBuffNum].buffer = q->payload;
        txBuffArray[txFrame.txBuffNum].length = q->len;
        txFrame.txBuffNum++;
        clen--;
    }

    /* Queue frame for transmit. */
    do
    {
        result = ENET_SendFrame(ethernetif->base, &ethernetif->handle, &txFrame, 0U);

        if (result == kStatus_ENET_TxFrameBusy)
        {
#if !NO_SYS
            xEventGroupWaitBits(ethernetif->enetTransmitAccessEvent, ethernetif->txFlag, pdTRUE, (BaseType_t) false,
                                portMAX_DELAY);
#endif /* !NO_SYS */
            cnt++;
            if (cnt >= ETHERNETIF_TIMEOUT)
            {
                ethernetif_pbuf_free_safe(p);
                return ERR_TIMEOUT;
            }
        }
        else if (result != kStatus_Success)
        {
            ethernetif_pbuf_free_safe(p);
            return ERR_IF;
        }
    } while (result != kStatus_Success);

    if (((uint8_t *)p->payload)[0] & 1)
    {
        /* broadcast or multicast packet */
        MIB2_STATS_NETIF_INC(netif, ifoutnucastpkts);
    }
    else
    {
        /* unicast packet */
        MIB2_STATS_NETIF_INC(netif, ifoutucastpkts);
    }

    /* Increment statistics counters accordingly. */
    if (result != ERR_OK)
    {
        LINK_STATS_INC(link.err);
        MIB2_STATS_NETIF_INC(netif, ifouterrors);
    }
    else
    {
        LINK_STATS_INC(link.xmit);
        MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p->tot_len);
    }

    return ERR_OK;
}

/**
 * Should be called at the beginning of the program to set up the
 * first network interface. It calls the function ethernetif_init() to do the
 * actual setup of the hardware.
 *
 * This function should be passed as a parameter to netif_add().
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @return ERR_OK if the loopif is initialized
 *         ERR_MEM if private data couldn't be allocated
 *         any other err_t on error
 */
err_t ethernetif0_init(struct netif *netif)
{
    static struct ethernetif ethernetif_0;
    AT_NONCACHEABLE_SECTION_ALIGN(static enet_rx_bd_struct_t rxBuffDescrip_0[ENET_RXBD_NUM], FSL_ENET_BUFF_ALIGNMENT);
    AT_NONCACHEABLE_SECTION_ALIGN(static enet_tx_bd_struct_t txBuffDescrip_0[ENET_TXBD_NUM], FSL_ENET_BUFF_ALIGNMENT);
    SDK_ALIGN(static rx_buffer_t rxDataBuff_0[ENET_RXBUFF_NUM], FSL_ENET_BUFF_ALIGNMENT);

    ethernetif_config_t *cfg = (ethernetif_config_t *)netif->state;

    ethernetif_0.RxBuffDescrip = &(rxBuffDescrip_0[0]);
    ethernetif_0.TxBuffDescrip = &(txBuffDescrip_0[0]);
    ethernetif_0.RxDataBuff    = &(rxDataBuff_0[0]);

    ethernetif_0.phyHandle = cfg->phyHandle;

    return ethernetif_init(netif, &ethernetif_0, ethernetif_get_enet_base(0U), cfg);
}

#if defined(FSL_FEATURE_SOC_LPC_ENET_COUNT) && (FSL_FEATURE_SOC_LPC_ENET_COUNT > 1)
/**
 * Should be called at the beginning of the program to set up the
 * second network interface. It calls the function ethernetif_init() to do the
 * actual setup of the hardware.
 *
 * This function should be passed as a parameter to netif_add().
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @return ERR_OK if the loopif is initialized
 *         ERR_MEM if private data couldn't be allocated
 *         any other err_t on error
 */
err_t ethernetif1_init(struct netif *netif)
{
    static struct ethernetif ethernetif_1;
    AT_NONCACHEABLE_SECTION_ALIGN(static enet_rx_bd_struct_t rxBuffDescrip_1[ENET_RXBD_NUM], FSL_ENET_BUFF_ALIGNMENT);
    AT_NONCACHEABLE_SECTION_ALIGN(static enet_tx_bd_struct_t txBuffDescrip_1[ENET_TXBD_NUM], FSL_ENET_BUFF_ALIGNMENT);
    SDK_ALIGN(static rx_buffer_t rxDataBuff_1[ENET_RXBUFF_NUM], FSL_ENET_BUFF_ALIGNMENT);

    ethernetif_config_t *cfg = (ethernetif_config_t *)netif->state;

    ethernetif_1.RxBuffDescrip = &(rxBuffDescrip_1[0]);
    ethernetif_1.TxBuffDescrip = &(txBuffDescrip_1[0]);
    ethernetif_1.RxDataBuff    = &(rxDataBuff_1[0]);

    ethernetif_1.phyHandle = cfg->phyHandle;

    return ethernetif_init(netif, &ethernetif_1, ethernetif_get_enet_base(1U), cfg);
}
#endif /* FSL_FEATURE_SOC_*_ENET_COUNT */
