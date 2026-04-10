/**
 * @file app_boot_nfc.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Implementation of the App booting time initilization functions
 */

#ifdef SMCOM_PN7150

#include <nxLog_app.h>
#include "sm_types.h"

#if AX_EMBEDDED
#include "board.h"
#include "pin_mux.h"
#include "fsl_gpio.h"
#endif /* FREEDOM */

#include <Nfc.h>
#include "tml_config.h"


/* Discovery loop configuration according to the targeted modes of operation */
unsigned char DiscoveryTechnologies[] = {

    MODE_POLL | TECH_PASSIVE_NFCA,

};

/* Mode configuration according to the targeted modes of operation */
unsigned mode = 0
#ifdef CARDEMU_SUPPORT
                | NXPNCI_MODE_CARDEMU
#endif // ifdef P2P_SUPPORT
#ifdef P2P_SUPPORT
                | NXPNCI_MODE_P2P
#endif // ifdef CARDEMU_SUPPORT
#ifdef RW_SUPPORT
                | NXPNCI_MODE_RW
#endif // ifdef RW_SUPPORT
    ;

void app_boot_pinConfig_NFC() {
    /*Pin Config for IRQ and VEN*/
    gpio_pin_config_t irq_config = {
        kGPIO_DigitalInput,
        0,
    };
    gpio_pin_config_t ven_config = {
        kGPIO_DigitalOutput,
        0,
    };

    GPIO_PinInit(NXPNCI_IRQ_GPIO, NXPNCI_IRQ_PIN, &irq_config);
    GPIO_PinInit(NXPNCI_VEN_GPIO, NXPNCI_VEN_PIN, &ven_config);
}

void StartDiscovery(void)
{
    NxpNci_RfIntf_t RfInterface;

    /* Open connection to NXPNCI device */
    if (NxpNci_Connect() == NFC_ERROR) {
        LOG_E("Error: cannot connect to NXPNCI device\n");
        return;
    }

    if (NxpNci_ConfigureSettings() == NFC_ERROR) {
        LOG_E("Error: cannot configure NXPNCI settings\n");
        return;
    }

    if (NxpNci_ConfigureMode(mode) == NFC_ERROR) {
        LOG_E("Error: cannot configure NXPNCI\n");
        return;
    }

    /* Start Discovery */
    if (NxpNci_StartDiscovery(DiscoveryTechnologies, sizeof(DiscoveryTechnologies)) != NFC_SUCCESS) {
        LOG_E("Error: cannot start discovery\n");
        return;
    }

    //while(1)
    {
        LOG_I("\nWAITING FOR DEVICE DISCOVERY\n");

        /* Wait until a peer is discovered */
        while (NxpNci_WaitForDiscoveryNotification(&RfInterface) != NFC_SUCCESS)
            ;

#ifdef CARDEMU_SUPPORT
        /* Is activated from remote T4T ? */
        if ((RfInterface.Interface == INTF_ISODEP) && ((RfInterface.ModeTech & MODE_MASK) == MODE_LISTEN)) {
            printf(" - LISTEN MODE: Activated from remote Reader\n");
#ifndef CARDEMU_RAW_EXCHANGE
            NxpNci_ProcessCardMode(RfInterface);
#else
            PICC_ISO14443_4_scenario();
#endif
            printf("READER DISCONNECTED\n");
        }
        else
#endif

#ifdef P2P_SUPPORT
            /* Is activated from remote T4T ? */
            if (RfInterface.Interface == INTF_NFCDEP) {
            if ((RfInterface.ModeTech & MODE_LISTEN) == MODE_LISTEN)
                printf(" - P2P TARGET MODE: Activated from remote Initiator\n");
            else
                printf(" - P2P INITIATOR MODE: Remote Target activated\n");

            /* Process with SNEP for NDEF exchange */
            NxpNci_ProcessP2pMode(RfInterface);

            printf("PEER LOST\n");
        }
        else
#endif // if defined P2P_SUPPORT
#ifdef RW_SUPPORT
            if ((RfInterface.ModeTech & MODE_MASK) == MODE_POLL) {
            //task_nfc_reader(RfInterface);
        }
        else
#endif // if defined RW_SUPPORT
        {
            LOG_I("WRONG DISCOVERY\n");
        }
    }
    LOG_I("DISCOVERY DONE\n");
}

#endif /* SMCOM_PN7150 */
