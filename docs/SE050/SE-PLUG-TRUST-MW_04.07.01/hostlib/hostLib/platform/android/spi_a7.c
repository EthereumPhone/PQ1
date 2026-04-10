/****************************************************************************
 *   Description:
 *     iMX UL board specific i2c code
 *
 ****************************************************************************
 * Copyright 2016 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/
#include "spi_a7.h"
#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>

#include <time.h>

// #define LOG_SPI 1

static int axSmDevice;

static unsigned char devName[20] = "/dev/spidev0.0";

static U8 spiMode = SPI_MODE_1;
static U8 spiBits = 8;
static U32 spiSpeed = 2000000;
static U16 spiDelay = 0;

/**
* @function       spiA7Init
* @description    Opens the communication channel to a7 device
*/
int spiA7Init(void)
{
    /*
     * Open the file (device handle)
     */
    printf("SpiInit: opening %s\n", devName);

    if ((axSmDevice = open((char*)devName, O_RDWR)) < 0) {

        printf("SpiInit: Opening %s failed...\n", devName);

        /* ERROR HANDLING: you can check errno to see what went wrong */
        perror("Failed to open the spi bus");
        return SPI_A7_DEV_OPEN_FAILED;
    }

    // SPI mode
    printf("SPI: mode=0x%02X\n", spiMode);
    if (ioctl(axSmDevice, SPI_IOC_WR_MODE, &spiMode) < 0)
    {
        printf("SPI: Failed setting spi mode.\n");
        return SPI_A7_SET_MODE_FAILED;
    }

    // bits per word
    if (ioctl(axSmDevice, SPI_IOC_WR_BITS_PER_WORD, &spiBits) < 0)
    {
        printf("SPI: Failed setting bits per word.\n");
        return SPI_A7_SET_BITS_FAILED;
    }

    // max speed in Hz
    if (ioctl(axSmDevice, SPI_IOC_WR_MAX_SPEED_HZ, &spiSpeed) < 0)
    {
        printf("SPI: Can't set max speed hz");
        return SPI_A7_SET_MAX_SPEED_FAILED;
    }

    return SPI_A7_INIT_OK;
}

int spiTransfer(U8 *txBuf, U8 *rxBuf, U16 txLen)
{
    int ret;
    struct spi_ioc_transfer tr = {
        .tx_buf = (unsigned long)txBuf,
        .rx_buf = (unsigned long)rxBuf,
        .len = txLen,
        .delay_usecs = spiDelay,
        .speed_hz = spiSpeed,
        .bits_per_word = spiBits,
    };

#ifdef LOG_SPI
    if (txBuf != NULL)
    {
        printf("spiTransfer (Tx): ");
        for (ret = 0; ret < txLen; ret++) {
            if (!(ret % 16))
                puts("");
            printf("%.2X ", txBuf[ret]);
        }
        puts("");
    }
#endif

    ret = ioctl(axSmDevice, SPI_IOC_MESSAGE(1), &tr);
    if (ret < 1)
    {
        perror("Can't send spi message");
        return SPI_A7_TRANSFER_FAILED;
    }

#ifdef LOG_SPI
    if (rxBuf != NULL)
    {
        printf("spiTransfer (Rx): ");
        for (ret = 0; ret < txLen; ret++) {
            if (!(ret % 16))
                puts("");
            printf("%.2X ", rxBuf[ret]);
        }
        puts("");
    }
#endif
    return SPI_A7_TRANSFER_OK;
}

/******************************************************************************
 **                            End Of File
 ******************************************************************************/
