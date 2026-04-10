/*
 * FreeRTOS version 202107.00-LTS
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */


/**
 * @brief Header file containing platform abstraction layer APIS for OTA update.
 */

#ifndef FLASH_PARTITIONING_H
#define FLASH_PARTITIONING_H

/** Flash device type enabled */
#define ISSI_IS25WPxxxA

/* Total Flash Size */
#define COMPONENT_FLASHIAP_SIZE    8388608

/* MCU Flash layout. */
#define BOOT_FLASH_BASE            0x60000000
#define BOOT_FLASH_ACT_APP         0x60040000
#define BOOT_FLASH_CAND_APP        0x60240000


/* Offsets for each image slots used for OTA. */
#define FLASH_AREA_IMAGE_1_OFFSET    ( BOOT_FLASH_ACT_APP - BOOT_FLASH_BASE )     /*MCUboot occupies 512KB */
#define FLASH_AREA_IMAGE_1_SIZE      ( BOOT_FLASH_CAND_APP - BOOT_FLASH_ACT_APP ) /*image1 slot occupies 2MB */
#define FLASH_AREA_IMAGE_2_OFFSET    ( FLASH_AREA_IMAGE_1_OFFSET + FLASH_AREA_IMAGE_1_SIZE )
#define FLASH_AREA_IMAGE_2_SIZE      FLASH_AREA_IMAGE_1_SIZE                      /*image2 slot occupies 2MB */
#define FLASH_AREA_IMAGE_3_OFFSET    ( FLASH_AREA_IMAGE_2_OFFSET + FLASH_AREA_IMAGE_2_SIZE )
#define FLASH_AREA_IMAGE_3_SIZE      0x80000                                      /* scratch slot occupies 512KB */


#endif /* FLASH_PARTITIONING_H */
