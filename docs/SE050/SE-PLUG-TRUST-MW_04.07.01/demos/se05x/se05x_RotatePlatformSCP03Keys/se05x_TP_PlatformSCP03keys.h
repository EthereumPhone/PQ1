/* Copyright 2019,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <nxEnsure.h>
#include <string.h>

#include "ex_sss_boot.h"
#include "se05x_APDU.h"
/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */
#define PUT_KEYS_KEY_TYPE_CODING_AES 0x88
#define CRYPTO_KEY_CHECK_LEN 0x03
#define GP_CLA_BYTE 0x80
#define GP_INS_PUTKEY 0xD8
#define GP_P2_MULTIPLEKEYS 0x81

sss_status_t ex_scp03_keys_from_path(uint8_t *pdek, size_t *dek_len);
