/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __PUF_PAIR_S_H__
#define __PUF_PAIR_S_H__

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <ex_sss_scp03_keys.h>
#include <ex_scp03_puf.h>

#define PUF_INTRINSIC_KEY_SIZE 16
/* Platform SCP03 Key Version no */
#define PF_KEY_VERSION_NO 0x0B

#define AES_KEY_LEN_nBYTE 0x10
#define PUT_KEYS_KEY_TYPE_CODING_AES 0x88
#define CRYPTO_KEY_CHECK_LEN 0x03
#define GP_CLA_BYTE 0x80
#define GP_INS_PUTKEY 0xD8
#define GP_P2_MULTIPLEKEYS 0x81

#define ORIG_EX_SSS_AUTH_SE05X_KEY_ENC SSS_AUTH_KEY_ENC

#define ORIG_EX_SSS_AUTH_SE05X_KEY_MAC SSS_AUTH_KEY_MAC

#define ORIG_EX_SSS_AUTH_SE05X_KEY_DEK SSS_AUTH_KEY_DEK

uint8_t activationCode[] = ACTIVATION_CODE_TESTING_LOCAL;

/* Key codes for PUF Index 1 */
uint8_t keyCodeENC_01[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)] = {0};
uint8_t keyCodeMAC_01[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)] = {0};
uint8_t keyCodeDEK_01[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)] = {0};

/* Old default SCP03 keys from SE05x dev kit */
uint8_t _OLD_KEY_ENC[] = ORIG_EX_SSS_AUTH_SE05X_KEY_ENC;
uint8_t _OLD_KEY_MAC[] = ORIG_EX_SSS_AUTH_SE05X_KEY_MAC;
uint8_t _OLD_KEY_DEK[] = ORIG_EX_SSS_AUTH_SE05X_KEY_DEK;

#endif // __PUF_PAIR_S_H__