/*
* Copyright 2020 NXP
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __IMPORT_EXT_OBJ_PREPARE__
#define __IMPORT_EXT_OBJ_PREPARE__

#include "fsl_sss_api.h"
#include "se05x_enums.h"

#define INTERNAL_AUTH_PK_TEE_ECKA_TAG \
    {                                 \
        0x7F, 0x49                    \
    }
#define INTERNAL_AUTH_PK_TEE_ECKA_SIG_TAG \
    {                                     \
        0x5F, 0x37                        \
    }
#define SE_ECKA_PUB_OBJID kSE05x_AppletResID_KP_ECKEY_IMPORT

uint32_t ecdsa_auth_id = 0x0;

/* clang-format off */
#define ECKEY_PARAMS { 0xA6, 0x1D, 0x4F, 0x10, 0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, \
0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x90, 0x03, 0xAB, 0x01, \
0x33, 0x80, 0x01, 0x88, 0x81, 0x01, 0x10,   \
}
/* clang-format on */

uint8_t WriteSymmKeyAPDU[1024] = {0};
/* clang-format on */
size_t WriteSymmKeyAPDU_len = sizeof(WriteSymmKeyAPDU);

/* TEE ECKA KeyPair */
sss_object_t sk_tee_ecka_obj = {0};
uint8_t hostEckakey[1024]    = {0};
size_t hostEckakey_len       = sizeof(hostEckakey);

/* SE ECKA Public key */
sss_object_t se_ecka_pub_obj      = {0};
sss_object_t se_ecka_pub_host_obj = {0};
uint8_t se_ecka_pub[256]          = {0};
size_t se_ecka_pub_len            = sizeof(se_ecka_pub);

/* Host ECDSA Keypair */
sss_object_t hostECDSAkey_object = {0};
uint8_t hostEcdsakey[1024]       = {0};
size_t hostEcdsakey_len          = sizeof(hostEcdsakey);

/* Shared Secret */
sss_object_t shsSecret = {0};
uint8_t sharedSecret[32];
size_t sharedSecretLen = sizeof(shsSecret);

/* Master Secret */
sss_object_t masterSec = {0};
uint8_t masterSk[32];
size_t masterSkLen = sizeof(masterSk);

sss_object_t enc_obj  = {0};
sss_object_t mac_obj  = {0};
sss_object_t rmac_obj = {0};
uint8_t iniMacChaining[16];
uint8_t ObjectMAC[16] = {0};
/* clang-format off */
const uint8_t commandCounter[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
/* clang-format on */

#endif //__IMPORT_EXT_OBJ_PREPARE__
