/*
* Copyright 2020,2021 NXP
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __SE05X_READ_W_ATTST_H__
#define __SE05X_READ_W_ATTST_H__

/*Usage of pre-provisioned attestation key as per Variants*/
#if SSS_HAVE_APPLET_SE05X_B && SSS_HAVE_SE05X_VER_03_XX
#define ATTESTATION_KEY_ID 0xF0000010
#define KEY_BIT_LEN 2048
#else
#define ATTESTATION_KEY_ID 0xF0000012
#define KEY_BIT_LEN 256
#endif

#define OBJECT_KEY_ID 0xF5EFFA

#include <fsl_sss_api.h>
#include <stdint.h>

#define OBJECT_TO_ATTEST                                                                                            \
    {                                                                                                               \
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, \
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F                      \
    }

SE05x_SecObjTyp_t obj_Binary = kSE05x_SecObjTyp_BINARY_FILE;

#endif //__SE05X_READ_W_ATTST_H__