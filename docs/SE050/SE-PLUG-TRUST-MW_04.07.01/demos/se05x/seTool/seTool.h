/* Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ex_sss_objid.h>

#define MAX_FILE_NAME_SIZE 255

/* Private part prefix specific for 256-bit NIST-p curve */
#define PRIV_PREFIX_NIST_P_256                                                                                      \
    {                                                                                                               \
        0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00                                                                \
    }

/* Magic bytes for OpenSSL engine */
#define MAGIC_BYTES_SE05X_OPENSSL_ENGINE               \
    {                                                  \
        0xA5, 0xA6, 0xB5, 0xB6, 0xA5, 0xA6, 0xB5, 0xB6 \
    }

/* Public part prefix specific for 256-bit NIST-p curve */
#define PUBLIC_PREFIX_NIST_P_256                                                           \
    {                                                                                      \
        0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0xA1, 0x44 \
    }
