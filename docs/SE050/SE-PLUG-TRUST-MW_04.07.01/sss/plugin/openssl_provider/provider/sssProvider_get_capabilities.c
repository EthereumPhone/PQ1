/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2024 NXP
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 *
 * OpenSSL Provider implementation to get capabilities for TLS
 *
 */

/* ********************** Include files ********************** */
#include "sssProvider_main.h"
#include <openssl/prov_ssl.h>
#include <string.h>

/* ********************** Constants ************************** */
#define OSSL_TLS_GROUP_ID_secp256r1 0x0017
#define OSSL_TLS_GROUP_ID_secp521r1 0x0019
#define OSSL_TLS_GROUP_ID_secp384r1 0x0018
#define OSSL_TLS_GROUP_ID_secp224k1 0x0014
#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

typedef struct tls_group_constants_st
{
    unsigned int group_id; /* Group ID */
    unsigned int secbits;  /* Bits of security */
    int mintls;            /* Minimum TLS version, -1 unsupported */
    int maxtls;            /* Maximum TLS version (or 0 for undefined) */
    int mindtls;           /* Minimum DTLS version, -1 unsupported */
    int maxdtls;           /* Maximum DTLS version (or 0 for undefined) */
} TLS_GROUP_CONSTANTS;

static const TLS_GROUP_CONSTANTS tls_group_list[] = {
    {OSSL_TLS_GROUP_ID_secp256r1, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0},
    {OSSL_TLS_GROUP_ID_secp384r1, 192, TLS1_VERSION, 0, DTLS1_VERSION, 0},
    {OSSL_TLS_GROUP_ID_secp521r1, 256, TLS1_VERSION, 0, DTLS1_VERSION, 0},
    {OSSL_TLS_GROUP_ID_secp224k1, 112, TLS1_VERSION, TLS1_2_VERSION, DTLS1_VERSION, DTLS1_2_VERSION},

};

#define TLS_GROUP_ENTRY(tlsname, realname, algorithm, idx)                                                          \
    {                                                                                                               \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, tlsname, sizeof(tlsname)),                           \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, realname, sizeof(realname)),            \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, algorithm, sizeof(algorithm)),                    \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, (unsigned int *)&tls_group_list[idx].group_id),           \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, (unsigned int *)&tls_group_list[idx].secbits), \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, (unsigned int *)&tls_group_list[idx].mintls),         \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, (unsigned int *)&tls_group_list[idx].maxtls),         \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, (unsigned int *)&tls_group_list[idx].mindtls),       \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, (unsigned int *)&tls_group_list[idx].maxdtls),       \
            OSSL_PARAM_END                                                                                          \
    }

static const OSSL_PARAM tls_param_group_list[][10] = {
    TLS_GROUP_ENTRY("secp256r1", "prime256v1", "EC", 0),
    TLS_GROUP_ENTRY("P-256", "prime256v1", "EC", 0), /* Alias of above */
    TLS_GROUP_ENTRY("secp384r1", "secp384r1", "EC", 1),
    TLS_GROUP_ENTRY("secp521r1", "secp521r1", "EC", 2),
    TLS_GROUP_ENTRY("P-521", "secp521r1", "EC", 2), /* Alias of above */
    TLS_GROUP_ENTRY("secp224k1", "secp224k1", "EC", 3),
};

int sss_get_capabilities(const OSSL_PROVIDER *prov, const char *capability, OSSL_CALLBACK *cb, void *arg)
{
    long unsigned int i;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(prov);
    if (OPENSSL_strcasecmp(capability, "TLS-GROUP") != 0)
        return 0;
    for (i = 0; i < OSSL_NELEM(tls_param_group_list); i++)
        if (!cb(tls_param_group_list[i], arg))
            return 0;

    return 1;
}