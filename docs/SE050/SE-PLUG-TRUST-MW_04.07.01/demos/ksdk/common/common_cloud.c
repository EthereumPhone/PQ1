/*
 * Copyright 2023 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "sss_pkcs11_pal.h"

#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"

#if SSS_HAVE_MBEDTLS_ALT
#include "mbedtls/ssl.h"
#endif

/* ************************************************************************** */
/* Structures                                                                 */
/* ************************************************************************** */

typedef struct _object_identifiers
{
    uint32_t identifier[16];
    size_t indentifier_len;
    int groupId;
    char *name;
} object_identifiers_t;

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#if SSS_HAVE_MBEDTLS_ALT
static mbedtls_ecp_group_id curve_list[16] = {
    0,
};
#endif // SSS_HAVE_MBEDTLS_ALT

SemaphoreHandle_t xSemaphore;

static object_identifiers_t object_identifiers[] = {
    {{1, 2, 840, 10045, 3, 1, 1}, 7, MBEDTLS_ECP_DP_SECP192R1, "MBEDTLS_ECP_DP_SECP192R1"},
    {{1, 3, 132, 0, 33}, 5, MBEDTLS_ECP_DP_SECP224R1, "MBEDTLS_ECP_DP_SECP224R1"},
    {{1, 2, 840, 10045, 3, 1, 7}, 7, MBEDTLS_ECP_DP_SECP256R1, "MBEDTLS_ECP_DP_SECP256R1"},
    {{1, 3, 132, 0, 34}, 5, MBEDTLS_ECP_DP_SECP384R1, "MBEDTLS_ECP_DP_SECP384R1"},
    {{1, 3, 132, 0, 35}, 5, MBEDTLS_ECP_DP_SECP521R1, "MBEDTLS_ECP_DP_SECP521R1"},

    {{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}, 10, MBEDTLS_ECP_DP_BP256R1, "MBEDTLS_ECP_DP_BP256R1"},
    {{1, 3, 24, 3, 3, 2, 8, 1, 1, 7}, 10, MBEDTLS_ECP_DP_BP256R1, "MBEDTLS_ECP_DP_BP256R1"},
    {{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}, 10, MBEDTLS_ECP_DP_BP384R1, "MBEDTLS_ECP_DP_BP384R1"},
    {{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}, 10, MBEDTLS_ECP_DP_BP512R1, "MBEDTLS_ECP_DP_BP512R1"},

    {{1, 3, 132, 0, 31}, 5, MBEDTLS_ECP_DP_SECP192K1, "MBEDTLS_ECP_DP_SECP192K1"},
    {{1, 3, 132, 0, 32}, 5, MBEDTLS_ECP_DP_SECP224K1, "MBEDTLS_ECP_DP_SECP224K1"},
    {{1, 3, 132, 0, 10}, 5, MBEDTLS_ECP_DP_SECP256K1, "MBEDTLS_ECP_DP_SECP256K1"},
    {
        {
            0,
        },
        0,
        0,
    },
};

#if SSS_HAVE_MBEDTLS_ALT
// int mbedtls_ssl_set_curve_list(mbedtls_ssl_config *conf, const char * pcLabelName)
int mbedtls_ssl_set_curve_list(mbedtls_ssl_config *conf, uint32_t keyIndex)
{
    sss_status_t status    = kStatus_SSS_Fail;
    sss_object_t clientKey = {
        0,
    };
    uint32_t objectId[16] = {
        0,
    };
    uint8_t objectIdLen = sizeof(objectId);
    int i               = 0;
    size_t compareLen   = 0;
    // uint32_t keyIndex = 0;
    // LabelToKeyId((unsigned char*)pcLabelName, strlen(pcLabelName), &keyIndex);

    // printf(" \n\n%s\n\n", __FUNCTION__);
    //LOCK_MUTEX_FOR_RTOS
    {
        status = sss_key_object_init(&clientKey, &pex_sss_demo_boot_ctx->ks);
        if (status != kStatus_SSS_Success) {
            //UNLOCK_MUTEX_FOR_RTOS_RET(kStatus_SSS_Fail);
            return 1;
        }

        status = sss_key_object_get_handle(&clientKey, keyIndex);
        if (status != kStatus_SSS_Success) {
            //UNLOCK_MUTEX_FOR_RTOS_RET(kStatus_SSS_Fail);
            return 1;
        }

        status = sss_util_asn1_get_oid_from_sssObj(&clientKey, objectId, &objectIdLen);
        if (status != kStatus_SSS_Success) {
            //UNLOCK_MUTEX_FOR_RTOS_RET(1);
            return 1;
        }

        //UNLOCK_MUTEX_FOR_RTOS
    }
    while (1) {
        if (object_identifiers[i].indentifier_len == 0) {
            break;
        }

        if (object_identifiers[i].indentifier_len != objectIdLen) {
            i++;
            continue;
        }

        if (objectIdLen * sizeof(uint32_t) > 64) {
            compareLen = 64;
        }
        else {
            compareLen = objectIdLen * sizeof(uint32_t);
        }
        if (0 == memcmp(object_identifiers[i].identifier, objectId, compareLen)) {
            curve_list[0] = object_identifiers[i].groupId;
            curve_list[1] = MBEDTLS_ECP_DP_NONE;
            mbedtls_ssl_conf_curves(conf, curve_list);
            return 0;
        }

        i++;
    }

    return 1;
}

#endif // SSS_HAVE_MBEDTLS_ALT