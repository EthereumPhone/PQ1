/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <nxEnsure.h>
#include <nxLog_App.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "mfa_utils.h"
#include "smCom.h"
#include "sm_apdu.h"
#ifdef SMCOM_JRCP_V2
#include <smComJRCP.h>
#endif

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

void initialise_allocate_key_object(sss_object_t *Key,
    sss_key_store_t *ks,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options)
{
    sss_status_t status;
    status = sss_key_object_init(Key, ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_D("Allocating KeyID=%Xh(%d) type=%d in %d",
        keyId,
        keyId,
        cipherType,
        ks->session->subsystem);

    status = sss_key_object_allocate_handle(
        Key, keyId, keyPart, cipherType, keyByteLenMax, options);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    return;
cleanup:
    LOG_E("Failurein initialise_allocate_key_object");
}

/* This Function will initialise, allocate and set the key in keystore,
for one sss_object in provided key store*/
void tst_asymm_alloc_and_set_key(sss_object_t *keyObject,
    sss_key_store_t *ks,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    uint32_t keyId,
    const uint8_t *key,
    size_t keyByteLen,
    size_t keyBitLen,
    uint32_t options)
{
    sss_status_t status;

    /*
     * KeyPair -> RSA_CRT       -> >=2048
     * Public  -> RSA, RSA_CRT  -> >=2048
     */
    if (cipherType == kSSS_CipherType_RSA ||
        cipherType == kSSS_CipherType_RSA_CRT) {
        if (keyBitLen < 2048) {
            LOG_W("Can not inject RSA <2048 in FIPS Mode");
        }
        if ((keyPart == kSSS_KeyPart_Pair || keyPart == kSSS_KeyPart_Private) &&
            cipherType == kSSS_CipherType_RSA) {
            LOG_W("Can not inject Plain RSA in FIPS Mode");
        }
    }
    if (keyBitLen < 224 && keyPart != kSSS_KeyPart_Default) {
        LOG_W("No SECP192R1 in FIPS Mode");
    }
    if (cipherType == kSSS_CipherType_EC_TWISTED_ED ||
        cipherType == kSSS_CipherType_EC_MONTGOMERY ) {
        LOG_W("Curve not supported in FIPS Mode");
    }

    initialise_allocate_key_object(
        keyObject, ks, keyId, keyPart, cipherType, keyByteLen, options);

    status = sss_key_store_set_key(
        ks, keyObject, key, keyByteLen, keyBitLen, NULL, 0);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    return;
cleanup:
    LOG_E("ERROR in Alloc and Set Key");
    return;
}

void printSEMSLiteStatusCode(sems_lite_status_t sems_lite_status)
{
    switch (sems_lite_status) {
    case kStatus_SEMS_Lite_Success:
        printf("SEMS Lite Status: SUCCESS");
        break;
    case kStatus_SEMS_Lite_ERR_General:
        printf("SEMS Lite Status: FAILED");
        break;
    case kStatus_SEMS_Lite_ERR_COM:
        printf("SEMS Lite Status: COMMUNICATION FAILED");
        break;
    case kStatus_SEMS_Lite_ERR_DoReRun:
        printf("SEMS Lite Status: Do Rerun");
        break;
    case kStatus_SEMS_Lite_ERR_NotApplicable:
        printf("SEMS Lite Status: Not Applicable");
        break;
    case kStatus_SEMS_Lite_ERR_DoRecovery:
        printf("SEMS Lite Status: Do Recovery");
        break;
    case kStatus_SEMS_Lite_ERR_Fatal:
        printf("SEMS Lite Status: Fatal Error");
        break;
    case kStatus_SEMS_Lite_ERR_NotEnoughNVMemory:
        printf("SEMS Lite Status: Not Enough NV Memory");
        break;
    case kStatus_SEMS_Lite_ERR_NotEnoughTransientMemory:
        printf("SEMS Lite Status: Not Enough Transient Memory");
        break;
    case kStatus_SEMS_Lite_ERR_MinPreviousVersion:
        printf("SEMS Lite Status: Old Previous Version");
        break;
    case kStatus_SEMS_Lite_ERR_OlderVersion:
        printf("SEMS Lite Status: Old Version");
        break;
    default:
        printf("SEMS Lite Status: UNKNOWN");
        break;
    }
    printf("\n");
}

void print_SSS_StatusCode(sss_status_t sss_stat)
{
    switch (sss_stat) {
    case kStatus_SSS_Success:
        printf("SSS Status: SUCCESS");
        break;
    case kStatus_SSS_Fail:
        printf("SSS Status: FAILED");
        break;
    default:
        printf("SSS Status: UNKNOWN");
        break;
    }
    printf("\n");
}

void print_hex_contents(
    const char *contentsName, uint8_t *contents, size_t contentsLen)
{
    printf("%s: ", contentsName);
    size_t i;
    for (i = 0; i < contentsLen; i++) {
        printf("%02x", contents[i]);
    }
    printf("\n");
}

uint8_t *hexstr_to_bytes(const char *str, size_t *len)
{
    if ((strlen(str) % 2) != 0) {
        printf("Invalid length");
        return NULL;
    }

    *len = strlen(str) / 2;
    uint8_t *res = (uint8_t *)malloc(*len);
    if (res == NULL) {
        LOG_E("Memory allocation failed");
        return NULL;
    }
    memset((void *)res, 0, *len);

    const char *pos = str;
    for (size_t count = 0; count < *len; count++) {
        if (sscanf(pos, "%2hhx", &res[count]) < 1) {
            free(res);
            return NULL;
        }
        pos += 2;
    }
    return res;
}
