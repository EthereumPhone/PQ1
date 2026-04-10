/* Copyright 2020,2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fsl_iap.h"
#include "fsl_iap_ffr.h"
#include "fsl_common.h"

#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa_crypto_storage.h"

#include "psa_alt.h"
#include "psa_alt_utils.h"
#include "psa_alt_flash.h"
#include "sss_psa_alt.h"

#include "nxLog_App.h"

#ifndef PAGE_INDEX_FROM_END
#define PAGE_INDEX_FROM_END 1U
#endif

#ifndef FLASH_WRITE_START_BASE_ADDR
#define FLASH_WRITE_START_BASE_ADDR 0x98000
#endif // FLASH_WRITE_START_BASE_ADDR

#define VERIFY_SUCCESS                                            \
    if (status != kStatus_Success) {                              \
        LOG_E("FAILED AT LINE %d. Error = %d", __LINE__, status); \
        while (1) {                                               \
        }                                                         \
    }

static flash_config_t flashInstance;
static PsakeyStoreTable_t psa_keystore;

static void psa_uid_to_flash_uid(psa_storage_uid_t uid, uint32_t *keyid);

#define FLASH_READPARAM_REG (FLASH->DATAW[0])
#define FLASH_READPARAM_WAIT_STATE_MASK (0xFU)
#define FLASH_READPARAM_WAIT_STATE_SHIFT (0U)
#define FLASH_READPARAM_WAIT_STATE(x) \
    (((uint32_t)(((uint32_t)(x)) << FLASH_READPARAM_WAIT_STATE_SHIFT)) & FLASH_READPARAM_WAIT_STATE_MASK)
#define FLASH_CMD_SET_READ_MODE 2

bool psa_flash_ks_init(bool reset)
{
    status_t status;

    uint32_t destAdrss = FLASH_WRITE_START_BASE_ADDR; /* Address of the target location */
    uint32_t failedAddress, failedData;
    uint32_t s_buffer[FLASH_BUFFER_LENGTH] = {0};
    memset(&psa_keystore, 0, sizeof(psa_keystore));

    status = FLASH_Init(&flashInstance);
    VERIFY_SUCCESS;

    if (reset) {
        LOG_W("PSA Keystore contents are being erased!");
        status = FLASH_Erase(&flashInstance, destAdrss, FLASH_BUFFER_LENGTH * 4, kFLASH_ApiEraseKey);
        VERIFY_SUCCESS;
    }

    status = FLASH_VerifyErase(&flashInstance, destAdrss, FLASH_BUFFER_LENGTH * 4);
    if (reset) {
        VERIFY_SUCCESS;

        status = FLASH_Program(&flashInstance, destAdrss, (uint8_t *)s_buffer, sizeof(s_buffer));
        VERIFY_SUCCESS;

        status = FLASH_VerifyProgram(
            &flashInstance, destAdrss, sizeof(s_buffer), (const uint8_t *)s_buffer, &failedAddress, &failedData);
        VERIFY_SUCCESS;
    }

    for (uint32_t i = 0; i < FLASH_BUFFER_LENGTH; i++) {
        s_buffer[i] = *(volatile uint32_t *)(destAdrss + i * 4);
    }
    psa_keystore.magic      = s_buffer[0];
    psa_keystore.version    = s_buffer[1];
    psa_keystore.maxEntries = s_buffer[2];

    if (psa_keystore.magic != PSA_KS_MAGIC) {
        LOG_W("PSA Keystore not created. Creating new keystore");
        psa_keystore.magic      = PSA_KS_MAGIC;
        psa_keystore.version    = PSA_KS_VERSION;
        psa_keystore.maxEntries = PSA_KS_MAX_ENTRIES;
        memset(psa_keystore.entries, 0, sizeof(PsaEntries_t) * PSA_KS_MAX_ENTRIES);
        psa_flash_ks_persist((uint8_t *)s_buffer);
        return true;
    }
    else {
        LOG_I("PSA Keystore available");
        if (psa_keystore.version != PSA_KS_VERSION) {
            /* Update KS version */
        }
        if (psa_keystore.maxEntries != PSA_KS_MAX_ENTRIES) {
            LOG_E("Keystore maxEntries mismatch");
            return false;
        }
    }

    memcpy(psa_keystore.entries, &s_buffer[PSA_KS_ENTRIES_WORD_INDEX], sizeof(psa_keystore.entries));

    return true;
}

void psa_flash_ks_persist(uint8_t *buffer)
{
    status_t status;

    uint32_t destAdrss = FLASH_WRITE_START_BASE_ADDR; /* Address of the target location */

    memcpy((void *)buffer, (void *)&psa_keystore, sizeof(psa_keystore));

    status = FLASH_Erase(&flashInstance, destAdrss, FLASH_BUFFER_LENGTH * 4, kFLASH_ApiEraseKey);
    VERIFY_SUCCESS;

    status = FLASH_VerifyErase(&flashInstance, destAdrss, FLASH_BUFFER_LENGTH * 4);
    VERIFY_SUCCESS;

    status = FLASH_Program(&flashInstance, destAdrss, (uint8_t *)buffer, FLASH_BUFFER_LENGTH * 4);
    VERIFY_SUCCESS;
}

void psa_flash_ks_persist_its_file()
{
    uint32_t buffer[FLASH_BUFFER_LENGTH] = {0};
    return psa_flash_ks_persist((uint8_t *)buffer);
}

psa_status_t psa_alt_store_flash_its_file(psa_storage_uid_t uid, uint8_t *data, size_t dataLen)
{
    psa_status_t psa_status = PSA_ERROR_STORAGE_FAILURE;
    uint32_t file_id        = 0;

    // LOG_I("%s", __FUNCTION__);

    psa_uid_to_flash_uid(uid, &file_id);

    if (file_id == PSA_ALT_LIFETIME_FILE) {
        LOG_E("Cannot store lifetime file");
    }

    else if (file_id == PSA_ALT_TRANSACTION_FILE) {
        LOG_E("Cannot store transaction file");
    }

    else {
        PsaEntries_t *psa_entries = &psa_keystore.entries[0];
        /* Search for first empty entry */
        size_t i        = 0;
        bool foundEntry = false;
        for (i = 0; i < PSA_KS_MAX_ENTRIES; i++) {
            psa_entries = &psa_keystore.entries[i];
            if (psa_entries->intKeyId == 0) {
                /* Entry found */
                foundEntry = true;
                break;
            }
        }

        if (foundEntry) {
            if (dataLen <= sizeof(psa_entries->data)) {
                psa_entries->intKeyId = file_id;
                psa_entries->dataLen  = dataLen;
                memcpy(psa_entries->data, data, dataLen);
                psa_status = PSA_SUCCESS;
            }
            else {
                LOG_E("Insufficient buffer");
            }
        }
        else {
            LOG_E("No entry available");
        }
    }

    if (psa_status == PSA_SUCCESS) {
        psa_flash_ks_persist_its_file();
    }

    return psa_status;
}

psa_status_t psa_alt_read_flash_its_file(psa_storage_uid_t uid, uint8_t *data, size_t *dataLen)
{
    psa_status_t psa_status = PSA_ERROR_STORAGE_FAILURE;
    uint32_t file_id        = 0;

    // LOG_I("%s", __FUNCTION__);

    psa_uid_to_flash_uid(uid, &file_id);

    if (file_id == PSA_ALT_LIFETIME_FILE) {
        LOG_E("Cannot read lifetime file");
    }

    else if (file_id == PSA_ALT_TRANSACTION_FILE) {
        LOG_E("Cannot read transaction file");
    }

    else {
        PsaEntries_t *psa_entries = &psa_keystore.entries[0];
        /* Search for matching entry */
        size_t i        = 0;
        bool foundEntry = false;
        for (i = 0; i < PSA_KS_MAX_ENTRIES; i++) {
            psa_entries = &psa_keystore.entries[i];
            if (psa_entries->intKeyId == file_id) {
                /* Entry found */
                foundEntry = true;
                break;
            }
        }

        if (foundEntry) {
            if (*dataLen >= psa_entries->dataLen) {
                memset(data, 0, *dataLen);
                memcpy(data, psa_entries->data, psa_entries->dataLen);
                *dataLen   = psa_entries->dataLen;
                psa_status = PSA_SUCCESS;
            }
        }
        else {
            psa_status = PSA_ERROR_DOES_NOT_EXIST;
        }
    }

    if (psa_status != PSA_SUCCESS) {
        *dataLen = 0;
    }

    return psa_status;
}

psa_status_t psa_alt_remove_flash_its_file(psa_storage_uid_t uid)
{
    psa_status_t psa_status = PSA_ERROR_STORAGE_FAILURE;
    // sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t file_id = 0;

    // LOG_I("%s", __FUNCTION__);

    psa_uid_to_flash_uid(uid, &file_id);

    if (file_id == PSA_ALT_LIFETIME_FILE) {
        LOG_E("Cannot remove lifetime file");
    }

    else if (file_id == PSA_ALT_TRANSACTION_FILE) {
        LOG_E("Cannot remove transaction file");
    }

    else {
        PsaEntries_t *psa_entries = &psa_keystore.entries[0];
        /* Search for matching entry */
        size_t i        = 0;
        bool foundEntry = false;
        for (i = 0; i < PSA_KS_MAX_ENTRIES; i++) {
            psa_entries = &psa_keystore.entries[i];
            if (psa_entries->intKeyId == file_id) {
                /* Entry found */
                foundEntry = true;
                break;
            }
        }

        if (foundEntry) {
            memset(psa_entries, 0, sizeof(PsaEntries_t));
            psa_status = PSA_SUCCESS;
        }
        else {
            psa_status = PSA_ERROR_DOES_NOT_EXIST;
        }
    }

    if (psa_status == PSA_SUCCESS) {
        psa_flash_ks_persist_its_file();
    }

    return psa_status;
}

static void psa_uid_to_flash_uid(psa_storage_uid_t uid, uint32_t *keyid)
{
#if defined(PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS)
    if (uid == PSA_CRYPTO_ITS_TRANSACTION_UID) {
        // LOG_I("TRANSACTION");
        *keyid = PSA_ALT_TRANSACTION_FILE;
    }
    else
#endif
    {
        if ((uid & PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE) == PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE) {
            // LOG_I("LIFETIME");
            *keyid = PSA_ALT_LIFETIME_FILE;
        }
        else {
            // LOG_I("OBJECT");
            *keyid = PSA_KEY_ID_TO_ITS_KEY_ID(*keyid);
        }
    }
}
