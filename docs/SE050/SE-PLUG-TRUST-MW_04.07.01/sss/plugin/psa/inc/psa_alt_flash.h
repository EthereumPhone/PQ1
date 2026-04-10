/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _PSA_ALT_FLASH_H_
#define _PSA_ALT_FLASH_H_

#include "fsl_iap.h"

#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa_crypto_se.h"
#include "psa_crypto_its.h"

#include "psa_alt.h"

#define PSA_KS_MAGIC 0xDEADBEEF
#define PSA_KS_VERSION 0x1
#define PSA_KS_MAX_ENTRIES 0x8
#define PSA_KS_ENTRIES_WORD_INDEX (1 + 1 + 1)
#define PSA_KS_ENTRIES_WORD_SIZE (1 + 1 + 625)

#define PSA_KS_FIXED_WORD_SIZE                               \
    (                               /* PsakeyStoreTable_t */ \
        PSA_KS_ENTRIES_WORD_INDEX + /* PsaEntries_t */       \
        (PSA_KS_ENTRIES_WORD_SIZE * PSA_KS_MAX_ENTRIES))

/* The PSA KS structure is written to flash.
 * Everything written to flash must be 
 * 512-bytes (128 words) aligned.
 *
 * We will calculate number of aligned blocks 
 * required to accomodate the keystore structure.
 */

#define FLASH_WORD_ALIGN 128
#define FLASH_BUFFER_LENGTH (((PSA_KS_FIXED_WORD_SIZE / FLASH_WORD_ALIGN) * FLASH_WORD_ALIGN) + FLASH_WORD_ALIGN)

/* Generic entry of a Key ID Mapping inside the secure element */
typedef struct _PsaEntries_t
{
    /** Internal flash keyID */
    uint32_t intKeyId;

    /* Object file */
    uint32_t dataLen;
    uint8_t data[2500];
} PsaEntries_t;

typedef struct _PsakeyStoreTable_t
{
    /** Fixed - Unique 32bit magic number.
     *
     * In case some one over-writes we can know. */
    uint32_t magic;
    /** Fixed - constant based on version number */
    uint32_t version;
    /**
     * maxEntries  Fixed - constant in the Layout. Should be equal to
     * KS_N_ENTIRES This will help in porting between A71CH with less memory and
     * SE050 with more memory
     */
    /* Fix this to 1 for now. 
     * TODO: How to manage if we don't fix this
     */
    uint32_t maxEntries;

    PsaEntries_t entries[PSA_KS_MAX_ENTRIES];
} PsakeyStoreTable_t;

bool psa_flash_ks_init(bool reset);
void psa_flash_ks_read(bool reset);
void psa_flash_ks_persist(uint8_t *buffer);
void psa_flash_ks_persist_its_file(void);

#endif //_PSA_ALT_FLASH_H_
