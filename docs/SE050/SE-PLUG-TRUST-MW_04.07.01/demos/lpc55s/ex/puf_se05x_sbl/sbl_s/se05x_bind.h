/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include <fsl_puf.h>

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* Platform SCP03 Key Version no */
#define PF_KEY_VERSION_NO 0x0B

#define PUF_INTRINSIC_KEY_SIZE 16
#define AES_KEY_LEN_nBYTE 0x10
#define PUT_KEYS_KEY_TYPE_CODING_AES 0x88
#define CRYPTO_KEY_CHECK_LEN 0x03
#define GP_CLA_BYTE 0x80
#define GP_INS_PUTKEY 0xD8
#define GP_P2_MULTIPLEKEYS 0x81

/* bootloader data region: 0x3F000 - 0x3FFFF */
#define BL_DATA_START (0x3F000)
#define BL_DATA_SIZE (4 * 1024)
#define BL_DATA_MARKER (0xAEAEAEAE)

typedef struct _sbl_nvm_t
{
    uint32_t marker;
    uint8_t keyCodeENC[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)];
    uint8_t keyCodeMAC[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)];
    uint8_t keyCodeDEK[PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_INTRINSIC_KEY_SIZE)];
} sbl_nvm_t;

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/* Generate new keys in PUF and return them in the given buffers */
sss_status_t puf_generate_scp03_keys(uint8_t *enc_key, uint8_t *mac_key, uint8_t *dek_key, size_t key_size);

/* Insert PUF keys into Index 0 */
sss_status_t puf_insert_scp03_keys();

/* Functions to rotate PlatfSCP03 keys */
sss_status_t rotate_platformscp_keys(uint8_t *enc, uint8_t *mac, uint8_t *dek, ex_sss_boot_ctx_t *pCtx);
sss_status_t createKeyData(uint8_t *key, uint8_t *targetStore, ex_sss_boot_ctx_t *pCtx, uint32_t Id);
sss_status_t genKCVandEncryptKey(
    uint8_t *encryptedkey, uint8_t *keyCheckVal, uint8_t *plainKey, ex_sss_boot_ctx_t *pCtx, uint32_t keyId);

/* Platform SCP03 prepare host */
sss_status_t s_platform_prepare_host(sss_session_t *pHostSession,
    sss_key_store_t *pHostKs,
    SE_Connect_Ctx_t *se05x_open_ctx,
    uint8_t *ENC_KEY,
    uint8_t *MAC_KEY,
    uint8_t *DEK_KEY,
    size_t key_length);

/* Platform SCP03 Allocate key object */
sss_status_t s_alloc_Scp03key_Host(sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId);

sss_status_t sbl_nvm_init();

sss_status_t sbl_nvm_write(sbl_nvm_t *ctx);

sss_status_t sbl_nvm_read(sbl_nvm_t *ctx);
