/* Copyright 2019, 2023 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "seTool.h"

#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
#include <openssl/core_names.h>
#endif
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

static ex_sss_boot_ctx_t gex_sss_se_tool;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_se_tool)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>
static sss_status_t getSE05xPublicRsaKey(
    ex_sss_boot_ctx_t *pCtx, uint32_t keyId, uint8_t *rsaKeyData, size_t *rsaKeyDataSize, size_t *rsaKeyBitLen);

#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
static EVP_PKEY *set_rsa_ref_key(
    BIGNUM *n, BIGNUM *e, BIGNUM *d, BIGNUM *p, BIGNUM *q, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);
static unsigned char *bn_to_bin(BIGNUM *bn, int *len);
#endif

static void usage()
{
    LOG_I("Usage:");
    LOG_I("EC NIST P256:");
    LOG_I("\tseTool genECC <keyId> <portname>");
    LOG_I("\tseTool setECC <keyId> <filename> <portname>");
    LOG_I("\tseTool getECCPublic <keyId> <filename> <portname>");
    LOG_I("\tseTool getECCRef <keyId> <filename> <portname>");
    LOG_I("RSA 1024/2048/3072/4096:");
    LOG_I("\tseTool genRSA <rsaKeySize> <keyId> <portname>");
    LOG_I("\tseTool setRSA <rsaKeySize> <keyId> <filename> <portname>");
    LOG_I("\tseTool getRSAPublic <keyId> <filename> <portname>");
    LOG_I("\tseTool getRSARef <keyId> <filename> <portname>");
    LOG_I("rsaKeySize = 1024, 2048, 3072 or 4096 (supported by the seTool)");
    LOG_I("Note: Please check the SE05x documentation for supported SE05x ");
    LOG_I("      device RSA key sizes.");
    LOG_I("portname = Subsystem specific connection parameters. Example: COM6,");
    LOG_I("127.0.0.1:8050. Use \"None\" where not applicable. e.g. SCI2C/T1oI2C.");
    LOG_I("Default i2c port (i2c-1) will be used for port name = \"none\"");
    LOG_I("Note: The Privacy-Enhanced Mail (PEM) file format is used for");
    LOG_I("storing and importing keys.");
}

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    int argc            = gex_sss_argc;
    const char **argv   = gex_sss_argv;
    int genECC          = 0;
    int getECCPublic    = 0;
    int getECCRef       = 0;
    int setECC          = 0;
    int genRSA          = 0;
    int setRSA          = 0;
    int getRSAPublic    = 0;
    int getRSARef       = 0;

    if (argc < 2) {
        usage();
        status = kStatus_SSS_Success;
        goto exit;
    }
    if (strncmp(argv[1], "genECC", sizeof("genECC")) == 0) {
        genECC = 1;
    }
    else if (strncmp(argv[1], "setECC", sizeof("setECC")) == 0) {
        setECC = 1;
    }
    else if (strncmp(argv[1], "getECCPublic", sizeof("getECCPublic")) == 0) {
        getECCPublic = 1;
    }
    else if (strncmp(argv[1], "getECCRef", sizeof("getECCRef")) == 0) {
        getECCRef = 1;
    }
    else if (strncmp(argv[1], "genRSA", sizeof("genRSA")) == 0) {
        genRSA = 1;
    }
    else if (strncmp(argv[1], "setRSA", sizeof("setRSA")) == 0) {
        setRSA = 1;
    }
    else if (strncmp(argv[1], "getRSAPublic", sizeof("getRSAPublic")) == 0) {
        getRSAPublic = 1;
    }
    else if (strncmp(argv[1], "getRSARef", sizeof("getRSARef")) == 0) {
        getRSARef = 1;
    }
    else {
        LOG_E("Invalid command line parameter");
        usage();
        goto exit;
    }

    if (genECC) {
        unsigned long int id         = 0;
        uint32_t keyId               = 0;
        sss_object_t obj             = {0};
        sss_key_part_t keyPart       = kSSS_KeyPart_Pair;
        sss_cipher_type_t cipherType = kSSS_CipherType_EC_NIST_P;
        size_t keyBitLen             = 256;

        if (argc < 4) {
            usage();
            goto exit;
        }

        id = strtoul(argv[2], NULL, 0);
        if (id > UINT32_MAX) {
            LOG_E("id can not be greater than 4 bytes.");
            goto exit;
        }
        keyId = (uint32_t)(id);
        /*We demonstrate for cipher type and key size corresponding to NISTP-256 keypair only*/

        status = sss_key_object_init(&obj, &pCtx->ks);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status =
            sss_key_object_allocate_handle(&obj, keyId, keyPart, cipherType, keyBitLen * 8, kKeyObject_Mode_Persistent);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_store_generate_key(&pCtx->ks, &obj, keyBitLen, NULL);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        sss_key_object_free(&obj);
    }
    else if (getECCPublic) {
        unsigned long int id = 0;
        uint32_t keyId       = 0;
        /*We demonstrate for cipher type and key size corresponding to NISTP-256 keypair only*/
        sss_object_t obj                   = {0};
        size_t keyBitLen                   = 256;
        uint8_t key[256]                   = {0};
        size_t keyByteLen                  = sizeof(key);
        BIO *bio                           = NULL;
        EVP_PKEY *pKey                     = NULL;
        char file_name[MAX_FILE_NAME_SIZE] = {0};
        FILE *fp                           = NULL;

        if (argc < 4) {
            usage();
            goto exit;
        }

        id = strtoul(argv[2], NULL, 0);
        if (id > UINT32_MAX) {
            LOG_E("id can not be greater than 4 bytes.");
            goto exit;
        }

        keyId = (uint32_t)(id);

        status = sss_key_object_init(&obj, &pCtx->ks);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_object_get_handle(&obj, keyId);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_store_get_key(&pCtx->ks, &obj, key, &keyByteLen, &keyBitLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        sss_key_object_free(&obj);

        bio = BIO_new_mem_buf(key, (int)sizeof(key));
        if (bio == NULL) {
            LOG_E("Unable to initialize BIO");
            status = kStatus_SSS_Fail;
            goto getECCPublic_freemem;
        }

        pKey = d2i_PUBKEY_bio(bio, NULL);
        if (!pKey) {
            LOG_E("Failed to load public key");
            status = kStatus_SSS_Fail;
            goto getECCPublic_freemem;
        }

        strncpy(file_name, argv[3], sizeof(file_name) - 1);
        if (strstr(file_name, "..") != NULL) {
            LOG_W("Potential directory traversal");
        }
        if (file_name[0] == '/') {
            LOG_W("Accessing file using absolute path");
        }
        fp = fopen(file_name, "wb+");
        if (fp == NULL) {
            LOG_E("Can not open the file");
            status = kStatus_SSS_Fail;
            goto getECCPublic_freemem;
        }
        else {
            PEM_write_PUBKEY(fp, pKey);
        }

    getECCPublic_freemem:
        if (bio != NULL) {
            BIO_free(bio);
        }
        if (pKey != NULL) {
            EVP_PKEY_free(pKey);
        }
        if (fp != NULL) {
            if (fclose(fp) != 0) {
                LOG_E("Can not close the file");
            }
        }
        goto exit;
    }
    else if (setECC) {
        uint32_t keyId = 0;
        /*We demonstrate for cipher type and key size corresponding to NISTP-256 keypair only*/
        sss_object_t obj                   = {0};
        sss_key_part_t keyPart             = kSSS_KeyPart_Pair;
        sss_cipher_type_t cipherType       = kSSS_CipherType_EC_NIST_P;
        size_t keyBitLen                   = 256;
        uint8_t key[256]                   = {0};
        size_t keyByteLen                  = sizeof(key);
        unsigned char *data                = &key[0];
        int len                            = 0;
        EVP_PKEY *pKey                     = NULL;
        char file_name[MAX_FILE_NAME_SIZE] = {0};
        FILE *fp                           = NULL;

        if (argc < 4) {
            usage();
            goto exit;
        }

        unsigned long int id = strtoul(argv[2], NULL, 0);
        if (id > UINT32_MAX) {
            LOG_E("id can not be greater than 4 bytes.");
            goto exit;
        }

        keyId = (uint32_t)(id);

        strncpy(file_name, argv[3], sizeof(file_name) - 1);
        if (strstr(file_name, "..") != NULL) {
            LOG_W("Potential directory traversal");
        }
        if (file_name[0] == '/') {
            LOG_W("Accessing file using absolute path");
        }
        fp = fopen(file_name, "rb");
        if (fp == NULL) {
            LOG_E("Can not open the file");
            goto exit;
        }
        else {
            PEM_read_PrivateKey(fp, &pKey, NULL, NULL);
            if (pKey == NULL) {
                LOG_E("Failed to read Keypair");
                status = kStatus_SSS_Fail;
                goto setECC_freemem;
            }
        }

        len = i2d_PrivateKey(pKey, &data);
        if (len <= 0) {
            status = kStatus_SSS_Fail;
            goto setECC_freemem;
        }
        keyByteLen = len;

        status = sss_key_object_init(&obj, &pCtx->ks);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        if (keyBitLen > (SIZE_MAX / 8)) {
            status = kStatus_SSS_Fail;
            goto setECC_freemem;
        }

        status =
            sss_key_object_allocate_handle(&obj, keyId, keyPart, cipherType, keyBitLen * 8, kKeyObject_Mode_Persistent);
        if (status != kStatus_SSS_Success) {
            goto setECC_freemem;
        }

        status = sss_key_store_set_key(&pCtx->ks, &obj, key, keyByteLen, keyBitLen, NULL, 0);
        if (status != kStatus_SSS_Success) {
            goto setECC_freemem;
        }

    setECC_freemem:
        if (obj.keyStore != NULL) {
            sss_key_object_free(&obj);
        }
        if (pKey != NULL) {
            EVP_PKEY_free(pKey);
        }
        if (fp != NULL) {
            if (fclose(fp) != 0) {
                LOG_E("Can not close the file");
            }
        }
        goto exit;
    }
    else if (getECCRef) {
        unsigned long int id = 0;
        uint32_t keyId       = 0;
        /*We demonstrate for cipher type and key size corresponding to NISTP-256 keypair only*/
        sss_object_t obj                   = {0};
        size_t keyBitLen                   = 256;
        uint8_t key[256]                   = {0};
        size_t keyByteLen                  = sizeof(key);
        uint8_t priv_header[]              = PRIV_PREFIX_NIST_P_256;
        uint8_t pub_header[]               = PUBLIC_PREFIX_NIST_P_256;
        uint8_t magic[]                    = MAGIC_BYTES_SE05X_OPENSSL_ENGINE;
        uint8_t ref[256]                   = {0};
        size_t ref_len                     = 0;
        uint8_t id_array[4]                = {0};
        BIO *bio                           = NULL;
        EVP_PKEY *pKey                     = NULL;
        char file_name[MAX_FILE_NAME_SIZE] = {0};
        FILE *fp                           = NULL;

        if (argc < 4) {
            usage();
            goto exit;
        }

        id = strtoul(argv[2], NULL, 0);
        if (id > UINT32_MAX) {
            LOG_E("id can not be greater than 4 bytes.");
            goto exit;
        }

        keyId = (uint32_t)(id);

        status = sss_key_object_init(&obj, &pCtx->ks);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_object_get_handle(&obj, keyId);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_store_get_key(&pCtx->ks, &obj, key, &keyByteLen, &keyBitLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        sss_key_object_free(&obj);

        memcpy(&ref[ref_len], priv_header, sizeof(priv_header));
        ref_len += sizeof(priv_header);

        id_array[0] = (keyId & 0xFF000000) >> (8 * 3);
        id_array[1] = (keyId & 0x00FF0000) >> (8 * 2);
        id_array[2] = (keyId & 0x0000FF00) >> (8 * 1);
        id_array[3] = (keyId & 0x000000FF) >> (8 * 0);

        memcpy(&ref[ref_len], id_array, sizeof(id_array));
        ref_len += sizeof(id_array);

        memcpy(&ref[ref_len], magic, sizeof(magic));
        ref_len += sizeof(magic);

        ref[ref_len++] = 0x10; // Hardcoded for Keypair
        ref[ref_len++] = 0x00; // Hardcoded as 0x00

        memcpy(&ref[ref_len], pub_header, sizeof(pub_header));
        ref_len += sizeof(pub_header);

        if ((keyByteLen < 22) || ((SIZE_MAX - ref_len) < (keyByteLen - 22))) {
            status = kStatus_SSS_Fail;
            goto getECCRef_freemem;
        }

        if ((ref_len + (keyByteLen - 22)) > sizeof(ref)) {
            status = kStatus_SSS_Fail;
            goto getECCRef_freemem;
        }

        if ((23 + (keyByteLen - 22)) > sizeof(key)) {
            status = kStatus_SSS_Fail;
            goto getECCRef_freemem;
        }

        /* Copy only public key part */
        memcpy(&ref[ref_len], &key[23], keyByteLen - 22);
        ref_len += (keyByteLen - 22);

        bio = BIO_new_mem_buf(ref, (int)(ref_len));
        if (bio == NULL) {
            status = kStatus_SSS_Fail;
            goto getECCRef_freemem;
        }

        pKey = d2i_PrivateKey_bio(bio, NULL);
        if (!pKey) {
            LOG_E("Failed to load public key");
            status = kStatus_SSS_Fail;
            goto getECCRef_freemem;
        }

        strncpy(file_name, argv[3], sizeof(file_name) - 1);
        if (strstr(file_name, "..") != NULL) {
            LOG_W("Potential directory traversal");
        }

        if (file_name[0] == '/') {
            LOG_W("Accessing file using absolute path");
        }

        fp = fopen(file_name, "wb+");
        if (fp == NULL) {
            LOG_E("Can not open the file");
            status = kStatus_SSS_Fail;
        }
        else {
            PEM_write_PrivateKey(fp, pKey, NULL, NULL, 0, NULL, NULL);
        }

    getECCRef_freemem:
        if (bio != NULL) {
            BIO_free(bio);
        }
        if (pKey != NULL) {
            EVP_PKEY_free(pKey);
        }
        if (fp != NULL) {
            if (fclose(fp) != 0) {
                LOG_E("Can not close the file");
            }
        }
        goto exit;
    }
    else if (genRSA) {
        unsigned long int rsaKeySize = 0;
        unsigned long int id         = 0;
        uint32_t keyId               = 0;
        sss_object_t obj             = {0};
        sss_key_part_t keyPart       = kSSS_KeyPart_Pair;
        sss_cipher_type_t cipherType = kSSS_CipherType_RSA_CRT;
        size_t keyBitLen             = 0;

        if (argc < 5) {
            usage();
            goto exit;
        }

        rsaKeySize = strtoul(argv[2], NULL, 0);
        id         = strtoul(argv[3], NULL, 0);

        if (id > UINT32_MAX) {
            LOG_E("id can not be greater than 4 bytes.");
            goto exit;
        }

        keyId     = (uint32_t)(id);
        keyBitLen = rsaKeySize;

        status = sss_key_object_init(&obj, &pCtx->ks);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        if (keyBitLen > (SIZE_MAX / 8)) {
            status = kStatus_SSS_Fail;
            goto exit;
        }

        status =
            sss_key_object_allocate_handle(&obj, keyId, keyPart, cipherType, keyBitLen * 8, kKeyObject_Mode_Persistent);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_key_store_generate_key(&pCtx->ks, &obj, keyBitLen, NULL);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        sss_key_object_free(&obj);
    }
    else if (setRSA) {
        unsigned long int rsaKeySize       = 0;
        unsigned long int id               = 0;
        uint32_t keyId                     = 0;
        sss_object_t obj                   = {0};
        sss_key_part_t keyPart             = kSSS_KeyPart_Pair;
        sss_cipher_type_t cipherType       = kSSS_CipherType_RSA_CRT;
        size_t keyBitLen                   = 0;
        uint8_t key[4096]                  = {0};
        size_t keyByteLen                  = sizeof(key);
        unsigned char *data                = &key[0];
        int len                            = 0;
        EVP_PKEY *pKey                     = NULL;
        char file_name[MAX_FILE_NAME_SIZE] = {0};
        FILE *fp                           = NULL;

        if (argc < 5) {
            usage();
            goto exit;
        }

        rsaKeySize = strtoul(argv[2], NULL, 0);
        id         = strtoul(argv[3], NULL, 0);

        keyBitLen = rsaKeySize;

        if (id > UINT32_MAX) {
            LOG_E("id can not be greater than 4 bytes.");
            goto exit;
        }
        keyId = (uint32_t)(id);

        strncpy(file_name, argv[4], sizeof(file_name) - 1);
        if (strstr(file_name, "..") != NULL) {
            LOG_W("Potential directory traversal");
        }
        if (file_name[0] == '/') {
            LOG_W("Accessing file using absolute path");
        }
        fp = fopen(file_name, "rb");
        if (fp == NULL) {
            LOG_E("Can not open the file");
            status = kStatus_SSS_Fail;
            goto setRSA_freemem;
        }
        else {
            PEM_read_PrivateKey(fp, &pKey, NULL, NULL);
            if (pKey == NULL) {
                LOG_E("Failed to read Keypair");
                status = kStatus_SSS_Fail;
                goto setRSA_freemem;
            }
        }

        len = i2d_PrivateKey(pKey, &data);
        if (len <= 0) {
            goto setRSA_freemem;
        }
        keyByteLen = len;

        status = sss_key_object_init(&obj, &pCtx->ks);
        if (status != kStatus_SSS_Success) {
            goto setRSA_freemem;
        }

        if (keyBitLen > (SIZE_MAX / 8)) {
            status = kStatus_SSS_Fail;
            goto setRSA_freemem;
        }

        status =
            sss_key_object_allocate_handle(&obj, keyId, keyPart, cipherType, keyBitLen * 8, kKeyObject_Mode_Persistent);
        if (status != kStatus_SSS_Success) {
            goto setRSA_freemem;
        }

        status = sss_key_store_set_key(&pCtx->ks, &obj, key, keyByteLen, keyBitLen, NULL, 0);

    setRSA_freemem:
        if (obj.keyStore != NULL) {
            sss_key_object_free(&obj);
        }
        if (pKey != NULL) {
            EVP_PKEY_free(pKey);
        }
        if (fp != NULL) {
            if (fclose(fp) != 0) {
                LOG_E("Can not close the file");
            }
        }
    }
    else if (getRSAPublic) {
        unsigned long int id               = 0;
        uint32_t keyId                     = 0;
        size_t rsaKeyBitLen                = 0;
        uint8_t rsaKeyData[808]            = {0}; //up to RSA 4096
        size_t rsaKeyByteLen               = sizeof(rsaKeyData);
        BIO *bio                           = NULL;
        char file_name[MAX_FILE_NAME_SIZE] = {0};
        FILE *fp                           = NULL;
        EVP_PKEY *pKey                     = NULL;

        if (argc < 4) {
            usage();
            goto exit;
        }

        id = strtoul(argv[2], NULL, 0);
        if (id > UINT32_MAX) {
            LOG_E("id can not be greater than 4 bytes.");
            goto exit;
        }
        keyId = (uint32_t)(id);

        /* get SE05x public rsa key. */
        status = getSE05xPublicRsaKey(pCtx, keyId, rsaKeyData, &rsaKeyByteLen, &rsaKeyBitLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        bio = BIO_new_mem_buf(rsaKeyData, rsaKeyByteLen);
        if (bio == NULL) {
            LOG_E("BIO_new_mem_buf() - failed");
            status = kStatus_SSS_Fail;
            goto getRSAPublic_freemem;
        }

        pKey = d2i_PUBKEY_bio(bio, NULL);
        if (!pKey) {
            LOG_E("d2i_PUBKEY_bio() - failed");
            status = kStatus_SSS_Fail;
            goto getRSAPublic_freemem;
        }

        strncpy(file_name, argv[3], sizeof(file_name) - 1);
        if (strstr(file_name, "..") != NULL) {
            LOG_W("Potential directory traversal");
        }
        if (file_name[0] == '/') {
            LOG_W("Accessing file using absolute path");
        }
        fp = fopen(file_name, "wb+");
        if (fp == NULL) {
            LOG_E("Can not open the file");
            status = kStatus_SSS_Fail;
            goto getRSAPublic_freemem;
        }
        else {
            PEM_write_PUBKEY(fp, pKey);
        }

    getRSAPublic_freemem:
        if (bio != NULL) {
            BIO_free(bio);
        }
        if (pKey != NULL) {
            EVP_PKEY_free(pKey);
        }
        if (fp != NULL) {
            if (fclose(fp) != 0) {
                LOG_E("Can not close the file");
            }
        }
    }
    else if (getRSARef) {
        unsigned long int id    = 0;
        uint32_t keyId          = 0;
        uint8_t rsaKeyData[808] = {0}; //up to RSA 4096
        size_t rsaKeyByteLen    = 0;
        size_t rsaKeyBitLen     = 0;
        BIO *bio                = NULL;
        EVP_PKEY *pKey          = NULL;
        BIGNUM *pBigNum_d       = NULL;
        BIGNUM *pBigNum_p       = NULL;
        BIGNUM *pBigNum_q       = NULL;
        BIGNUM *pBigNum_dmp1    = NULL;
        BIGNUM *pBigNum_dmq1    = NULL;
        BIGNUM *pBigNum_n       = NULL;
        BIGNUM *pBigNum_e       = NULL;
        BIGNUM *pBigNum_iqmp    = NULL;
        EVP_PKEY *pKey2         = NULL;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
#else
        RSA *pRSAPublic  = NULL;
        RSA *pRSAPrivate = NULL;
#endif
        char file_name[MAX_FILE_NAME_SIZE] = {0};
        FILE *fp                           = NULL;

        if (argc < 4) {
            usage();
            goto exit;
        }

        id = strtoul(argv[2], NULL, 0);
        if (id > UINT32_MAX) {
            LOG_E("id can not be greater than 4 bytes.");
            goto exit;
        }

        keyId         = (uint32_t)(id);
        rsaKeyByteLen = sizeof(rsaKeyData);

        /* get SE05x public rsa key. */
        status = getSE05xPublicRsaKey(pCtx, keyId, rsaKeyData, &rsaKeyByteLen, &rsaKeyBitLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        bio = BIO_new_mem_buf(rsaKeyData, rsaKeyByteLen);
        if (bio == NULL) {
            LOG_E("BIO_new_mem_buf() - failed");
            status = kStatus_SSS_Fail;
            goto getRSARef_freemem;
        }

        pKey = d2i_PUBKEY_bio(bio, NULL);
        if (!pKey) {
            LOG_E("d2i_PUBKEY_bio() -failed");
            status = kStatus_SSS_Fail;
            goto getRSARef_freemem;
        }

        /* placeholder for p(aka 'prime1') */
        pBigNum_d = BN_new();
        BN_set_word(pBigNum_d, 1L);

        /* placeholder for p(aka 'prime1') */
        pBigNum_p = BN_new();
        BN_set_word(pBigNum_p, 1L);

        /*The value reserved for �q�(aka 'prime2') is used to store the 32 bit key identifier*/
        pBigNum_q = BN_new();
        BN_set_word(pBigNum_q, (unsigned long)keyId);

        /* placeholder for exponent1 d mod(p - 1) */
        pBigNum_dmp1 = BN_new();
        BN_set_word(pBigNum_dmp1, 1L);

        /* placeholder for exponent2 d mod(q - 1) */
        pBigNum_dmq1 = BN_new();
        BN_set_word(pBigNum_dmq1, 1L);

#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
        // Retrieve n and e
        if (EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_N, &pBigNum_n) <= 0) {
            status = kStatus_SSS_Fail;
            goto getRSARef_freemem;
        }

        if (EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_E, &pBigNum_e) <= 0) {
            status = kStatus_SSS_Fail;
            goto getRSARef_freemem;
        }

        /* The value reserved for �(inverse of q) mod p' */
        /* (aka �coefficient�) is used to store the magic number 0xA5A6B5B6 */
        /* to indicate this key is a referece key */
        pBigNum_iqmp = BN_new();
        BN_set_word(pBigNum_iqmp, (unsigned long)0xA5A6B5B6);

        pKey2 = set_rsa_ref_key(
            pBigNum_n, pBigNum_e, pBigNum_d, pBigNum_p, pBigNum_q, pBigNum_dmp1, pBigNum_dmq1, pBigNum_iqmp);
#else
        pRSAPublic       = EVP_PKEY_get1_RSA(pKey);
        if (!pRSAPublic) {
            LOG_E("EVP_PKEY_get1_RSA() - failed");
            status = kStatus_SSS_Fail;
            goto getRSARef_freemem;
        }

        const BIGNUM *n = RSA_get0_n(pRSAPublic);
        const BIGNUM *e = RSA_get0_e(pRSAPublic);

        pBigNum_n = BN_dup(n);
        pBigNum_e = BN_dup(e);

        if (!pBigNum_n || !pBigNum_e) {
            LOG_E("BN_dup() failed");
            status = kStatus_SSS_Fail;
            goto getRSARef_freemem;
        }

        pBigNum_iqmp = BN_new();

        BN_set_word(pBigNum_iqmp, (unsigned long)0xA5A6B5B6);

        pRSAPrivate = RSA_new();
        if (!pRSAPrivate) {
            LOG_E("RSA_new() failed");
            status = kStatus_SSS_Fail;
            goto getRSARef_freemem;
        }

        RSA_set0_key(pRSAPrivate, pBigNum_n, pBigNum_e, pBigNum_d);
        RSA_set0_factors(pRSAPrivate, pBigNum_p, pBigNum_q);
        RSA_set0_crt_params(pRSAPrivate, pBigNum_dmp1, pBigNum_dmq1, pBigNum_iqmp);

        pBigNum_n    = NULL;
        pBigNum_e    = NULL;
        pBigNum_d    = NULL;
        pBigNum_p    = NULL;
        pBigNum_q    = NULL;
        pBigNum_dmp1 = NULL;
        pBigNum_dmq1 = NULL;
        pBigNum_iqmp = NULL;

        pKey2 = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pKey2, pRSAPrivate);

        pRSAPrivate = NULL;
#endif

        strncpy(file_name, argv[3], sizeof(file_name) - 1);
        if (strstr(file_name, "..") != NULL) {
            LOG_W("Potential directory traversal");
        }
        if (file_name[0] == '/') {
            LOG_W("Accessing file using absolute path");
        }
        fp = fopen(file_name, "wb+");
        if (fp == NULL) {
            LOG_E("Can not open the file");
            status = kStatus_SSS_Fail;
            goto getRSARef_freemem;
        }
        else {
            PEM_write_PrivateKey(fp, pKey2, NULL, NULL, 0, NULL, NULL);
            status = kStatus_SSS_Success;
        }

    getRSARef_freemem:
        if (bio != NULL) {
            BIO_free(bio);
        }
        if (pKey2 != NULL) {
            EVP_PKEY_free(pKey2);
        }
        if (pKey != NULL) {
            EVP_PKEY_free(pKey);
        }
        if (pBigNum_n != NULL) {
            BN_free(pBigNum_n);
        }
        if (pBigNum_e != NULL) {
            BN_free(pBigNum_e);
        }
        if (pBigNum_d != NULL) {
            BN_free(pBigNum_d);
        }
        if (pBigNum_p != NULL) {
            BN_free(pBigNum_p);
        }
        if (pBigNum_q != NULL) {
            BN_free(pBigNum_q);
        }
        if (pBigNum_dmp1 != NULL) {
            BN_free(pBigNum_dmp1);
        }
        if (pBigNum_dmq1 != NULL) {
            BN_free(pBigNum_dmq1);
        }
        if (pBigNum_iqmp != NULL) {
            BN_free(pBigNum_iqmp);
        }
        if (fp != NULL) {
            if (fclose(fp) != 0) {
                LOG_E("Can not close the file");
            }
        }
#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
#else
        if (pRSAPublic != NULL) {
            RSA_free(pRSAPublic);
        }
        if (pRSAPrivate != NULL) {
            RSA_free(pRSAPrivate);
        }
#endif
    }
exit:
    return status;
}

static sss_status_t getSE05xPublicRsaKey(
    ex_sss_boot_ctx_t *pCtx, uint32_t keyId, uint8_t *rsaKeyData, size_t *rsaKeyDataSize, size_t *rsaKeyBitLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t obj    = {0};

    status = sss_key_object_init(&obj, &pCtx->ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&obj, keyId);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_store_get_key(&pCtx->ks, &obj, rsaKeyData, rsaKeyDataSize, rsaKeyBitLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
exit:
    sss_key_object_free(&obj);
    if (status != kStatus_SSS_Success) {
        LOG_E("getSE05xPublicKey failed!");
    }
    return status;
}

#if (OPENSSL_VERSION_NUMBER >= 0x30000000)
static EVP_PKEY *set_rsa_ref_key(
    BIGNUM *n, BIGNUM *e, BIGNUM *d, BIGNUM *p, BIGNUM *q, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    EVP_PKEY *pkey    = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[9]; // Array to hold parameters
    size_t params_count  = 0;
    int len              = 0;
    unsigned char *buf_n = NULL, *buf_e = NULL, *buf_d = NULL;
    unsigned char *buf_p = NULL, *buf_q = NULL;
    unsigned char *buf_dmp1 = NULL, *buf_dmq1 = NULL, *buf_iqmp = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (ctx == NULL) {
        return NULL;
    }
    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        goto cleanup;
    }

    // Set modulus (n)
    buf_n = bn_to_bin(n, &len);
    if (buf_n == NULL) {
        goto cleanup;
    }
    // reverse the moduluse
    {
        int a       = 0;
        int b       = len - 1;
        uint8_t tmp = 0;
        for (; a < b; a++, b--) {
            if ((b < 0) || (b >= 512)) {
                goto cleanup;
            }
            tmp      = buf_n[a];
            buf_n[a] = buf_n[b];
            buf_n[b] = tmp;
        }
    }
    params[params_count++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, buf_n, len);

    // Set public exponent (e)
    buf_e = bn_to_bin(e, &len);
    if (buf_e == NULL) {
        goto cleanup;
    }
    params[params_count++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, buf_e, len);

    // Set private exponent (d)
    if (d) {
        buf_d = bn_to_bin(d, &len);
        if (buf_d == NULL) {
            goto cleanup;
        }
        params[params_count++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_D, buf_d, len);
    }

    // Set factor p
    if (p) {
        buf_p = bn_to_bin(p, &len);
        if (buf_p == NULL) {
            goto cleanup;
        }
        params[params_count++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, buf_p, len);
    }

    // Set factor q
    if (q) {
        buf_q = bn_to_bin(q, &len);
        if (buf_q == NULL) {
            goto cleanup;
        }
        params[params_count++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, buf_q, len);
    }

    // Set exponent dmp1
    if (dmp1) {
        buf_dmp1 = bn_to_bin(dmp1, &len);
        if (buf_dmp1 == NULL) {
            goto cleanup;
        }
        params[params_count++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, buf_dmp1, len);
    }

    // Set exponent dmq1
    if (dmq1) {
        buf_dmq1 = bn_to_bin(dmq1, &len);
        if (buf_dmq1 == NULL) {
            goto cleanup;
        }
        params[params_count++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, buf_dmq1, len);
    }

    // Set coefficient iqmp
    if (iqmp) {
        buf_iqmp = bn_to_bin(iqmp, &len);
        if (buf_iqmp == NULL) {
            goto cleanup;
        }
        params[params_count++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, buf_iqmp, len);
    }

    // Null-terminate the parameters array
    params[params_count] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        goto cleanup;
    }

cleanup:
    if (buf_n) {
        OPENSSL_free(buf_n);
    }
    if (buf_e) {
        OPENSSL_free(buf_e);
    }
    if (buf_d) {
        OPENSSL_free(buf_d);
    }
    if (buf_p) {
        OPENSSL_free(buf_p);
    }
    if (buf_q) {
        OPENSSL_free(buf_q);
    }
    if (buf_dmp1) {
        OPENSSL_free(buf_dmp1);
    }
    if (buf_dmq1) {
        OPENSSL_free(buf_dmq1);
    }
    if (buf_iqmp) {
        OPENSSL_free(buf_iqmp);
    }
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    return pkey;
}

static unsigned char *bn_to_bin(BIGNUM *bn, int *len)
{
    *len               = BN_num_bytes(bn);
    unsigned char *buf = OPENSSL_malloc(*len);
    if (buf == NULL) {
        return NULL;
    }
    BN_bn2nativepad(bn, buf, *len);
    return buf;
}
#endif
