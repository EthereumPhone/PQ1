/*
 * Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 *
 * test_Crypto.c:  *The purpose and scope of this file*
 *
 * Project:  SecureIoTMW-Debug@simw-top-eclipse_x86
 *
 * $Date: March 03, 2020 $
 * $Author: ing05193 $
 * $Revision$
 */

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */

#include "test_Crypto.h"


/* *****************************************************************************************************************
 * Internal Definitions
 * ***************************************************************************************************************** */

#if defined(CPU_JN518X)
/* Allocate the memory for the heap. */
uint8_t __attribute__((section(".bss.$SRAM1"))) ucHeap[configTOTAL_HEAP_SIZE];
#endif

/* *****************************************************************************************************************
 * Type Definitions
 * ***************************************************************************************************************** */
#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif // AES_BLOCK_SIZE

/* *****************************************************************************************************************
 * Global and Static Variables
 * ***************************************************************************************************************** */
uint8_t AES_key[16] = { 0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x31 }; /*HELLOHELLOHELLO1*/

#define TEST_ROOT_FOLDER "."


/* Test Function */

typedef struct TestFunction
{
    const char *name;
    sss_status_t (*fpTestFunction)(struct userCtx *pUserCtx);
} TestFunction_t;

/* *****************************************************************************************************************
 * Private Functions Prototypes
 * ***************************************************************************************************************** */
static sss_status_t test_session_open_host(userCtx_t *pUserCtx);
static sss_status_t test_Init_keyStore_keyObject(userCtx_t *pUserCtx);
static sss_status_t test_get_random_number(userCtx_t *pUserCtx);
static sss_status_t test_aes_cbc_encrypt_algo_TC1(userCtx_t *pUserCtx);
static sss_status_t test_aes_cbc_encrypt_algo_TC2(userCtx_t *pUserCtx);
static sss_status_t test_aes_cbc_decrypt_algo_TC1(userCtx_t *pUserCtx);
static sss_status_t test_aes_cbc_decrypt_algo_TC2(userCtx_t *pUserCtx);
static sss_status_t test_mac_one_go_algo(userCtx_t *pUserCtx);

static sss_status_t test_cbc_encdec_algo(userCtx_t *pUserCtx,
    const uint8_t* expectedData,
    sss_mode_t mode,
    const uint8_t* srcData,
    size_t srcDataLen,
    uint8_t* destData,
    size_t destDataLen
    );



static sss_status_t test_session_close_host(userCtx_t *pUserCtx);

const TestFunction_t test_functions[] = {
    {"Open Host Session", &test_session_open_host},
    {"Init Key Store and Object", &test_Init_keyStore_keyObject},
    {"Get Random Number", &test_get_random_number},
    { "AES CBC Encrypt TC1", &test_aes_cbc_encrypt_algo_TC1 },
    {"AES CBC Encrypt TC2", &test_aes_cbc_encrypt_algo_TC2},
    {"AES CBC Decrypt TC1", &test_aes_cbc_decrypt_algo_TC1 },
    {"AES CBC Decrypt TC2", &test_aes_cbc_decrypt_algo_TC2},
    {"MAC One Go", &test_mac_one_go_algo},
    {"MAC Multi Step 1[mmm]", &test_mac_multiStep_algo_mmm},
    {"MAC Multi Step 2[mmz]", &test_mac_multiStep_algo_mmz},
    {"MAC Multi Step 3[mmp]", &test_mac_multiStep_algo_mmp},
    {"MAC Multi Step 4[mmq]", &test_mac_multiStep_algo_mmq},
    {"MAC Multi Step 5[mzm]", &test_mac_multiStep_algo_mzm},
    {"MAC Multi Step 6[mzz]", &test_mac_multiStep_algo_mzz},
    {"MAC Multi Step 7[mzp]", &test_mac_multiStep_algo_mzp},
    {"MAC Multi Step 8[mzq]", &test_mac_multiStep_algo_mzq},
    {"MAC Multi Step 9[mpm]", &test_mac_multiStep_algo_mpm},
    {"MAC Multi Step 10[mpz]", &test_mac_multiStep_algo_mpz},
    {"MAC Multi Step 11[mpp]", &test_mac_multiStep_algo_mpp},
    {"MAC Multi Step 12[mpq]", &test_mac_multiStep_algo_mpq},
    {"MAC Multi Step 13[mqm]", &test_mac_multiStep_algo_mqm},
    {"MAC Multi Step 14[mqz]", &test_mac_multiStep_algo_mqz},
    {"MAC Multi Step 15[mqp]", &test_mac_multiStep_algo_mqp},
    {"MAC Multi Step 16[mqq]", &test_mac_multiStep_algo_mqq},
    {"MAC Multi Step 17[zmm]", &test_mac_multiStep_algo_zmm},
    {"MAC Multi Step 18[zmz]", &test_mac_multiStep_algo_zmz},
    {"MAC Multi Step 19[zmp]", &test_mac_multiStep_algo_zmp},
    {"MAC Multi Step 20[zmq]", &test_mac_multiStep_algo_zmq},
    {"MAC Multi Step 21[zzm]", &test_mac_multiStep_algo_zzm},
    {"MAC Multi Step 22[zzz]", &test_mac_multiStep_algo_zzz},
    {"MAC Multi Step 23[zzp]", &test_mac_multiStep_algo_zzp},
    {"MAC Multi Step 24[zzq]", &test_mac_multiStep_algo_zzq},
    {"MAC Multi Step 25[zpm]", &test_mac_multiStep_algo_zpm},
    {"MAC Multi Step 26[zpz]", &test_mac_multiStep_algo_zpz},
    {"MAC Multi Step 27[zpp]", &test_mac_multiStep_algo_zpp},
    {"MAC Multi Step 28[zpq]", &test_mac_multiStep_algo_zpq},
    {"MAC Multi Step 29[zqm]", &test_mac_multiStep_algo_zqm},
    {"MAC Multi Step 30[zqz]", &test_mac_multiStep_algo_zqz},
    {"MAC Multi Step 31[zqp]", &test_mac_multiStep_algo_zqp},
    {"MAC Multi Step 32[zqq]", &test_mac_multiStep_algo_zqq},
    {"MAC Multi Step 33[pmm]", &test_mac_multiStep_algo_pmm},
    {"MAC Multi Step 34[pmz]", &test_mac_multiStep_algo_pmz},
    {"MAC Multi Step 35[pmp]", &test_mac_multiStep_algo_pmp},
    {"MAC Multi Step 36[pmq]", &test_mac_multiStep_algo_pmq},
    {"MAC Multi Step 37[pzm]", &test_mac_multiStep_algo_pzm},
    {"MAC Multi Step 38[pzz]", &test_mac_multiStep_algo_pzz},
    {"MAC Multi Step 39[pzp]", &test_mac_multiStep_algo_pzp},
    {"MAC Multi Step 40[pzq]", &test_mac_multiStep_algo_pzq},
    {"MAC Multi Step 41[ppm]", &test_mac_multiStep_algo_ppm},
    {"MAC Multi Step 42[ppz]", &test_mac_multiStep_algo_ppz},
    {"MAC Multi Step 43[ppp]", &test_mac_multiStep_algo_ppp},
    {"MAC Multi Step 44[ppq]", &test_mac_multiStep_algo_ppq},
    {"MAC Multi Step 45[pqm]", &test_mac_multiStep_algo_pqm},
    {"MAC Multi Step 46[pqz]", &test_mac_multiStep_algo_pqz},
    {"MAC Multi Step 47[pqp]", &test_mac_multiStep_algo_pqp},
    {"MAC Multi Step 48[pqq]", &test_mac_multiStep_algo_pqq},
    {"MAC Multi Step 49[qmm]", &test_mac_multiStep_algo_qmm},
    {"MAC Multi Step 50[qmz]", &test_mac_multiStep_algo_qmz},
    {"MAC Multi Step 51[qmp]", &test_mac_multiStep_algo_qmp},
    {"MAC Multi Step 52[qmq]", &test_mac_multiStep_algo_qmq},
    {"MAC Multi Step 53[qzm]", &test_mac_multiStep_algo_qzm},
    {"MAC Multi Step 54[qzz]", &test_mac_multiStep_algo_qzz},
    {"MAC Multi Step 55[qzp]", &test_mac_multiStep_algo_qzp},
    {"MAC Multi Step 56[qzq]", &test_mac_multiStep_algo_qzq},
    {"MAC Multi Step 57[qpm]", &test_mac_multiStep_algo_qpm},
    {"MAC Multi Step 58[qpz]", &test_mac_multiStep_algo_qpz},
    {"MAC Multi Step 59[qpp]", &test_mac_multiStep_algo_qpp},
    {"MAC Multi Step 60[qpq]", &test_mac_multiStep_algo_qpq},
    {"MAC Multi Step 61[qqm]", &test_mac_multiStep_algo_qqm},
    {"MAC Multi Step 62[qqz]", &test_mac_multiStep_algo_qqz},
    {"MAC Multi Step 63[qqp]", &test_mac_multiStep_algo_qqp},
    {"MAC Multi Step 64[qqq]", &test_mac_multiStep_algo_qqq},
    {"Close Host Session", &test_session_close_host},

    {NULL, NULL},
};

/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */

int main(int argc, const char *argv[])
{
    AX_UNUSED_ARG(argc);
    AX_UNUSED_ARG(argv);
    int ret = 0;
    sss_status_t status = kStatus_SSS_Fail;
    const TestFunction_t *pTF = NULL;
    userCtx_t userCtx;
    userCtx_t *pUserCtx = &userCtx;
    for (pTF = &test_functions[0]; pTF->name != NULL; pTF++) {
        printf("\n");
        LOG_I("########################################################");
        LOG_I("# Running: %-43s #", pTF->name);
        status = pTF->fpTestFunction(pUserCtx);
        if (status != kStatus_SSS_Success) {
            LOG_E("Failed.");
            break;
        }
        else {
            LOG_I("Success!");
        }
    }

    return ret;
}



/* *****************************************************************************************************************
 * Private Functions
 * ***************************************************************************************************************** */
static sss_status_t test_session_open_host(userCtx_t *pUserCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_type_t subsystem;

    // Must be software only.
    subsystem = kType_SSS_Software;

    status = sss_host_session_open(&pUserCtx->session,
        subsystem,
        0,
        kSSS_ConnectionType_Plain,
        TEST_ROOT_FOLDER);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("User Session Open Failed!!!");
    }


    return status;
}

static sss_status_t test_session_close_host(userCtx_t *pUserCtx)
{
    sss_status_t status = kStatus_SSS_Success;
    sss_host_session_close(&pUserCtx->session);
    return status;
}

static sss_status_t test_Init_keyStore_keyObject(userCtx_t *pUserCtx)
{
    sss_status_t status = kStatus_SSS_Fail;

    status = sss_host_key_store_context_init(&pUserCtx->ks, &pUserCtx->session);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("User key_store_context_init Failed!!!");
        goto exit;
    }
    status = sss_host_key_store_allocate(&pUserCtx->ks, __LINE__);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("User key_store_allocate Failed!!!");
        goto exit;
    }
    status = sss_host_key_object_init(&pUserCtx->key, &pUserCtx->ks);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("User key_object Failed!!!");
        goto exit;
    }
exit:
    sss_host_key_object_free(&pUserCtx->key);
    sss_host_key_store_context_free(&pUserCtx->ks);
    return status;
}

static sss_status_t test_get_random_number(userCtx_t *pUserCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    uint8_t rndData[32] = { 0 };
    size_t rndDataLen = sizeof(rndData);

    status = sss_host_rng_context_init(&pUserCtx->rng, &pUserCtx->session);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("User rng_context_init Failed!!!");
        goto exit;
    }

    status = sss_host_rng_get_random(&pUserCtx->rng, rndData, rndDataLen);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("User rng_get_random Failed!!!");
        goto exit;
    }
    LOG_AU8_I(rndData, rndDataLen);
    sss_host_rng_context_free(&pUserCtx->rng);

exit:
    return status;
}

static sss_status_t test_aes_cbc_encrypt_algo_TC1(userCtx_t *pUserCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_mode_t mode = kMode_SSS_Encrypt;
    /* clang-format off */
    const uint8_t srcData[16] = { 0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x31 }; /*HELLOHELLOHELLO1*/
    uint8_t expectedData[16] = { 0x32, 0xA6, 0x04, 0x88, 0xC5, 0xB3, 0xFF, 0x40, 0x50, 0xAF, 0x56, 0xA5, 0x68, 0xAE, 0xD1, 0x05 };
    /* clang-format on */
    uint8_t destData[16] = { 0, };
    size_t destDataLen = sizeof(destData);
    size_t srcDataLen = sizeof(srcData);
    status = test_cbc_encdec_algo(pUserCtx,
        expectedData,
        mode,
        srcData,
        srcDataLen,
        destData,
        destDataLen
        );
    return status;
}

static sss_status_t test_aes_cbc_encrypt_algo_TC2(userCtx_t *pUserCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_mode_t mode = kMode_SSS_Encrypt;
    /* clang-format off */
    const uint8_t srcData[] = { 0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x31,
                0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x31 };
    uint8_t expectedData[32] = { 0x32,0xA6,0x04,0x88,0xC5,0xB3,0xFF,0x40,0x50,0xAF,0x56,0xA5,0x68,0xAE,0xD1,0x05,0x90,
        0xCF,0x97,0xC3,0xCD,0x9E,0xC0,0x70,0x02,0xAD,0x9C,0x04,0x1B,0x90,0x3A,0x64 };
    /* clang-format on */
    size_t srcDataLen = sizeof(srcData);
    uint8_t destData[32] = { 0, };
    size_t destDataLen = sizeof(destData);
    status = test_cbc_encdec_algo(pUserCtx,
        expectedData,
        mode,
        srcData,
        srcDataLen,
        destData,
        destDataLen
        );
    return status;
}

static sss_status_t test_aes_cbc_decrypt_algo_TC1(userCtx_t *pUserCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_mode_t mode = kMode_SSS_Decrypt;
    /* clang-format off */
    const uint8_t srcData[16] = { 0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x31 }; /*HELLOHELLOHELLO1*/
    uint8_t expectedData[16] = { 0x33, 0x34, 0x9A, 0x07, 0xEA, 0x1C, 0xF6, 0xAC, 0x7F, 0x35, 0x00, 0x9A, 0x22, 0xBC, 0x8A, 0x16 };
    /* clang-format on */
    size_t srcDataLen = sizeof(srcData);

    uint8_t destData[16] = { 0, };
    size_t destDataLen = sizeof(destData);

    status = test_cbc_encdec_algo(pUserCtx,
        expectedData,
        mode,
        srcData,
        srcDataLen,
        destData,
        destDataLen
        );
    return status;

}
static sss_status_t test_aes_cbc_decrypt_algo_TC2(userCtx_t *pUserCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_mode_t mode = kMode_SSS_Decrypt;
    /* clang-format off */
    const uint8_t srcData[32] = { 0x48,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x31,
                0x48,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x48 ,0x45 ,0x4c ,0x4c ,0x4f ,0x31 };
    uint8_t expectedData[32] = { 0x33,0x34,0x9A,0x07,0xEA,0x1C,0xF6,0xAC,0x7F,0x35,0x00,0x9A,0x22,0xBC,0x8A,
                               0x16,0x7B,0x71,0xD6,0x4B,0xA5,0x54,0xB3,0xE0,0x33,0x7A,0x48,0xDF,0x6E,0xF0,0xC5,0x27 };
    /* clang-format on */
    size_t srcDataLen = sizeof(srcData);

    uint8_t destData[32] = { 0, };
    size_t destDataLen = sizeof(destData);

    status = test_cbc_encdec_algo(pUserCtx,
        expectedData,
        mode,
        srcData,
        srcDataLen,
        destData,
        destDataLen
        );
    return status;

}

static sss_status_t test_cbc_encdec_algo(userCtx_t *pUserCtx,
    const uint8_t* expectedData,
    sss_mode_t mode,
    const uint8_t* srcData,
    size_t srcDataLen,
    uint8_t* destData,
    size_t destDataLen
    )
{
    AX_UNUSED_ARG(srcDataLen);
    sss_status_t status = kStatus_SSS_Fail;
    sss_algorithm_t algorithm = kAlgorithm_SSS_AES_CBC;
    sss_key_part_t keyPart = kSSS_KeyPart_Default;
    sss_cipher_type_t cipherType = kSSS_CipherType_AES;

    uint8_t iv[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    size_t ivlen = sizeof(iv);
    size_t count = 0;

    status = sss_host_key_object_allocate_handle(&pUserCtx->key,
        __LINE__,
        keyPart,
        cipherType,
        16,
        kKeyObject_Mode_Transient);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("Userkey_object_allocate_handle Failed!!!");
        goto exit;
    }

    status = sss_host_key_store_set_key(&pUserCtx->ks,
        &pUserCtx->key,
        AES_key,
        sizeof(AES_key),
        sizeof(AES_key) * 8,
        NULL,
        0);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("Userkey_set_key Failed!!!");
        goto exit;
    }

    status = sss_host_symmetric_context_init(
        &pUserCtx->symm, &pUserCtx->session, &pUserCtx->key, algorithm, mode);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("Userkey_symmetric_context_init Failed!!!");
        goto exit;
    }

    status = sss_host_cipher_one_go(
        &pUserCtx->symm, iv, ivlen, srcData, destData, destDataLen);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("Userkey_cipher_one_go Failed!!!");
        goto exit;
    }
    LOG_AU8_I(destData, destDataLen);
    for (count = 0;count < destDataLen;count++)
    {
        if (destData[count] != expectedData[count])
        {
            LOG_E("Crypto results are wrong cipher_one_go !!!");
            status = kStatus_SSS_Fail;
            break;
        }
    }

exit:
    sss_host_key_object_free(&pUserCtx->key);
    sss_host_symmetric_context_free(&pUserCtx->symm);
    sss_host_key_store_context_free(&pUserCtx->ks);
    return status;

}



sss_status_t test_mac_one_go_algo(userCtx_t *pUserCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_key_part_t keyPart = kSSS_KeyPart_Default;
    sss_cipher_type_t cipherType = kSSS_CipherType_AES;
    sss_algorithm_t algorithm = kAlgorithm_SSS_CMAC_AES;
    sss_mode_t mode = kMode_SSS_Mac;
    /* clang-format off */
    const uint8_t srcData[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a };
    const uint8_t keystring[] = { 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
    const uint8_t expectedData[] = { 0x07,0x0a,0x16,0xb4,0x6b,0x4d,0x41,0x44,0xf7,0x9b,0xdd,0x9d,0xd0,0x4a,0x28,0x7c };
    uint8_t outdata[256] = {0,};
    size_t outdatLen = sizeof(outdata);
    size_t count = 0;
    /* clang-format on */

    status = sss_host_key_object_allocate_handle(&pUserCtx->key,
        __LINE__,
        keyPart,
        cipherType,
        16,
        kKeyObject_Mode_Transient);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("Userkey_key_object_alloc_mac_one_go Failed!!!");
        goto exit;
    }

    status = sss_host_key_store_set_key(&pUserCtx->ks,
        &pUserCtx->key,
        keystring,
        sizeof(keystring),
        sizeof(keystring) * 8,
        NULL,
        0);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("Userkey_set_key_mac_one_go Failed!!!");
        goto exit;
    }

    status = sss_host_mac_context_init(
        &pUserCtx->mac, &pUserCtx->session, &pUserCtx->key, algorithm, mode);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("Userkey_mac_init Failed !!!");
        goto exit;
    }

    status = sss_host_mac_one_go(
        &pUserCtx->mac, srcData, sizeof(srcData), outdata, &outdatLen);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("Userkey_mac_one_go Failed!!!");
        goto exit;
    }

    LOG_AU8_I(outdata, outdatLen);
    if (outdatLen != sizeof(expectedData))
    {
        LOG_E("Crypto results are wrong mismatch in length !!!");
        status = kStatus_SSS_Fail;
        goto exit;
    }
    for (count = 0;count < outdatLen;count++)
    {
        if (outdata[count] != expectedData[count])
        {
            LOG_E("Crypto results are wrong mac_one_go !!!");
            status = kStatus_SSS_Fail;
            break;
        }
    }

exit:
    sss_host_key_object_free(&pUserCtx->key);
    sss_host_mac_context_free(&pUserCtx->mac);
    sss_host_key_store_context_free(&pUserCtx->ks);
    return status;

}
