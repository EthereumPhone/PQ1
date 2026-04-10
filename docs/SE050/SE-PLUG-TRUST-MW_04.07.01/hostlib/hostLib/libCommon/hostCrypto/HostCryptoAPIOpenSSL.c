/**
 * @file HostCryptoAPIOpenSSL.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Host Crypto OpenSSL wrapper implementation
 *
 * @par HISTORY
 *
 */

#include "HostCryptoAPI.h"
//#include "ax_util.h"
//#include "sm_types.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef OPENSSL

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/rand.h>
#include <openssl/des.h>
#include <openssl/ecdsa.h>


HLSE_RET_CODE   HLCRYPT_GetSupportedMechanisms(HLSE_MECHANISM_TYPE* mechanism, U32* mechanismLen)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (mechanismLen == NULL)
        return HLSE_ERR_API_ERROR;
#endif

    if (mechanism == NULL) {
        *mechanismLen = 11;
        return HLSE_SW_OK;
    }
    if (mechanism != NULL && mechanismLen != NULL && *mechanismLen < 11) {
        *mechanismLen = 11;
        return HLSE_ERR_BUF_TOO_SMALL;
    }

    *mechanismLen = 11;

    *mechanism++ = HLSE_SHA1;
    *mechanism++ = HLSE_SHA256;
    *mechanism++ = HLSE_AES_CMAC;
    *mechanism++ = HLSE_AES_ECB_ENCRYPT;
    *mechanism++ = HLSE_AES_ECB_DECRYPT;
    *mechanism++ = HLSE_AES_CBC_ENCRYPT;
    *mechanism++ = HLSE_AES_CBC_DECRYPT;
    *mechanism++ = HLSE_DES_ECB_ENCRYPT;
    *mechanism++ = HLSE_DES_ECB_DECRYPT;
    *mechanism++ = HLSE_DES_CBC_ENCRYPT;
    *mechanism++ = HLSE_DES_CBC_DECRYPT;

    return HLSE_SW_OK;

}

HLSE_RET_CODE HLCRYPT_Single_DES_CBC_Encrypt(U8 *key, U32 keylen,
    U8 *iv,
    U16 ivlen,
    U8 *inData,
    U32 inDatalen,
    U8 * outData,
    U32 *outDatalen)
{
    int nRet = HOST_CRYPTO_NOT_SUPPORTED;
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (key == NULL || inData == NULL || outData == NULL || outDatalen == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif
    return nRet;
}

HLSE_RET_CODE   HLCRYPT_Encrypt(HLSE_MECHANISM_INFO* pMechanismType, U8* inKey, U32 inKeyLen,
    U8* inData, U32 inDataLen,
    U8* outEncryptedData, U32* outEncryptedDataLen)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (pMechanismType == NULL || inKey == NULL || inData == NULL || outEncryptedDataLen == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    // { Check if user requests to obtain the length only
    if (outEncryptedData == NULL) {
        if ((pMechanismType->mechanism == HLSE_AES_ECB_ENCRYPT) || (pMechanismType->mechanism == HLSE_AES_CBC_ENCRYPT))
        {
            *outEncryptedDataLen = 16;
            return HLSE_SW_OK;
        }
        else if ((pMechanismType->mechanism == HLSE_DES_ECB_ENCRYPT) || (pMechanismType->mechanism == HLSE_DES_CBC_ENCRYPT))
        {
            *outEncryptedDataLen = 8;
            return HLSE_SW_OK;
        }
        else {
            // type requested not found
            return HLSE_ERR_API_ERROR;
        }
    }
    // } end section obtaining only the length

    if (pMechanismType->mechanism == HLSE_AES_ECB_ENCRYPT) {
        AES_KEY keyLocal;
        int keyLenBits = inKeyLen * 8;
        int nRet = 0;

        // This works assuming the plaintext has the same size as the key
        // NOTE: AES_set_encrypt_key returns 0 upon success
        nRet = AES_set_encrypt_key(inKey, keyLenBits, &keyLocal);
        if (nRet != 0)
        {
            return HOST_CRYPTO_ERROR;
        }

        // AES_ecb_encrypt has return type void
        AES_ecb_encrypt(inData, outEncryptedData, &keyLocal, AES_ENCRYPT);

        return HOST_CRYPTO_OK;
    }
    else if (pMechanismType->mechanism == HLSE_AES_CBC_ENCRYPT) {
        // int outLen = 0;
        int nRet;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        EVP_CIPHER_CTX aesCtx;
#else
        EVP_CIPHER_CTX *aesCtx = NULL;
#endif
        int outEncryptedDataLenInt = (int)(*outEncryptedDataLen);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        EVP_CIPHER_CTX_init(&aesCtx);
#else
        aesCtx = EVP_CIPHER_CTX_new();
        if (aesCtx == NULL) {
            return HOST_CRYPTO_ERROR;
        }
#endif

        if (inKeyLen != AES_BLOCK_SIZE) {
            // printf("Unsupported key length for HOST_AES_CBC_Process\r\n");
            return HLSE_ERR_API_ERROR;
        }

        // iv is passed in the pParameter
        if (pMechanismType->pParameter == NULL) {
            return HLSE_ERR_API_ERROR;
        }

        if ((inDataLen % AES_BLOCK_SIZE) != 0) {
            // printf("Input data are not block aligned for HOST_AES_CBC_Process\r\n");
            return HLSE_ERR_API_ERROR;
        }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        // EVP_EncryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_EncryptInit_ex(&aesCtx, EVP_aes_128_cbc(), NULL, inKey, pMechanismType->pParameter)) {
            return HOST_CRYPTO_ERROR;
        }

        if (!EVP_EncryptUpdate(&aesCtx, outEncryptedData, &outEncryptedDataLenInt, inData, inDataLen)) {
            *outEncryptedDataLen = (U32)outEncryptedDataLenInt;
            return HOST_CRYPTO_ERROR;
        }
#else
        // EVP_EncryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_EncryptInit_ex(aesCtx, EVP_aes_128_cbc(), NULL, inKey, pMechanismType->pParameter)) {
            return HOST_CRYPTO_ERROR;
        }

        if (!EVP_EncryptUpdate(aesCtx, outEncryptedData, &outEncryptedDataLenInt, inData, inDataLen)) {
            *outEncryptedDataLen = (U32)outEncryptedDataLenInt;
            return HOST_CRYPTO_ERROR;
        }
#endif

        *outEncryptedDataLen = (U32)outEncryptedDataLenInt;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        nRet = EVP_CIPHER_CTX_cleanup(&aesCtx);
#else
        EVP_CIPHER_CTX_free(aesCtx);
        nRet = 1;
#endif
        return nRet;
    }
    else if (pMechanismType->mechanism == HLSE_DES_ECB_ENCRYPT) {
        int nRet = 0;
        // DES_cblock key1, key2, key3;
        DES_key_schedule ks1, ks2, ks3;
        U32 i;

        if (inKeyLen >= 8) {
            nRet = DES_set_key((DES_cblock *)inKey, &ks1);
            if (nRet != 0) {
                return HOST_CRYPTO_ERROR;
            }
        }
        if (inKeyLen >= 16) {
            nRet = DES_set_key((DES_cblock *)(&inKey[8]), &ks2);
            if (nRet != 0) {
                return HOST_CRYPTO_ERROR;
            }
        }
        if (inKeyLen == 24) {
            nRet = DES_set_key((DES_cblock *)(&inKey[16]), &ks3);
            if (nRet != 0) {
                return HOST_CRYPTO_ERROR;
            }
        }

        for (i = 0; i < inDataLen; i += 8) {
            if (inKeyLen == 24) {
                DES_ecb3_encrypt((DES_cblock *)(inData + i), (DES_cblock *)(outEncryptedData + i), &ks1, &ks2, &ks3, DES_ENCRYPT);
            }
            else if (inKeyLen == 16) {
                DES_ecb2_encrypt((DES_cblock *)(inData + i), (DES_cblock *)(outEncryptedData + i), &ks1, &ks2, DES_ENCRYPT);
            }
            else {
                DES_ecb_encrypt((DES_cblock *)(inData + i), (DES_cblock *)(outEncryptedData + i), &ks1, DES_ENCRYPT);
            }
        }

        return HOST_CRYPTO_OK;
    }
    else if (pMechanismType->mechanism == HLSE_DES_CBC_ENCRYPT) {
        int nRet = 0;
        // DES_cblock key1, key2, key3;
        DES_key_schedule ks1, ks2, ks3;

        // iv is passed in the pParameter
        if (pMechanismType->pParameter == NULL) {
            return HLSE_ERR_API_ERROR;
        }

        if (inKeyLen >= 8) {
            nRet = DES_set_key((DES_cblock *)inKey, &ks1);
            if (nRet != 0) {
                return HOST_CRYPTO_ERROR;
            }
        }
        if (inKeyLen >= 16) {
            nRet = DES_set_key((DES_cblock *)(&inKey[8]), &ks2);
            if (nRet != 0) {
                return HOST_CRYPTO_ERROR;
            }
        }
        if (inKeyLen == 24) {
            nRet = DES_set_key((DES_cblock *)(&inKey[16]), &ks3);
            if (nRet != 0) {
                return HOST_CRYPTO_ERROR;
            }
        }

        if (inKeyLen == 24) {
            DES_ede3_cbc_encrypt(inData, outEncryptedData, inDataLen, &ks1, &ks2, &ks3, pMechanismType->pParameter, DES_ENCRYPT);
        }
        else if (inKeyLen == 16) {
            DES_ede2_cbc_encrypt(inData, outEncryptedData, inDataLen, &ks1, &ks2, pMechanismType->pParameter, DES_ENCRYPT);
        }
        else {
            DES_cbc_encrypt(inData, outEncryptedData, inDataLen, &ks1, pMechanismType->pParameter, DES_ENCRYPT);
        }

        return HOST_CRYPTO_OK;
    }

    return HLSE_ERR_API_ERROR;
}

HLSE_RET_CODE   HLCRYPT_Decrypt(HLSE_MECHANISM_INFO* pMechanismType, U8* inKey, U32 inKeyLen,
    U8* inData, U32 inDataLen,
    U8* outDecryptedData, U32* outDecryptedDataLen)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (pMechanismType == NULL || inKey == NULL || inData == NULL || outDecryptedDataLen == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    // { Check if user requets to obtain the length only
    if (outDecryptedData == NULL) {
        if ((pMechanismType->mechanism == HLSE_AES_ECB_DECRYPT) || (pMechanismType->mechanism == HLSE_AES_CBC_DECRYPT))
        {
            *outDecryptedDataLen = 16;
            return HLSE_SW_OK;
        }
        else if ((pMechanismType->mechanism == HLSE_DES_ECB_DECRYPT) || (pMechanismType->mechanism == HLSE_DES_CBC_DECRYPT))
        {
            *outDecryptedDataLen = 8;
            return HLSE_SW_OK;
        }
        else {
            // type requested not found
            return HLSE_ERR_API_ERROR;
        }
    }
    // } end section obtaining only the length

    if (pMechanismType->mechanism == HLSE_AES_ECB_DECRYPT) {
        AES_KEY keyLocal;
        int keyLenBits = inKeyLen * 8;
        int nRet = 0;

        // This works assuming the plaintext has the same size as the key
        // NOTE: AES_set_encrypt_key returns 0 upon success
        nRet = AES_set_decrypt_key(inKey, keyLenBits, &keyLocal);
        if (nRet != 0)
        {
            return HOST_CRYPTO_ERROR;
        }

        // AES_ecb_encrypt has return type void
        AES_ecb_encrypt(inData, outDecryptedData, &keyLocal, AES_DECRYPT);

        return HOST_CRYPTO_OK;
    }
    else if (pMechanismType->mechanism == HLSE_AES_CBC_DECRYPT) {
        // int outLen = 0;
        int nRet;
        int outDecryptedDataLenInt = (int)(*outDecryptedDataLen);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        EVP_CIPHER_CTX aesCtx;
#else
        EVP_CIPHER_CTX *aesCtx = NULL;
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        EVP_CIPHER_CTX_init(&aesCtx);
#else
        aesCtx = EVP_CIPHER_CTX_new();
        if (aesCtx == NULL) {
            return HOST_CRYPTO_ERROR;
        }
#endif

        if (inKeyLen != AES_BLOCK_SIZE) {
            // printf("Unsupported key length for HOST_AES_CBC_Process\r\n");
            return HLSE_ERR_API_ERROR;
        }

        // iv is passed in the pParameter
        if (pMechanismType->pParameter == NULL) {
            return HLSE_ERR_API_ERROR;
        }

        if ((inDataLen % AES_BLOCK_SIZE) != 0) {
            // printf("Input data are not block aligned for HOST_AES_CBC_Process\r\n");
            return HLSE_ERR_API_ERROR;
        }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        // EVP_EncryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_DecryptInit_ex(&aesCtx, EVP_aes_128_cbc(), NULL, inKey, pMechanismType->pParameter)) {
            return HOST_CRYPTO_ERROR;
        }

        if (!EVP_DecryptUpdate(&aesCtx, outDecryptedData, &outDecryptedDataLenInt, inData, inDataLen)) {
            *outDecryptedDataLen = outDecryptedDataLenInt;
            return HOST_CRYPTO_ERROR;
        }
#else
        // EVP_EncryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_DecryptInit_ex(aesCtx, EVP_aes_128_cbc(), NULL, inKey, pMechanismType->pParameter)) {
            return HOST_CRYPTO_ERROR;
        }

        if (!EVP_DecryptUpdate(aesCtx, outDecryptedData, &outDecryptedDataLenInt, inData, inDataLen)) {
            *outDecryptedDataLen = outDecryptedDataLenInt;
            return HOST_CRYPTO_ERROR;
        }
#endif

        *outDecryptedDataLen = outDecryptedDataLenInt;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        nRet = EVP_CIPHER_CTX_cleanup(&aesCtx);
#else
        EVP_CIPHER_CTX_free(aesCtx);
        nRet = 1;
#endif
        return nRet;
    }
    else if (pMechanismType->mechanism == HLSE_DES_ECB_DECRYPT) {
        int nRet = 0;
        // DES_cblock key1, key2, key3;
        DES_key_schedule ks1, ks2, ks3;
        U32 i;

        if (inKeyLen >= 8) {
            nRet = DES_set_key((DES_cblock *)inKey, &ks1);
            if (nRet != 0) {
                return HOST_CRYPTO_ERROR;
            }
        }
        if (inKeyLen >= 16) {
            nRet = DES_set_key((DES_cblock *)(&inKey[8]), &ks2);
            if (nRet != 0) {
                return HOST_CRYPTO_ERROR;
            }
        }
        if (inKeyLen == 24) {
            nRet = DES_set_key((DES_cblock *)(&inKey[16]), &ks3);
            if (nRet != 0) {
                return HOST_CRYPTO_ERROR;
            }
        }

        for (i = 0; i < inDataLen; i += 8) {
            if (inKeyLen == 24) {
                DES_ecb3_encrypt((DES_cblock *)(inData + i), (DES_cblock *)(outDecryptedData + i), &ks1, &ks2, &ks3, DES_DECRYPT);
            }
            else if (inKeyLen == 16) {
                DES_ecb2_encrypt((DES_cblock *)(inData + i), (DES_cblock *)(outDecryptedData + i), &ks1, &ks2, DES_DECRYPT);
            }
            else {
                DES_ecb_encrypt((DES_cblock *)(inData + i), (DES_cblock *)(outDecryptedData + i), &ks1, DES_DECRYPT);
            }
        }

        return HOST_CRYPTO_OK;
    }
    else if (pMechanismType->mechanism == HLSE_DES_CBC_DECRYPT) {
        int nRet = 0;
        // DES_cblock key1, key2, key3;
        DES_key_schedule ks1, ks2, ks3;

        // iv is passed in the pParameter
        if (pMechanismType->pParameter == NULL) {
            return HLSE_ERR_API_ERROR;
        }

        if (inKeyLen >= 8) {
            nRet = DES_set_key((DES_cblock *)inKey, &ks1);
            if (nRet != 0) {
                return HOST_CRYPTO_ERROR;
            }
        }
        if (inKeyLen >= 16) {
            nRet = DES_set_key((DES_cblock *)(&inKey[8]), &ks2);
            if (nRet != 0) {
                return HOST_CRYPTO_ERROR;
            }
        }
        if (inKeyLen == 24) {
            nRet = DES_set_key((DES_cblock *)(&inKey[16]), &ks3);
            if (nRet != 0) {
                return HOST_CRYPTO_ERROR;
            }
        }

        if (inKeyLen == 24) {
            DES_ede3_cbc_encrypt(inData, outDecryptedData, inDataLen, &ks1, &ks2, &ks3, pMechanismType->pParameter, DES_DECRYPT);
        }
        else if (inKeyLen == 16) {
            DES_ede2_cbc_encrypt(inData, outDecryptedData, inDataLen, &ks1, &ks2, pMechanismType->pParameter, DES_DECRYPT);
        }
        else {
            DES_cbc_encrypt(inData, outDecryptedData, inDataLen, &ks1, pMechanismType->pParameter, DES_DECRYPT);
        }

        return HOST_CRYPTO_OK;
    }

    return HLSE_ERR_API_ERROR;
}

HLSE_RET_CODE   HLCRYPT_Digest(HLSE_MECHANISM_INFO* pMechanismType,
    U8* inData, U32 inDataLen,
    U8* outDigest, U32* outDigestLen)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (pMechanismType == NULL || inData == NULL || outDigestLen == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    // Check for a request for digest Len
    if (outDigest == NULL) {
        if (pMechanismType->mechanism == HLSE_SHA256) {
            *outDigestLen = 32;
            return HLSE_SW_OK;
        }
        else if (pMechanismType->mechanism == HLSE_SHA1) {
            *outDigestLen = 20;
            return HLSE_SW_OK;
        }
        else {
            return HLSE_ERR_API_ERROR;
        }
    }

    if (pMechanismType->mechanism == HLSE_SHA256) {
        SHA256_CTX ctx256;
        int ret;

        ret = SHA256_Init(&ctx256);
        if (ret == HOST_CRYPTO_OK) {
            ret = SHA256_Update(&ctx256, inData, inDataLen);
            if (ret == HOST_CRYPTO_OK)
            {
                ret = SHA256_Final(outDigest, &ctx256);
                *outDigestLen = 32;
            }
        }

        return ret;
    }
    else if (pMechanismType->mechanism == HLSE_SHA1) {
        SHA_CTX ctx;
        int ret;

        ret = SHA1_Init(&ctx);
        if (ret == HOST_CRYPTO_OK)
        {
            ret = SHA1_Update(&ctx, inData, inDataLen);
            if (ret == HOST_CRYPTO_OK)
            {
                ret = SHA1_Final(outDigest, &ctx);
                *outDigestLen = 20;
            }
        }
        return ret;
    }

    return HLSE_ERR_API_ERROR;
}


static S32 HOST_CMAC_Init_Des(CMAC_CTX **ctx, const U8 *pKey, U8 keySizeInBytes)
{
    int ret;

    *ctx = CMAC_CTX_new();
    if (*ctx == NULL)
    {
        return HLSE_ERR_API_ERROR;
    }

    // CMAC_Init() returns
    //      1 = success
    //      0 = failure
    ret = CMAC_Init(*ctx, pKey, keySizeInBytes, EVP_des_ede3_cbc(), NULL);

    return ret;
}


HLSE_RET_CODE   HLCRYPT_Sign(HLSE_MECHANISM_INFO* pMechanismType, U8* inKey, U32 inKeyLen,
    U8* inData, U32 inDataLen,
    U8* outSignature, U32* outSignatureLen)
{

#ifndef HLSE_IGNORE_PARAM_CHECK
    if (pMechanismType == NULL || inKey == NULL || inData == NULL || outSignatureLen == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    // Check for a request to get the required signature len
    if (outSignature == NULL) {
        if (pMechanismType->mechanism == HLSE_AES_CMAC) {
            *outSignatureLen = 16; // AES_KEY_LEN_nBYTE
            return HLSE_SW_OK;
        }
        else {
            return HLSE_ERR_API_ERROR;
        }
    }

    if (pMechanismType->mechanism == HLSE_AES_CMAC) {
        int ret;
        CMAC_CTX *ctx;
        size_t outSignatureLenSizeT = (size_t)(*outSignatureLen);

        ctx = CMAC_CTX_new();
        if (ctx == NULL)
        {
            return HLSE_ERR_API_ERROR;
        }

        // CMAC_Init() returns
        //      1 = success
        //      0 = failure
        ret = CMAC_Init(ctx, inKey, inKeyLen, EVP_aes_128_cbc(), NULL);

        if (ret == HOST_CRYPTO_OK)
        {
            ret = CMAC_Update(ctx, inData, inDataLen);
            if (ret == HOST_CRYPTO_OK)
            {
                ret = CMAC_Final(ctx, outSignature, &outSignatureLenSizeT);
                *outSignatureLen = (U32)outSignatureLenSizeT;
            }
        }

        if (ret != HLSE_ERR_MEMORY)
        {
            CMAC_CTX_free(ctx);
        }

        return ret;

    }
    else if (pMechanismType->mechanism == HLSE_DES_CMAC) {
        int ret;
        size_t size;
        CMAC_CTX *ctx;

        ret = HOST_CMAC_Init_Des(&ctx, inKey, inKeyLen);
        if (ret == HOST_CRYPTO_OK)
        {
            ret = CMAC_Update(ctx, inData, inDataLen);
            if (ret == HOST_CRYPTO_OK)
            {
                ret = CMAC_Final(ctx, outSignature, &size);
            }
        }

        if (ret != HLSE_ERR_MEMORY)
        {
            CMAC_CTX_free(ctx);
        }

        return ret;
    }

    else if (pMechanismType->mechanism == HLSE_ECDSA_SIGN)
    {
        unsigned int lclOutSignatureLen = (unsigned int)(*outSignatureLen);
        int status;
        status = ECDSA_sign(0, inData, inDataLen, outSignature, &lclOutSignatureLen, (EC_KEY *)inKey);
        *outSignatureLen = lclOutSignatureLen;
        if (status == 1)
        {
            return HLSE_SW_OK;
        }
        else
        {
            return HLSE_ERR_CRYPTO_ENGINE_FAILED;
        }
    }

    return HLSE_ERR_API_ERROR;
}

HLSE_RET_CODE   HLCRYPT_Verify(HLSE_MECHANISM_INFO* pMechanismType, U8* inKey, U32 inKeyLen,
                            U8* inData, U32 inDataLen,
                            U8* inSignature, U32 inSignatureLen)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (pMechanismType == NULL || inKey == NULL || inData == NULL || inSignature == NULL ) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    if (pMechanismType->mechanism == HLSE_ECDSA_VERIFY)
    {
        int status;
        status = ECDSA_verify(0, inData, inDataLen, inSignature, inSignatureLen, (EC_KEY *)inKey);
        if (status == 1)
        {
            return HLSE_SW_OK;
        }
        else
        {
            return HLSE_ERR_CRYPTO_ENGINE_FAILED;
        }

    }
    else
    {
        return HLSE_ERR_API_ERROR;
    }
}

HLSE_RET_CODE   HLCRYPT_SignInit(HLSE_MECHANISM_INFO* pMechanismType, U8* inKey, U32 inKeyLen, HLSE_CONTEXT_HANDLE* hContext)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (pMechanismType == NULL || inKey == NULL || hContext == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    if (pMechanismType->mechanism == HLSE_AES_CMAC) {
        int ret;

        *hContext = CMAC_CTX_new();
        if (*hContext == NULL)
        {
            return HLSE_ERR_MEMORY;
        }

        // CMAC_Init() returns
        //      1 = success
        //      0 = failure
        ret = CMAC_Init(*hContext, inKey, inKeyLen, EVP_aes_128_cbc(), NULL);

        return ret;
    }

    return HLSE_ERR_API_ERROR;
}

HLSE_RET_CODE   HLCRYPT_SignUpdate(HLSE_CONTEXT_HANDLE hContext, U8* inDataPart, U32 inDataPartLen)
{
    int ret;
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (inDataPart == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif


    // CMAC_Update() returns
    //      1 = success
    //      0 = failure
    ret = CMAC_Update(hContext, inDataPart, inDataPartLen);

    return ret;
}

HLSE_RET_CODE   HLCRYPT_SignFinal(HLSE_CONTEXT_HANDLE hContext, U8* outSignature, U32* outSignatureLen)
{
    int ret;
    size_t outSignatureLenSizeT;

#ifndef HLSE_IGNORE_PARAM_CHECK
    if (outSignatureLen == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    outSignatureLenSizeT = (size_t)(*outSignatureLen);

    // Check for a request to get the required signature len
    if (outSignature == NULL)
    {
        *outSignatureLen = 16;
        return HLSE_SW_OK;
    }

    // CMAC_Final() returns
    //      1 = success
    //      0 = failure
    ret = CMAC_Final(hContext, outSignature, &outSignatureLenSizeT);
    *outSignatureLen = (U32)outSignatureLenSizeT;

    CMAC_CTX_free(hContext);

    return ret;
}

HLSE_RET_CODE    HLCRYPT_GetRandom(U32 inLen, U8 * pRandom)
{
    int nRet;
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (pRandom == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif


    nRet = RAND_bytes(pRandom, inLen);
    return nRet;
}

#endif // OPENSSL
