/**
 * @file axHostCryptoOpenSSL.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2016 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Host Crypto OpenSSL wrapper implementation for the A7-series
 *
 * @par HISTORY
 *
 */

#include "axHostCrypto.h"
#include "ax_util.h"
#include "sm_types.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "nxLog_hostLib.h"
#include "nxEnsure.h"

#ifdef OPENSSL
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/rand.h>
#include <openssl/des.h>
#include <openssl/evp.h>

#ifdef TGT_A70CU
S32 HOST_SHA256_GetPartialHash(const U8 *msg, U32 msgLen, U8 *pHashState, U32 *pNumProcessedMsgBytes)
{
    SHA256_CTX ctx256;
    const U32 sha256BlockSize = 64;
    int ret = HOST_CRYPTO_ERROR;

    ENSURE_OR_GO_EXIT(pHashState != NULL);
    ENSURE_OR_GO_EXIT(pNumProcessedMsgBytes != NULL);
    ret = SHA256_Init(&ctx256);
    if (ret == HOST_CRYPTO_OK)
    {
        U32 numExtraBytes = msgLen % sha256BlockSize;
        U32 numProcessedBytes = msgLen - numExtraBytes;

#ifdef PARTIAL_HASH_DEFAULT_NO_STATE
        if (numProcessedBytes > 0)
        {
#endif
            ret = SHA256_Update(&ctx256, msg, numProcessedBytes);
            if (ret == HOST_CRYPTO_OK)
            {
                SHA_LONG h;
                int i;
                for (i = 0; i < 8; i++)
                {
                    h = ctx256.h[i];
                    *pHashState++ = (h >> 24) & 0xff;
                    *pHashState++ = (h >> 16) & 0xff;
                    *pHashState++ = (h >> 8) & 0xff;
                    *pHashState++ = h  & 0xff;
                }
            }
#ifdef PARTIAL_HASH_DEFAULT_NO_STATE
        }
#endif

        *pNumProcessedMsgBytes = numProcessedBytes;
    }

exit:
    return ret;
}
#endif // TGT_A70CU

S32 HOST_SHA1_Get(const U8 *msg, U32 msgLen, U8 *pHash)
{
    SHA_CTX ctx;
    int ret;

    ret = SHA1_Init(&ctx);
    if (ret == HOST_CRYPTO_OK)
    {
        ret = SHA1_Update(&ctx, msg, msgLen);
        if (ret == HOST_CRYPTO_OK)
        {
            ret = SHA1_Final(pHash, &ctx);
        }
    }
    return ret;
}

S32 HOST_SHA256_Get(const U8 *msg, U32 msgLen, U8 *pHash)
{
    SHA256_CTX ctx256;
    int ret;

    ret = SHA256_Init(&ctx256);
    if (ret == HOST_CRYPTO_OK)
    {
        ret = SHA256_Update(&ctx256, msg, msgLen);
        if (ret == HOST_CRYPTO_OK)
        {
            ret = SHA256_Final(pHash, &ctx256);
        }
    }

    return ret;
}

S32 HOST_AES_ECB_ENCRYPT(const U8 *plainText, U8 *cipherText, const U8 *key, U32 keyLen)
{
    AES_KEY keyLocal;
    int keyLenBits = keyLen * 8;
    int nRet = 0;

    // This works assuming the plaintext has the same size as the key
    // NOTE: AES_set_encrypt_key returns 0 upon success
    nRet = AES_set_encrypt_key(key, keyLenBits, &keyLocal);
    if (nRet != 0)
    {
        return HOST_CRYPTO_ERROR;
    }

    // AES_ecb_encrypt has return type void
    AES_ecb_encrypt(plainText, cipherText, &keyLocal, AES_ENCRYPT);

    return HOST_CRYPTO_OK;
}

S32 HOST_AES_ECB_DECRYPT(U8 *plainText, const U8 *cipherText, const U8 *key, U32 keyLen)
{
    AES_KEY keyLocal;
    int keyLenBits = keyLen * 8;
    int nRet = 0;

    // This works assuming the plaintext has the same size as the key
    // NOTE: AES_set_encrypt_key returns 0 upon success
    nRet = AES_set_decrypt_key(key, keyLenBits, &keyLocal);
    if (nRet != 0)
    {
        return HOST_CRYPTO_ERROR;
    }

    // AES_ecb_encrypt has return type void
    AES_ecb_encrypt(cipherText, plainText, &keyLocal, AES_DECRYPT);

    return HOST_CRYPTO_OK;
}

S32 HOST_CMAC_Get(const U8 *pKey, U8 keySizeInBytes, const U8 *pMsg, U32 msgLen, U8* pMac)
{
    int ret;
    size_t size;
    axHcCmacCtx_t *ctx;

    ret = HOST_CMAC_Init(&ctx, pKey, keySizeInBytes);
    if (ret == HOST_CRYPTO_OK)
    {
        ret = CMAC_Update(ctx, pMsg, msgLen);
        if (ret == HOST_CRYPTO_OK)
        {
            ret = CMAC_Final(ctx, pMac, &size);
        }
    }

    if (ret != ERR_MEMORY)
    {
        CMAC_CTX_free(ctx);
    }

    return ret;
}

S32 HOST_CMAC_Init(axHcCmacCtx_t **ctx, const U8 *pKey,  U8 keySizeInBytes)
{
    int ret = ERR_GENERAL_ERROR;

    ENSURE_OR_GO_EXIT(ctx != NULL);
    *ctx = CMAC_CTX_new();
    if (*ctx == NULL)
    {
        return ERR_MEMORY;
    }

    // CMAC_Init() returns
    //      1 = success
    //      0 = failure
    ret = CMAC_Init(*ctx, pKey, keySizeInBytes, EVP_aes_128_cbc(), NULL);

exit:
    return ret;
}

S32 HOST_CMAC_Update(axHcCmacCtx_t *ctx, const U8 *pMsg, U32 msgLen)
{
    int ret;

    // CMAC_Update() returns
    //      1 = success
    //      0 = failure
    ret = CMAC_Update(ctx, pMsg, msgLen);

    return ret;
}

S32 HOST_CMAC_Finish(axHcCmacCtx_t *ctx, U8 *pMac)
{
    int ret;
    size_t size;

    // CMAC_Final() returns
    //      1 = success
    //      0 = failure
    ret = CMAC_Final(ctx, pMac, &size);
    CMAC_CTX_free(ctx);

    return ret;
}

S32 HOST_AES_CBC_Process(const U8 *pKey, U32 keyLen, const U8 *pIv,
                         U8 dir, const U8 *pIn, U32 inLen, U8 *pOut)
{
    int outLen = 0;
    int nRet = ERR_API_ERROR;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    EVP_CIPHER_CTX aesCtx; // OpenSSL 1.0
#else
    EVP_CIPHER_CTX *aesCtx = NULL;    // OpenSSL 1.1
#endif

    ENSURE_OR_GO_EXIT(pIn != NULL);
    ENSURE_OR_GO_EXIT(pOut != NULL);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    EVP_CIPHER_CTX_init(&aesCtx);
#else
    aesCtx = EVP_CIPHER_CTX_new();
    if (aesCtx == NULL) {
        return HOST_CRYPTO_ERROR;
    }
#endif

    if (keyLen != AES_BLOCK_SIZE)
    {
        // printf("Unsupported key length for HOST_AES_CBC_Process\r\n");
        return ERR_API_ERROR;
    }

    if ((inLen % AES_BLOCK_SIZE) != 0)
    {
        // printf("Input data are not block aligned for HOST_AES_CBC_Process\r\n");
        return ERR_API_ERROR;
    }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if (dir == HOST_ENCRYPT)
    {
        // EVP_EncryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_EncryptInit_ex(&aesCtx, EVP_aes_128_cbc(), NULL, pKey, pIv))
        {
            return HOST_CRYPTO_ERROR;
        }
        if (!EVP_EncryptUpdate(&aesCtx, pOut, &outLen, pIn, inLen))
        {
            return HOST_CRYPTO_ERROR;
        }
    }
    else if (dir == HOST_DECRYPT)
    {
        // EVP_DecryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_DecryptInit_ex(&aesCtx, EVP_aes_128_cbc(), NULL, pKey, pIv))
        {
            return HOST_CRYPTO_ERROR;
        }
        if (!EVP_DecryptUpdate(&aesCtx, pOut, &outLen, pIn, inLen))
        {
            return HOST_CRYPTO_ERROR;
        }
    }
#else
    if (dir == HOST_ENCRYPT)
    {
        // EVP_EncryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_EncryptInit_ex(aesCtx, EVP_aes_128_cbc(), NULL, pKey, pIv))
        {
            return HOST_CRYPTO_ERROR;
        }
        if (!EVP_EncryptUpdate(aesCtx, pOut, &outLen, pIn, inLen))
        {
            return HOST_CRYPTO_ERROR;
        }
    }
    else if (dir == HOST_DECRYPT)
    {
        // EVP_DecryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_DecryptInit_ex(aesCtx, EVP_aes_128_cbc(), NULL, pKey, pIv))
        {
            return HOST_CRYPTO_ERROR;
        }
        if (!EVP_DecryptUpdate(aesCtx, pOut, &outLen, pIn, inLen))
        {
            return HOST_CRYPTO_ERROR;
        }
    }
#endif
    else
    {
        // printf("Unsupported direction for HOST_AES_CBC_Process\r\n");
        return ERR_API_ERROR;
    }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    nRet = EVP_CIPHER_CTX_cleanup(&aesCtx);
#else
    EVP_CIPHER_CTX_free(aesCtx);
    nRet = 1;
#endif
exit:
    return nRet;
}

S32 HOST_AES_ECB_Process(const U8 *pKey, U32 keyLen, const U8 *pIv,
                         U8 dir, const U8 *pIn, U32 inLen, U8 *pOut)
{
    int outLen = 0;
    int nRet = ERR_API_ERROR;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    EVP_CIPHER_CTX aesCtx; // OpenSSL 1.0
#else
    EVP_CIPHER_CTX *aesCtx = NULL;    // OpenSSL 1.1
#endif

    ENSURE_OR_GO_EXIT(pIn != NULL);
    ENSURE_OR_GO_EXIT(pOut != NULL);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    EVP_CIPHER_CTX_init(&aesCtx);
#else
    aesCtx = EVP_CIPHER_CTX_new();
    if (aesCtx == NULL) {
        return HOST_CRYPTO_ERROR;
    }
#endif

    if (keyLen != AES_BLOCK_SIZE)
    {
        // printf("Unsupported key length for HOST_AES_CBC_Process\n");
        return ERR_API_ERROR;
    }

    if ((inLen % AES_BLOCK_SIZE) != 0)
    {
        // printf("Input data are not block aligned for HOST_AES_CBC_Process\n");
        return ERR_API_ERROR;
    }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if (dir == HOST_ENCRYPT)
    {
        // EVP_EncryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_EncryptInit_ex(&aesCtx, EVP_aes_128_ecb(), NULL, pKey, pIv))
        {
          return HOST_CRYPTO_ERROR;
        }
        if (!EVP_EncryptUpdate(&aesCtx, pOut, &outLen, pIn, inLen))
        {
          return HOST_CRYPTO_ERROR;
        }
    }
    else if (dir == HOST_DECRYPT)
    {
        // EVP_DecryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_DecryptInit_ex(&aesCtx, EVP_aes_128_ecb(), NULL, pKey, pIv))
        {
          return HOST_CRYPTO_ERROR;
        }
        if (!EVP_DecryptUpdate(&aesCtx, pOut, &outLen, pIn, inLen))
        {
          return HOST_CRYPTO_ERROR;
        }
    }
#else
    if (dir == HOST_ENCRYPT)
    {
        // EVP_EncryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_EncryptInit_ex(aesCtx, EVP_aes_128_ecb(), NULL, pKey, pIv))
        {
          return HOST_CRYPTO_ERROR;
        }
        if (!EVP_EncryptUpdate(aesCtx, pOut, &outLen, pIn, inLen))
        {
          return HOST_CRYPTO_ERROR;
        }
    }
    else if (dir == HOST_DECRYPT)
    {
        // EVP_DecryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_DecryptInit_ex(aesCtx, EVP_aes_128_ecb(), NULL, pKey, pIv))
        {
          return HOST_CRYPTO_ERROR;
        }
        if (!EVP_DecryptUpdate(aesCtx, pOut, &outLen, pIn, inLen))
        {
          return HOST_CRYPTO_ERROR;
        }
    }
#endif
    else
    {
        // printf("Unsupported direction for HOST_AES_CBC_Process\n");
        return ERR_API_ERROR;
    }

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    nRet = EVP_CIPHER_CTX_cleanup(&aesCtx);
#else
    EVP_CIPHER_CTX_free(aesCtx);
    nRet = 1;
#endif

exit:
    return nRet;
}

S32 HOST_GetRandom(U32 inLen, U8 *pRandom)
{
    int nRet;

    nRet = RAND_bytes(pRandom, inLen);
    return nRet;
}

S32 HOST_3DES_CBC_Process(const U8 *pKey, U32 keyLen, const U8 *pIv,
                          U8 dir, const U8 *pIn, U32 inLen, U8 *pOut)
{
    //DES_ecb3_encrypt();
    int outLen = 0;
    int nRet = ERR_API_ERROR;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    EVP_CIPHER_CTX desCtx;
#else
    EVP_CIPHER_CTX *desCtx = NULL;
#endif

    ENSURE_OR_GO_EXIT(pIn != NULL);
    ENSURE_OR_GO_EXIT(pOut != NULL);

    if (keyLen == 8) {
        DES_key_schedule ks1;
        nRet = DES_set_key((DES_cblock *)pKey, &ks1);  // C_Block -> DES_cblock
        if (nRet != 0) {
            return ERR_API_ERROR;
        }
        DES_cbc_encrypt(pIn, pOut, inLen, &ks1, (void *)pIv, DES_ENCRYPT);

        return HOST_CRYPTO_OK;
    }

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    EVP_CIPHER_CTX_init(&desCtx);
#else
    desCtx = EVP_CIPHER_CTX_new();
    if (desCtx == NULL) {
        return HOST_CRYPTO_ERROR;
    }
#endif

    if (keyLen != 16)
    {
        // printf("Unsupported key length for HOST_AES_CBC_Process\n");
        return ERR_API_ERROR;
    }

    if ((inLen % 8) != 0)
    {
        // printf("Input data are not block aligned for HOST_AES_CBC_Process\n");
        return ERR_API_ERROR;
    }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if (dir == HOST_ENCRYPT)
    {
        if (!EVP_EncryptInit_ex(&desCtx, EVP_des_ede_cbc(), NULL, pKey, pIv))
        {
            return HOST_CRYPTO_ERROR;
        }
        if (!EVP_EncryptUpdate(&desCtx, pOut, &outLen, pIn, inLen))
        {
            return HOST_CRYPTO_ERROR;
        }
    }
    else if (dir == HOST_DECRYPT)
    {
        // EVP_DecryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_DecryptInit_ex(&desCtx, EVP_des_ede_cbc(), NULL, pKey, pIv))
        {
            return HOST_CRYPTO_ERROR;
        }
        if (!EVP_DecryptUpdate(&desCtx, pOut, &outLen, pIn, inLen))
        {
            return HOST_CRYPTO_ERROR;
        }
    }
#else
    if (dir == HOST_ENCRYPT)
    {
        if (!EVP_EncryptInit_ex(desCtx, EVP_des_ede_cbc(), NULL, pKey, pIv))
        {
            return HOST_CRYPTO_ERROR;
        }
        if (!EVP_EncryptUpdate(desCtx, pOut, &outLen, pIn, inLen))
        {
            return HOST_CRYPTO_ERROR;
        }
    }
    else if (dir == HOST_DECRYPT)
    {
        // EVP_DecryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_DecryptInit_ex(desCtx, EVP_des_ede_cbc(), NULL, pKey, pIv))
        {
            return HOST_CRYPTO_ERROR;
        }
        if (!EVP_DecryptUpdate(desCtx, pOut, &outLen, pIn, inLen))
        {
            return HOST_CRYPTO_ERROR;
        }
    }
#endif
    else
    {
        // printf("Unsupported direction for HOST_AES_CBC_Process\n");
        return ERR_API_ERROR;
    }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    nRet = EVP_CIPHER_CTX_cleanup(&desCtx);
#else
    EVP_CIPHER_CTX_free(desCtx);
    nRet = 1;
#endif

exit:
    return nRet;
}

S32 HOST_3DES_ECB_Process(const U8 *pKey, U32 keyLen, const U8 *pIv,
                          U8 dir, const U8 *pIn, U32 inLen, U8 *pOut)
{
    //DES_ecb3_encrypt();
    int outLen = 0;
    int nRet = ERR_API_ERROR;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    EVP_CIPHER_CTX desCtx;
#else
    EVP_CIPHER_CTX *desCtx = NULL;
#endif

    ENSURE_OR_GO_EXIT(pIn != NULL);
    ENSURE_OR_GO_EXIT(pOut != NULL);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    EVP_CIPHER_CTX_init(&desCtx);
#else
    desCtx = EVP_CIPHER_CTX_new();
    if (desCtx == NULL) {
        return HOST_CRYPTO_ERROR;
    }
#endif

    if (keyLen != 16)
    {
        // printf("Unsupported key length for HOST_AES_CBC_Process\n");
        return ERR_API_ERROR;
    }

    if ((inLen % 8) != 0)
    {
        // printf("Input data are not block aligned for HOST_AES_CBC_Process\n");
        return ERR_API_ERROR;
    }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if (dir == HOST_ENCRYPT)
    {
        if (!EVP_EncryptInit_ex(&desCtx, EVP_des_ede_ecb(), NULL, pKey, pIv))
        {
            return HOST_CRYPTO_ERROR;
        }
        if (!EVP_EncryptUpdate(&desCtx, pOut, &outLen, pIn, inLen))
        {
            return HOST_CRYPTO_ERROR;
        }
    }
    else if (dir == HOST_DECRYPT)
    {
        // EVP_DecryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_DecryptInit_ex(&desCtx, EVP_des_ede_ecb(), NULL, pKey, pIv))
        {
            return HOST_CRYPTO_ERROR;
        }
        if (!EVP_DecryptUpdate(&desCtx, pOut, &outLen, pIn, inLen))
        {
            return HOST_CRYPTO_ERROR;
        }
    }
#else
    if (dir == HOST_ENCRYPT)
    {
        if (!EVP_EncryptInit_ex(desCtx, EVP_des_ede_ecb(), NULL, pKey, pIv))
        {
            return HOST_CRYPTO_ERROR;
        }
        if (!EVP_EncryptUpdate(desCtx, pOut, &outLen, pIn, inLen))
        {
            return HOST_CRYPTO_ERROR;
        }
    }
    else if (dir == HOST_DECRYPT)
    {
        // EVP_DecryptInit_ex returns 0 on failure and 1 upon success
        if (!EVP_DecryptInit_ex(desCtx, EVP_des_ede_ecb(), NULL, pKey, pIv))
        {
            return HOST_CRYPTO_ERROR;
        }
        if (!EVP_DecryptUpdate(desCtx, pOut, &outLen, pIn, inLen))
        {
            return HOST_CRYPTO_ERROR;
        }
    }
#endif
    else
    {
        // printf("Unsupported direction for HOST_AES_CBC_Process\n");
        return ERR_API_ERROR;
    }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    nRet = EVP_CIPHER_CTX_cleanup(&desCtx);
#else
    EVP_CIPHER_CTX_free(desCtx);
    nRet = 1;
#endif

exit:
    return nRet;
}

S32 HOST_CMAC_Get_Des(const U8 *pKey, U8 keySizeInBytes, const U8 *pMsg, U32 msgLen, U8* pMac)
{
  int ret;
  size_t size;
  axHcCmacCtx_t *ctx;

  ret = HOST_CMAC_Init_Des(&ctx, pKey, keySizeInBytes);
  if (ret == HOST_CRYPTO_OK)
  {
    ret = CMAC_Update(ctx, pMsg, msgLen);
    if (ret == HOST_CRYPTO_OK)
    {
      ret = CMAC_Final(ctx, pMac, &size);
    }
  }

  if (ret != ERR_MEMORY)
  {
    CMAC_CTX_free(ctx);
  }

  return ret;
}

S32 HOST_CMAC_Init_Des(axHcCmacCtx_t **ctx, const U8 *pKey,  U8 keySizeInBytes)
{
    int ret = ERR_GENERAL_ERROR;

    ENSURE_OR_GO_EXIT(ctx != NULL);
    *ctx = CMAC_CTX_new();
    if (*ctx == NULL) {
        return ERR_MEMORY;
    }

    // CMAC_Init() returns
    //      1 = success
    //      0 = failure
    ret = CMAC_Init(*ctx, pKey, keySizeInBytes, EVP_des_ede3_cbc(), NULL);

exit:
    return ret;
}


/**
* Key wrapping according to RFC3394 (https://tools.ietf.org/html/rfc3394)
* \note Only tested with an 128 bits wrapKey. When wrapping a 128 bit key (16 byte), the resulting
*  wrapped key is 24 byte long.
* @param[in] wrapKey Secret key used to wrap \p in. Also called KEK (key encryption key)
* @param[in] wrapKeyLen Length in byte of wrapKey
* @param[in,out] out IN: buffer of at least \p outLen byte; OUT: wrapped key
* @param[in,out] outLen IN: size of buffer \p out provided; OUT: actual length of wrapped key
* @param[in] in Key to be wrapped
* @param[in] inLen Length in byte of key to be wrapped
*/
S32 HOST_AesWrapKeyRFC3394(const U8 *wrapKey, U16 wrapKeyLen, U8 *out, U16 *outLen, const U8 *in, U16 inLen)
{
    unsigned char *iv = NULL;
    int ret = 0;
    AES_KEY wctx;
    int keybits = wrapKeyLen * 8;
    S32 rv = ERR_GENERAL_ERROR;

    ENSURE_OR_GO_EXIT(outLen != NULL);

    if (*outLen < (inLen + 8))
    {
        return ERR_API_ERROR;
    }

    if (AES_set_encrypt_key(wrapKey, keybits, &wctx))
    {
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    ret = AES_wrap_key(&wctx, iv, out, in, inLen);
    if (ret <= 0)
    {
        return ERR_API_ERROR;
    }

    *outLen = (U16)ret;

    rv = 1;
exit:
    return rv; // OpenSSL success code
}

S32 HOST_AesWrapKeyRFC3394WithIV(const U8 *wrapKey, U16 wrapKeyLen, U8* iv, U8 *out, U16 *outLen, const U8 *in, U16 inLen)
{
    int ret = 0;
    AES_KEY wctx;
    int keybits = wrapKeyLen * 8;
    S32 rv = ERR_GENERAL_ERROR;

    ENSURE_OR_GO_EXIT(outLen != NULL);

    if (*outLen < (inLen + 8))
    {
        return ERR_API_ERROR;
    }

    if (AES_set_encrypt_key(wrapKey, keybits, &wctx))
    {
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    ret = AES_wrap_key(&wctx, iv, out, in, inLen);
    if (ret <= 0)
    {
        return ERR_API_ERROR;
    }

    *outLen = (U16)ret;

    rv = 1;
exit:
    return rv; // OpenSSL success code
}

#endif // OPENSSL
