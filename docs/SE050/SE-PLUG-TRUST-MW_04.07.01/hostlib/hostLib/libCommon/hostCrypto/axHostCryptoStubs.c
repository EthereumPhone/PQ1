/**
 * @file axHostCryptoStubs.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2016 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Host Crypto stub implementation for the A7-series
 *
 * @par HISTORY
 *
 */

#include "axHostCrypto.h"
#include "ax_util.h"
#include "sm_types.h"
#include "sm_printf.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

// Provide here your own implementation (In case crypto is required and OpenSSL is not available)
S32 HOST_SHA1_Get(const U8 *msg, U32 msgLen, U8 *pHash)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_SHA256_Get(const U8 *msg, U32 msgLen, U8 *pHash)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_AES_ECB_DECRYPT(U8 *plainText, const U8 *cipherText, const U8 *decryptKey, U32 decryptKeyLen)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_AES_ECB_ENCRYPT(const U8 *plainText, U8 *cipherText, const U8 *encryptKey, U32 encryptKeyLen)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_AES_CBC_Process(const U8 *pKey, U32 keyLen, const U8 *pIv, U8 dir, const U8 *pIn, U32 inLen, U8 *pOut)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_CMAC_Get(const U8 *pKey, U8 keySizeInBytes, const U8* pMsg, U32 msgLen, U8 *pMac)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_CMAC_Init(axHcCmacCtx_t **ctx, const U8 *pKey,  U8 keySizeInBytes)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_CMAC_Update(axHcCmacCtx_t *ctx, const U8 *pMsg, U32 msgLen)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_CMAC_Finish(axHcCmacCtx_t *ctx, U8 *pMac)
{
    return HOST_CRYPTO_ERROR;
}
S32 HOST_GetRandom(U32 inLen, U8 *pRandom)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_3DES_CBC_Process(const U8 *pKey, U32 keyLen, const U8 *pIv, U8 dir, const U8 *pIn, U32 inLen, U8 *pOut)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_3DES_ECB_Process(const U8 *pKey, U32 keyLen, const U8 *pIv,
    U8 dir, const U8 *pIn, U32 inLen, U8 *pOut)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_CMAC_Get_Des(const U8 *pKey, U8 keySizeInBytes, const U8 *pMsg, U32 msgLen, U8* pMac)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_CMAC_Init_Des(axHcCmacCtx_t **ctx, const U8 *pKey, U8 keySizeInBytes)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_AesWrapKeyRFC3394(const U8 *wrapKey, U16 wrapKeyLen, U8 *out, U16 *outLen, const U8 *in, U16 inLen)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_AesWrapKeyRFC3394WithIV(const U8 *wrapKey, U16 wrapKeyLen, U8* iv, U8 *out, U16 *outLen, const U8 *in, U16 inLen)
{
    return HOST_CRYPTO_ERROR;
}

S32 HOST_AES_ECB_Process(const U8 *pKey, U32 keyLen, const U8 *pIv, U8 dir, const U8 *pIn, U32 inLen, U8 *pOut)
{
    return HOST_CRYPTO_ERROR;
}
