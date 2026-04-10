/* Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sss_interface.h"

#include <stdlib.h>
#include <string.h>

#include "nxEnsure.h"
#include "nxLog_App.h"

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "mbedtls/base64.h"

#if USE_SSS_DLL
#include <windows.h>
#endif

#if USE_SSS_DLL
HMODULE hDll = NULL;
#endif

/* Declare gSESession in the server and client application file
   and assign session context to it
*/
extern sss_session_t *gSESession;

int init_done            = 0;
sss_session_t *gPSession = NULL;

sss_key_store_t gkeyStore = {
    0,
};
sss_object_t priv_key_keyObject = {
    0,
};
unsigned int PRIV_KEY_ID  = 0;
unsigned int PRIV_KEY_LEN = 0;

#define KEYSTORE_ID 0x7D000022
#define CERT_ID 0x7D000021
#define MAGIC_NO               \
    {                          \
        0xA5, 0xA6, 0xB5, 0xB6 \
    }

#if USE_SSS_DLL
static pFunc_sss_key_store_context_init pSSSkeyStoreContextInit         = NULL;
static pFunc_sss_key_store_context_free pSSSkeyStoreContextFree         = NULL;
static pFunc_sss_key_store_allocate pSSSkeyStoreAllocate                = NULL;
static pFunc_sss_key_object_get_handle pSSSKeyObjectGethandle           = NULL;
static pFunc_sss_key_object_init pSSSkeyObjectInit                      = NULL;
static pFunc_sss_key_object_free pSSSkeyObjectFree                      = NULL;
static pFunc_sss_key_object_allocate_handle pSSSKeyObjectAllocatehandle = NULL;
static pFunc_sss_asymmetric_context_init pSSSAssymCtxInit               = NULL;
static pFunc_sss_asymmetric_context_free pSSSAssymCtxFree               = NULL;
static pFunc_sss_asymmetric_decrypt pSSSAssymDecrypt                    = NULL;
static pFunc_sss_asymmetric_encrypt pSSSAssymEncrypt                    = NULL;
static pFunc_sss_asymmetric_sign pSSSAssymSign                          = NULL;
static pFunc_sss_key_store_get_key pSSSKeyStoreGetKey                   = NULL;
#endif

int sss_interface_init()
{
    sss_status_t status = kStatus_SSS_Fail;
    int ret             = -1;

    LOG_I("function - %s", __FUNCTION__);

    if (init_done || gSESession == NULL) {
        return 0;
    }

    gPSession = gSESession;

#if USE_SSS_DLL
    hDll = LoadLibrary("sssapisw.dll");
    ENSURE_OR_GO_EXIT(hDll != NULL);
#endif

#if USE_SSS_DLL
    pSSSkeyStoreContextInit = (pFunc_sss_key_store_context_init)GetProcAddress(hDll, "sss_key_store_context_init");
    pSSSkeyStoreContextFree = (pFunc_sss_key_store_context_free)GetProcAddress(hDll, "sss_key_store_context_free");
    pSSSkeyStoreAllocate    = (pFunc_sss_key_store_allocate)GetProcAddress(hDll, "sss_key_store_allocate");
    pSSSkeyObjectInit       = (pFunc_sss_key_object_init)GetProcAddress(hDll, "sss_key_object_init");
    pSSSkeyObjectFree       = (pFunc_sss_key_object_free)GetProcAddress(hDll, "sss_key_object_free");
    pSSSKeyObjectAllocatehandle =
        (pFunc_sss_key_object_allocate_handle)GetProcAddress(hDll, "sss_key_object_allocate_handle");
    pSSSKeyObjectGethandle = (pFunc_sss_key_object_get_handle)GetProcAddress(hDll, "sss_key_object_get_handle");
    pSSSAssymCtxInit       = (pFunc_sss_asymmetric_context_init)GetProcAddress(hDll, "sss_asymmetric_context_init");
    pSSSAssymCtxFree       = (pFunc_sss_asymmetric_context_free)GetProcAddress(hDll, "sss_asymmetric_context_free");
    pSSSAssymDecrypt       = (pFunc_sss_asymmetric_decrypt)GetProcAddress(hDll, "sss_asymmetric_decrypt");
    pSSSAssymEncrypt       = (pFunc_sss_asymmetric_encrypt)GetProcAddress(hDll, "sss_asymmetric_encrypt");
    pSSSAssymSign          = (pFunc_sss_asymmetric_sign)GetProcAddress(hDll, "sss_asymmetric_sign_digest");
    pSSSKeyStoreGetKey     = (pFunc_sss_key_store_get_key)GetProcAddress(hDll, "sss_key_store_get_key");
#endif

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSkeyStoreContextInit != NULL);
    status = pSSSkeyStoreContextInit(&gkeyStore, gPSession);
#else
    status = sss_key_store_context_init(&gkeyStore, gPSession);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSkeyStoreAllocate != NULL);
    status = pSSSkeyStoreAllocate(&gkeyStore, KEYSTORE_ID);
#else
    status = sss_key_store_allocate(&gkeyStore, KEYSTORE_ID);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /*
    ENSURE_OR_GO_EXIT(pSSSkeyObjectInit != NULL);
    status = pSSSkeyObjectInit(&priv_key_keyObject, &gkeyStore);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    ENSURE_OR_GO_EXIT(pSSSKeyObjectAllocatehandle != NULL);
    status = pSSSKeyObjectAllocatehandle(&priv_key_keyObject,
        0x123456,
        kSSS_KeyPart_Pair,
        kSSS_CipherType_RSA,
        2048,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    */

    ret       = 0;
    init_done = 1;
exit:
    return ret;
}

void sss_interface_deinit(sss_session_t *session)
{
    LOG_I("function - %s", __FUNCTION__);

#if USE_SSS_DLL
    ENSURE_OR_RETURN(pSSSkeyStoreContextFree != NULL);
    pSSSkeyStoreContextFree(&gkeyStore);
#else
    sss_key_store_context_free(&gkeyStore);
#endif

    return;
}

int sss_interface_rsa_decrypt_data(
    unsigned char *input, unsigned int inlen, unsigned char *output, unsigned int *outLen)
{
    int ret                       = -1;
    sss_status_t status           = kStatus_SSS_Fail;
    sss_asymmetric_t assymContext = {
        0,
    };
    sss_object_t keyObject = {
        0,
    };

    unsigned int inoffset  = 0;
    unsigned int outoffset = 0;
    size_t outLenTemp      = *outLen;

    LOG_I("function - %s", __FUNCTION__);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSkeyObjectInit != NULL);
    status = pSSSkeyObjectInit(&keyObject, &gkeyStore);
#else
    status = sss_key_object_init(&keyObject, &gkeyStore);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSKeyObjectGethandle != NULL);
    status = pSSSKeyObjectGethandle(&keyObject, PRIV_KEY_ID);
#else
    status = sss_key_object_get_handle(&keyObject, PRIV_KEY_ID);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSAssymCtxInit != NULL);
    status =
        pSSSAssymCtxInit(&assymContext, gPSession, &keyObject, kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1, kMode_SSS_Decrypt);
#else
    status = sss_asymmetric_context_init(
        &assymContext, gPSession, &keyObject, kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1, kMode_SSS_Decrypt);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    while (inoffset < inlen) {
        size_t inDataLen = (inlen < PRIV_KEY_LEN) ? inlen : PRIV_KEY_LEN;

#if USE_SSS_DLL
        ENSURE_OR_GO_EXIT(pSSSAssymDecrypt != NULL);
        status = pSSSAssymDecrypt(
            &assymContext, (const uint8_t *)input + inoffset, inDataLen, (uint8_t *)output + outoffset, &outLenTemp);
#else
        status = sss_asymmetric_decrypt(
            &assymContext, (const uint8_t *)input + inoffset, inDataLen, (uint8_t *)output + outoffset, &outLenTemp);
#endif
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        outoffset = outoffset + outLenTemp;
        inoffset  = inoffset + inDataLen;
    }

    *outLen = outoffset;

    ret = 0;
exit:

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSkeyObjectFree != NULL);
    pSSSkeyObjectFree(&keyObject);
#else
    sss_key_object_free(&keyObject);
#endif

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSAssymCtxFree != NULL);
    pSSSAssymCtxFree(&assymContext);
#else
    sss_asymmetric_context_free(&assymContext);
#endif

    return ret;
}

/* Not used by OPC UA stack */
int sss_interface_rsa_encrypt_data(
    unsigned char *input, unsigned int inlen, unsigned char *output, unsigned int *outLen)
{
    int ret                       = -1;
    sss_status_t status           = kStatus_SSS_Fail;
    sss_asymmetric_t assymContext = {
        0,
    };
    sss_object_t keyObject = {
        0,
    };
    size_t outputLen = *outLen;

    LOG_I("function - %s", __FUNCTION__);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSkeyObjectInit != NULL);
    status = pSSSkeyObjectInit(&keyObject, &gkeyStore);
#else
    status = sss_key_object_init(&keyObject, &gkeyStore);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSKeyObjectGethandle != NULL);
    status = pSSSKeyObjectGethandle(&keyObject, PRIV_KEY_ID);
#else
    status = sss_key_object_get_handle(&keyObject, PRIV_KEY_ID);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSAssymCtxInit != NULL);
    status =
        pSSSAssymCtxInit(&assymContext, gPSession, &keyObject, kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1, kMode_SSS_Encrypt);
#else
    status = sss_asymmetric_context_init(
        &assymContext, gPSession, &keyObject, kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1, kMode_SSS_Encrypt);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSAssymEncrypt != NULL);
    status = pSSSAssymEncrypt(&assymContext, input, inlen, output, &outputLen);
#else
    status = sss_asymmetric_encrypt(&assymContext, (const uint8_t *)input, inlen, (uint8_t *)output, &outputLen);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    *outLen = outputLen;
    ret     = 0;
exit:

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSkeyObjectFree != NULL);
    pSSSkeyObjectFree(&keyObject);
#else
    sss_key_object_free(&keyObject);
#endif

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSAssymCtxFree != NULL);
    pSSSAssymCtxFree(&assymContext);
#else
    sss_asymmetric_context_free(&assymContext);
#endif

    return ret;
}

int sss_interface_rsa_sign_data(unsigned char *input, unsigned int inlen, unsigned char *output, unsigned int *outLen)
{
    int ret                       = -1;
    sss_status_t status           = kStatus_SSS_Fail;
    sss_asymmetric_t assymContext = {
        0,
    };
    sss_object_t keyObject = {
        0,
    };
    sss_algorithm_t algorithm = kAlgorithm_None;
    size_t outputLen          = *outLen;

    LOG_I("function - %s", __FUNCTION__);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSkeyObjectInit != NULL);
    status = pSSSkeyObjectInit(&keyObject, &gkeyStore);
#else
    status = sss_key_object_init(&keyObject, &gkeyStore);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSKeyObjectGethandle != NULL);
    status = pSSSKeyObjectGethandle(&keyObject, PRIV_KEY_ID);
#else
    status = sss_key_object_get_handle(&keyObject, PRIV_KEY_ID);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    switch (inlen) {
    case 20:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1;
        break;
    case 28:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224;
        break;
    case 32:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
        break;
    case 48:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384;
        break;
    case 64:
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512;
        break;
    default:
        LOG_E("%s - Invalid input length", __FUNCTION__);
        goto exit;
    }

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSAssymCtxInit != NULL);
    status = pSSSAssymCtxInit(&assymContext, gPSession, &keyObject, algorithm, kMode_SSS_Sign);
#else
    status = sss_asymmetric_context_init(&assymContext, gPSession, &keyObject, algorithm, kMode_SSS_Sign);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSAssymSign != NULL);
    status = pSSSAssymSign(&assymContext, input, inlen, output, &outputLen);
#else
    status = sss_asymmetric_sign_digest(&assymContext, (uint8_t *)input, inlen, (uint8_t *)output, &outputLen);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    *outLen = outputLen;
    ret     = 0;
exit:

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSkeyObjectFree != NULL);
    pSSSkeyObjectFree(&keyObject);
#else
    sss_key_object_free(&keyObject);
#endif

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSAssymCtxFree != NULL);
    pSSSAssymCtxFree(&assymContext);
#else
    sss_asymmetric_context_free(&assymContext);
#endif

    return ret;
}

int sss_interface_rsa_get_key_size()
{
    return PRIV_KEY_LEN;
}

int sss_interface_read_certificate(unsigned char **cert_buf, size_t *cert_buf_len)
{
    int ret                 = -1;
    sss_status_t status     = kStatus_SSS_Fail;
    sss_object_t certObject = {
        0,
    };
    unsigned char buf[2048] = {
        0,
    };
    size_t buf_len      = sizeof(buf);
    size_t buf_len_bits = sizeof(buf) * 8;

    LOG_I("function - %s", __FUNCTION__);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSkeyObjectInit != NULL);
    status = pSSSkeyObjectInit(&certObject, &gkeyStore);
#else
    status = sss_key_object_init(&certObject, &gkeyStore);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSKeyObjectGethandle != NULL);
    status = pSSSKeyObjectGethandle(&certObject, CERT_ID);
#else
    status = sss_key_object_get_handle(&certObject, CERT_ID);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSKeyStoreGetKey != NULL);
    status = pSSSKeyStoreGetKey(&gkeyStore, &certObject, buf, &buf_len, &buf_len_bits);
#else
    status = sss_key_store_get_key(&gkeyStore, &certObject, buf, &buf_len, &buf_len_bits);
#endif
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    *cert_buf = (unsigned char *)SSS_MALLOC(buf_len);
    memcpy(*cert_buf, buf, buf_len);
    *cert_buf_len = buf_len;

    ret = 0;
exit:
#if USE_SSS_DLL
    ENSURE_OR_GO_EXIT(pSSSkeyObjectFree != NULL);
    pSSSkeyObjectFree(&certObject);
#else
    sss_key_object_free(&certObject);
#endif
    return ret;
}

#define IGNORE_TAG 1
#define MODULUS 2
#define PUBLIC_EXP 3
#define PRIVATE_EXP 4
#define PRIME1 5
#define PRIME2 6
#define EXP1 7
#define EXP2 8
#define COEFFICIENT 9
#define END 10

int sss_interface_is_ref_key(unsigned char *pem_key, unsigned int pem_key_len)
{
    int ret                          = -1;
    unsigned char base64decode[2048] = {
        0,
    };
    size_t outLen       = sizeof(base64decode);
    char magic_no[4]    = MAGIC_NO;
    int mbedtls_ret     = 0;
    unsigned int i      = 0;
    unsigned int length = 0;
    int state           = 0;

    mbedtls_ret = mbedtls_base64_decode(base64decode,
        outLen,
        &outLen,
        pem_key + 32 /*Remove '-----BEGIN RSA PRIVATE KEY-----' and '-----END RSA PRIVATE KEY-----'*/
        ,
        pem_key_len - 63);
    ENSURE_OR_GO_EXIT(mbedtls_ret == 0);

    if (memcmp(base64decode + outLen - 4, magic_no, 4) != 0) {
        goto exit;
    }

    i = 0;
    if (base64decode[i++] == 0x30) {
        /* Verify the length */
        if (base64decode[i] == 0x81) {
            i++;
            length = base64decode[i++];
        }
        else if (base64decode[i] == 0x82) {
            i++;
            length = base64decode[i + 1] | base64decode[i] << 8;
            i      = i + 2;
        }
        else {
            length = base64decode[i++];
        }

        if (length != outLen - i) {
            goto exit;
        }
    }

    state = IGNORE_TAG;
    while (i < outLen) {
        if (base64decode[i++] == 0x02) {
            if (base64decode[i] == 0x81) {
                i++;
                length = base64decode[i++];
            }
            else if (base64decode[i] == 0x82) {
                i++;
                length = base64decode[i + 1] | base64decode[i] << 8;
                i      = i + 2;
            }
            else {
                length = base64decode[i++];
            }

            switch (state) {
            case IGNORE_TAG:
            case PUBLIC_EXP:
            case PRIVATE_EXP:
            case PRIME1:
            case EXP1:
            case EXP2:
            case COEFFICIENT: {
                i = i + length;

                if (state == IGNORE_TAG) {
                    state = MODULUS;
                }
                else if (state == PUBLIC_EXP) {
                    state = PRIVATE_EXP;
                }
                else if (state == PRIVATE_EXP) {
                    state = PRIME1;
                }
                else if (state == PRIME1) {
                    state = PRIME2;
                }
                else if (state == EXP1) {
                    state = EXP2;
                }
                else if (state == EXP2) {
                    state = COEFFICIENT;
                }
                else if (state == COEFFICIENT) {
                    state = END;
                }
                else {
                    goto exit;
                }
            } break;
            case MODULUS: {
                PRIV_KEY_LEN = length;
                if (base64decode[i] == 0x00) {
                    PRIV_KEY_LEN = PRIV_KEY_LEN - 1;
                }
                i     = i + length;
                state = PUBLIC_EXP;
            } break;
            case PRIME2: {
                unsigned int j = 0;
                while (j < length) {
                    PRIV_KEY_ID |= base64decode[i + length - j - 1] << (8 * j);
                    j++;
                }
                i     = i + length;
                state = EXP1;
            } break;
            default: {
                PRIV_KEY_LEN = 0;
                PRIV_KEY_ID  = 0;
                goto exit;
            }
            }
        }
        else {
            goto exit;
        }
    }

    ret = 1;
exit:
    return ret;
}