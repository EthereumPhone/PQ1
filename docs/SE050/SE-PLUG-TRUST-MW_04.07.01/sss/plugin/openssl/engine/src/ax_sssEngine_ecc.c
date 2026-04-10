/**
 * @file ax_sssEngine_ecc.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Engine for NXP Embedded Secure Element over SSS API's
 *
 * The following operations are supported by this engine:
 * - Random number generation
 * - ECC sign
 * - ECC verify
 * - ECDH compute_key
 *
 * When dealing with an EC key argument whose a public key is used:
 * - In case the key is a 'reference key' -> use the referenced public key
 * - In case the above does not apply; at compile time one can choose between two
 *   strategies:
 *   (1) return a fail
 *   (2) delegate the operation to the OpenSSL SW implementation
 *
 * When dealing with an EC key argument whose private key is used:
 * - In case the key is a 'reference key' -> use the referenced private key
 * - In case the above does not apply; at compile time one can choose between two
 *   strategies:
 *   (1) return a fail
 *   (2) delegate the operation to the OpenSSL SW implementation
 *
 * @note
 *   Compatible with:
 *   - OpenSSL 1.0.2
 *   - OpenSSL 1.1.0
 *
 */

/*
 * This file contains source code form OpenSSL distribution that is covered
 * by the LICENSE-OpenSSL file to be found in the root of this source code
 * distribution tree.
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_ECC || (SSS_HAVE_APPLET_NONE && (SSS_HAVE_HOSTCRYPTO_OPENSSL || SSS_HAVE_HOSTCRYPTO_MBEDTLS))

#include <ex_sss.h>
#include <stdlib.h>
//#include <malloc.h>
#include <fsl_sss_util_asn1_der.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "ax_api.h"
#include "ax_embSeEngine.h"
#include "ax_embSeEngine_Internal.h"
#include "sm_printf.h"

#define ECDH_MAX_LEN 32
#define EMBSE_MAX_ECC_PUBKEY_BUF (2 * 96 + 1) // Corresponds to 768 bit ECC key

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
EC_KEY_METHOD *EmbSe_EC = NULL;
const EC_KEY_METHOD *EmbSe_EC_Default = NULL;
#endif

/* ecdsa_method struct definition from */
struct ecdsa_method
{
    const char *name;
    ECDSA_SIG *(*ecdsa_do_sign)(
        const unsigned char *dgst, int dgst_len, const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey);
    int (*ecdsa_sign_setup)(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv, BIGNUM **r);
    int (*ecdsa_do_verify)(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig, EC_KEY *eckey);
#if 0
    int (*init)(EC_KEY *eckey);
    int (*finish)(EC_KEY *eckey);
#endif
    int flags;
    char *app_data;
};

/* ecdh_method struct definition from ech_locl.h*/
struct ecdh_method
{
    const char *name;
    int (*compute_key)(void *key,
        size_t outlen,
        const EC_POINT *pub_key,
        EC_KEY *ecdh,
        void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
#if 0
    int (*init)(EC_KEY *eckey);
    int (*finish)(EC_KEY *eckey);
#endif
    int flags;
    char *app_data;
};

/**
 * Either zero sign extend \p pIn so it becomes \p expectedLen byte long
 * or truncate the right most byte.
 * The caller must ensure \p expectedLen is bigger than \p actualLen
 * @param[in,out]   pOut
 * @param[in]       expectedLen Zero sign extend/truncate until this length.
 * @param[in]       pIn  Array representation of big number, to be zero sign extended or truncated
 * @param[in]       actualLen Length of incoming array \p pIn
 *
 * @retval SW_OK In case of successfull execution
 * @retval ERR_API_ERROR Requested adjustment would result in truncation
 */
static U16 axAdaptSize(U8 *pOut, U16 expectedLen, const U8 *pIn, U16 actualLen)
{
    U16 sw = SW_OK;

    int numExtraByte = (int)expectedLen - (int)actualLen;

    if (numExtraByte == 0) {
        memcpy(pOut, pIn, actualLen);
    }
    else if (numExtraByte < 0) {
        memcpy(pOut, pIn, expectedLen);
    }
    else {
        memcpy(pOut + numExtraByte, pIn, actualLen);
        memset(pOut, 0x00, numExtraByte);
    }

    return sw;
}

/**
 Return SW_OK when the ecKey passed as argument is a reference key.
 Upon successfull execution keyId is retrieved from the reference key.

 @return ERR_PATTERN_COMPARE_FAILED  Not a reference key
 @return ERR_IDENT_IDX_RANGE         Not a valid keyId (for future expansion)
 @return ERR_NO_PRIVATE_KEY          No private key present
*/
static U16 getEcKeyReference(const EC_KEY *eckey, uint32_t *keyId)
{
    U16 sw = ERR_PATTERN_COMPARE_FAILED;
    const BIGNUM *prv_key_bn;
    U8 tmpBuf[EMBSE_MAX_ECC_PUBKEY_BUF] = {0};
    int privKeylen = 0;
    U8 Ident = 0;
    U8 Index = 0;
    U32 Coeff[2] = {0, 0};
    int i = 0;
    int j = 0;

    *keyId = 0;
    /* Test for private key */
    prv_key_bn = EC_KEY_get0_private_key(eckey);
    if (prv_key_bn) {
        privKeylen = BN_bn2bin(prv_key_bn, tmpBuf);

        if (privKeylen == 0) {
            return ERR_PATTERN_COMPARE_FAILED;
        }
        /* Get Ident and Index, not used */
        if (privKeylen < 2) {
            return ERR_PATTERN_COMPARE_FAILED;
        }
        Ident = tmpBuf[privKeylen - 2];
        Index = tmpBuf[privKeylen - 1];
        /* Get double ID string */
        if (privKeylen < 14 /* Based on for loops below. 2 Magic numbers + key id */) {
            return ERR_PATTERN_COMPARE_FAILED;
        }
        for (j = 0; j < 2; j++) {
            for (i = 3; i < 7; i++) {
                Coeff[j] |= (U32)tmpBuf[privKeylen - i - (j * 4)] << 8 * (i - 3);
            }
        }
        if (((unsigned int)Coeff[0] == (unsigned int)EMBSE_REFKEY_ID) &&
            ((unsigned int)Coeff[1] == (unsigned int)EMBSE_REFKEY_ID)) {
            j = 2;
            for (i = 3; i < 7; i++) {
                *keyId |= (uint32_t)tmpBuf[privKeylen - i - (j * 4)] << 8 * (i - 3);
            }
            sw = SW_OK;
            EmbSe_Print(LOG_DBG_ON, "Using keyId=0x%08X\n", *keyId);
        }
        else {
            sw = ERR_PATTERN_COMPARE_FAILED;
        }
    }
    else {
        sw = ERR_NO_PRIVATE_KEY;
    }

    return sw;
}

static U16 getMatchingShaAlgo(U16 dgstLen, sss_algorithm_t *shaAlgo)
{
    switch (dgstLen) {
    case 20:
        *shaAlgo = kAlgorithm_SSS_SHA1;
        break;
    case 28:
        *shaAlgo = kAlgorithm_SSS_SHA224;
        break;
    case 32:
        *shaAlgo = kAlgorithm_SSS_SHA256;
        break;
    case 48:
        *shaAlgo = kAlgorithm_SSS_SHA384;
        break;
    case 64:
        *shaAlgo = kAlgorithm_SSS_SHA512;
        break;
    default:
        EmbSe_Print(LOG_ERR_ON, "Cannot handle matching digest size %d\n", dgstLen);
        return ERR_PATTERN_COMPARE_FAILED;
    }

    EmbSe_Print(LOG_DBG_ON, "shaAlgo: %d\n", *shaAlgo);
    return SW_OK;
}

/**
 * The RAW public key value must be encapsulated in a proper ASN.1 structure.
 * This is equivalent to concatenating a fixed header (per keytype) with the raw public data
 * We call this process 'decorating'.
 * \param[in] nid OpenSSL specific value
 * \param[in,out] decoratedKey IN: Buffer provided by caller; OUT: Concatenation of ASN.1 header and raw public key
 * \param[in,out] decoratedKeyLen IN: Length of buffer provided by caller; OUT: Size of decoratedKey
 * \param[in] keyValue Raw public key The length of the info data passed as argument
 * \param[in] keyValueLen Length of raw public key
 * \retval ::SW_OK Successfull execution
 */
static U16 decoratePublicKey(int nid, U8 *decoratedKey, U16 *decoratedKeyLen, const U8 *keyValue, size_t keyValueLen)
{
    const U8 *decoration = NULL;
    size_t decorationLen = 0;

    switch (nid) {
    case NID_X9_62_prime192v1:
        decoration = gecc_der_header_nist192;
        decorationLen = der_ecc_nistp192_header_len;
        // memcpy(decoratedKey, gecc_der_header_nist192, der_ecc_nistp192_header_len);
        break;
    case NID_secp224r1:
        decoration = gecc_der_header_nist224;
        decorationLen = der_ecc_nistp224_header_len;
        break;
    case NID_X9_62_prime256v1:
        decoration = gecc_der_header_nist256;
        decorationLen = der_ecc_nistp256_header_len;
        break;
    case NID_secp384r1:
        decoration = gecc_der_header_nist384;
        decorationLen = der_ecc_nistp384_header_len;
        break;
    case NID_secp521r1:
        decoration = gecc_der_header_nist521;
        decorationLen = der_ecc_nistp521_header_len;
        break;
    case NID_brainpoolP160r1:
        decoration = gecc_der_header_bp160;
        decorationLen = der_ecc_bp160_header_len;
        break;
    case NID_brainpoolP192r1:
        decoration = gecc_der_header_bp192;
        decorationLen = der_ecc_bp192_header_len;
        break;
    case NID_brainpoolP224r1:
        decoration = gecc_der_header_bp224;
        decorationLen = der_ecc_bp224_header_len;
        break;
    case NID_brainpoolP256r1:
        decoration = gecc_der_header_bp256;
        decorationLen = der_ecc_bp256_header_len;
        break;
    case NID_brainpoolP320r1:
        decoration = gecc_der_header_bp320;
        decorationLen = der_ecc_bp320_header_len;
        break;
    case NID_brainpoolP384r1:
        decoration = gecc_der_header_bp384;
        decorationLen = der_ecc_bp384_header_len;
        break;
    case NID_brainpoolP512r1:
        decoration = gecc_der_header_bp512;
        decorationLen = der_ecc_bp512_header_len;
        break;
    case NID_secp160k1:
        decoration = gecc_der_header_160k;
        decorationLen = der_ecc_160k_header_len;
        break;
    case NID_secp192k1:
        decoration = gecc_der_header_192k;
        decorationLen = der_ecc_192k_header_len;
        break;
    case NID_secp224k1:
        decoration = gecc_der_header_224k;
        decorationLen = der_ecc_224k_header_len;
        break;
    case NID_secp256k1:
        decoration = gecc_der_header_256k;
        decorationLen = der_ecc_256k_header_len;
        break;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
    case NID_X448:
        decoration = gecc_der_header_mont_dh_448;
        decorationLen = der_ecc_mont_dh_448_header_len;
        break;
#endif
    default:
        return ERR_PATTERN_COMPARE_FAILED;
    }

    if ((SIZE_MAX - decorationLen) < keyValueLen) {
        return ERR_COMM_ERROR;
    }
    if ((decorationLen + keyValueLen) > *decoratedKeyLen) {
        // Avoid bufferoverlow
        return ERR_BUF_TOO_SMALL;
    }

    memcpy(decoratedKey, decoration, decorationLen);
    memcpy(decoratedKey + decorationLen, keyValue, keyValueLen);
    *decoratedKeyLen = (U16)(decorationLen + keyValueLen);

    return SW_OK;
}

static U16 getCipherTypeFromNid(int nid, uint32_t *cipherType)
{
    U16 status = SW_OK;

    switch (nid) {
    case NID_X9_62_prime192v1:
    case NID_secp224r1:
    case NID_X9_62_prime256v1:
    case NID_secp384r1:
    case NID_secp521r1:
        *cipherType = kSSS_CipherType_EC_NIST_P;
        break;

    case NID_brainpoolP192r1:
    case NID_brainpoolP224r1:
    case NID_brainpoolP320r1:
    case NID_brainpoolP384r1:
    case NID_brainpoolP160r1:
    case NID_brainpoolP256r1:
    case NID_brainpoolP512r1:
        *cipherType = kSSS_CipherType_EC_BRAINPOOL;
        break;

    case NID_secp160k1:
    case NID_secp192k1:
    case NID_secp224k1:
    case NID_secp256k1:
        *cipherType = kSSS_CipherType_EC_NIST_K;
        break;

    default:
        EmbSe_Print(LOG_DBG_ON, "nid %d not supported\n", nid);
        status = ERR_PATTERN_COMPARE_FAILED;
        break;
    }
    return status;
}

// EmbSE ECDSA Implementation
// --------------------------
static ECDSA_SIG *EmbSe_ECDSA_Do_Sign(
    const unsigned char *dgst, int dgst_len, const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey)
{
    U8 sigDER[256];
    size_t sigDERLen = sizeof(sigDER);
    U16 sw;
    sss_status_t status;
    sss_object_t keyPair;
    sss_asymmetric_t asymm;
    ECDSA_SIG *pSig;
    EC_KEY *dup_eckey = NULL;
    U8 *pp;
    uint32_t keyId;
    U8 dgstBuf[96];
    U16 dgstBufLen = sizeof(dgstBuf);

    sw = getEcKeyReference(eckey, &keyId);
    if (sw == SW_OK) {
        int dgstLenMatchingKey = 0;
        sss_algorithm_t shaAlgo_matchOnSize = kAlgorithm_SSS_SHA256;

        dgstLenMatchingKey = dgst_len;
        if (dgstLenMatchingKey > dgstBufLen) {
            EmbSe_Print(LOG_ERR_ON, "Buffer allocated for digest too small.\n");
            return NULL;
        }

        sw = getMatchingShaAlgo(dgstLenMatchingKey, &shaAlgo_matchOnSize);
        if (sw != SW_OK) {
            return NULL;
        }

        axAdaptSize(dgstBuf, dgstLenMatchingKey, dgst, dgst_len);

        EmbSe_Print(LOG_FLOW_ON, "SSS based sign (keyId=0x%08X, dgstLen=%d)\n", keyId, dgst_len);
        status = sss_key_object_init(&keyPair, &gpCtx->ks);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "sss_key_object_init for keyPair failed\n");
            return NULL;
        }

        status = sss_key_object_get_handle(&keyPair, keyId);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "sss_key_object_get_handle for keyPair failed\n");
            sss_key_object_free(&keyPair);
            return NULL;
        }

        status = sss_asymmetric_context_init(&asymm, &gpCtx->session, &keyPair, shaAlgo_matchOnSize, kMode_SSS_Sign);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "sss_asymmetric_context_init for sign failed\n");
            sss_key_object_free(&keyPair);
            return NULL;
        }

        /* Do Signing */
        status = sss_asymmetric_sign_digest(&asymm, dgstBuf, dgstLenMatchingKey, sigDER, &sigDERLen);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "sss_asymmetric_sign_digest failed\n");
            sss_asymmetric_context_free(&asymm);
            sss_key_object_free(&keyPair);
            return NULL;
        }

        EmbSe_Print(LOG_FLOW_ON, "SSS based sign called successfully (sigDERLen=%zu)\n", sigDERLen);

        /* sig is DER encoded. Transform to ECDSA_SIG and return this */
        pp = (U8 *)sigDER;
        pSig = ECDSA_SIG_new();

        if (pSig == NULL) {
            EmbSe_Print(LOG_ERR_ON, "ECDSA_SIG_new call failed\n");
            sss_asymmetric_context_free(&asymm);
            sss_key_object_free(&keyPair);
            return NULL;
        }

        if (d2i_ECDSA_SIG((ECDSA_SIG **)&pSig, (const unsigned char **)&pp, (long)sigDERLen) == NULL) {
            EmbSe_Print(LOG_ERR_ON, "d2i_ECDSA_SIG failed\n");
            sss_asymmetric_context_free(&asymm);
            sss_key_object_free(&keyPair);
            return NULL;
        }

        // EmbSe_Print(LOG_FLOW_ON, "Clean up SSS data structures.\n");
        sss_asymmetric_context_free(&asymm);
        sss_key_object_free(&keyPair);
        EmbSe_Print(LOG_FLOW_ON, "EmbSe_ECDSA_Do_Sign success.\n");
        return pSig;
    }
    else if (sw == ERR_NO_PRIVATE_KEY) {
        EmbSe_Print(LOG_ERR_ON, "Expecting private key (by value or reference): 0x%04X.\n", sw);
        return NULL;
    }
    else if (sw == ERR_PATTERN_COMPARE_FAILED) {
#ifdef PRIVATE_KEY_HANDOVER_TO_SW
        // Invoke OpenSSL sign API if no valid key reference is detected
        EmbSe_Print(LOG_FLOW_ON, "No matching key in Secure Element. Invoking OpenSSL API: ECDSA_do_sign_ex.\n");
        /* Create a duplicate key */
        dup_eckey = EC_KEY_dup(eckey);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        /* Attach OpenSSL's SW method to duplicate key */
        if (!ECDSA_set_method(dup_eckey, ECDSA_OpenSSL())) {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL ECDSA_set_method failure..\n");
            return NULL;
        }
#else
        /* Attach OpenSSL's SW method to duplicate key */
        if (!EC_KEY_set_method(dup_eckey, EC_KEY_OpenSSL())) {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL EC_KEY_set_method failure..\n");
            return NULL;
        }
#endif
        /* Invoke OpenSSL's sign API and return result */
        return ECDSA_do_sign_ex(dgst, dgst_len, inv, rp, dup_eckey);
#else
        EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Sign expected a reference key: 0x%04X.\n", sw);
        return NULL;
#endif
    }
    else {
        EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Sign unexpected key type: 0x%04X.\n", sw);
        return NULL;
    }
}

static int EmbSe_ECDSA_Sign_Setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv, BIGNUM **r)
{
    AX_UNUSED_ARG(eckey);
    AX_UNUSED_ARG(ctx);
    AX_UNUSED_ARG(kinv);
    AX_UNUSED_ARG(r);
    return 1;
}

static int EmbSe_ECDSA_Do_Verify(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig, EC_KEY *eckey)
{
    U16 sw;
    sss_status_t status;
    sss_object_t pubKey;
    sss_asymmetric_t asymm;
    int nRet = 0;
    int flagHandleKey = AX_ENGINE_INVOKE_NOTHING;
    EC_KEY *dup_eckey = NULL;
    U8 *pSignatureDER = NULL, *pSigTmp = NULL;
    int sigLen;
    uint32_t keyId;

    EmbSe_Print(LOG_FLOW_ON, "Invoking EmbSe_ECDSA_Do_Verify(..)\n");

    if (!eckey) {
        EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Verify: No EC Key provided as input.\n");
        return -1;
    }
    if (!sig) {
        EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Verify: No signature provided as input.\n");
        return -1;
    }

    /* Convert ECDSA_SIG to DER and print */
    sigLen = i2d_ECDSA_SIG((ECDSA_SIG *)sig, NULL);
    if (sigLen < 0) {
        return -1;
    }
    if (sigLen != 0) {
        pSignatureDER = (U8 *)OPENSSL_malloc(sigLen);
        if (pSignatureDER != NULL) {
            memset((void *)pSignatureDER, 0, sigLen);
            pSigTmp = pSignatureDER;
            // The pointer passed as second argument will point past the end of the returned signature
            // upon return. Which explains pointer copy operation before the call.
            i2d_ECDSA_SIG((ECDSA_SIG *)sig, &pSigTmp);
        }
        else {
            goto clean_mem_up;
        }
    }
    else {
        EmbSe_Print(LOG_ERR_ON, "Call to i2d_ECDSA_SIG failed\n");
        return -1;
    }
    EmbSe_Print(LOG_DBG_ON, "====>SIGNATURE (len=%d)\n", sigLen);
    EmbSe_PrintPayload(LOG_DBG_ON, pSignatureDER, sigLen, "");

    if ((dgst_len < 0) || (dgst_len > UINT16_MAX)) {
        nRet = -1;
        goto clean_mem_up;
    }
    EmbSe_PrintPayload(LOG_DBG_ON, dgst, dgst_len, "====>DIGEST");

    sw = getEcKeyReference(eckey, &keyId);
    if (sw == SW_OK) {
        flagHandleKey = AX_ENGINE_INVOKE_SE;
    }
    else if ((sw == ERR_NO_PRIVATE_KEY) || (sw == ERR_PATTERN_COMPARE_FAILED)) {
        flagHandleKey = AX_ENGINE_INVOKE_OPENSSL_SW;
    }
    else {
        EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Verify: No matching/valid public key\n");
        nRet = -1;
        goto clean_mem_up;
    }

    if (flagHandleKey == AX_ENGINE_INVOKE_SE) {
        U8 dgstBuf[96];
        U16 dgstBufLen = sizeof(dgstBuf);
        int dgstLenMatchingKey = 0;
        sss_algorithm_t shaAlgo_matchOnSize = kAlgorithm_SSS_SHA256;

        dgstLenMatchingKey = dgst_len;
        if (dgstLenMatchingKey > dgstBufLen) {
            EmbSe_Print(LOG_ERR_ON, "Buffer allocated for digest too small.\n");
            nRet = -1;
            goto clean_mem_up;
        }

        sw = getMatchingShaAlgo(dgstLenMatchingKey, &shaAlgo_matchOnSize);
        if (sw != SW_OK) {
            nRet = -1;
            goto clean_mem_up;
        }

        axAdaptSize(dgstBuf, dgstLenMatchingKey, dgst, dgst_len);

        EmbSe_Print(LOG_FLOW_ON, "SSS based verify (keyId=0x%08X, dgst_len=%d, sigLen=%d)\n", keyId, dgst_len, sigLen);
        status = sss_key_object_init(&pubKey, &gpCtx->ks);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "sss_key_object_init for pubKey failed\n");
            nRet = -1;
            goto clean_mem_up;
        }

        status = sss_key_object_get_handle(&pubKey, keyId);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "sss_key_object_get_handle for pubKey failed\n");
            nRet = -1;
            sss_key_object_free(&pubKey);
            goto clean_mem_up;
        }

        status = sss_asymmetric_context_init(&asymm, &gpCtx->session, &pubKey, shaAlgo_matchOnSize, kMode_SSS_Verify);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "sss_asymmetric_context_init for sign failed\n");
            nRet = -1;
            sss_key_object_free(&pubKey);
            goto clean_mem_up;
        }

        /* Do Signing */
        status = sss_asymmetric_verify_digest(&asymm, dgstBuf, dgstLenMatchingKey, pSignatureDER, sigLen);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "sss_asymmetric_verify_digest failed\n");
            nRet = -1;
            sss_asymmetric_context_free(&asymm);
            sss_key_object_free(&pubKey);
            goto clean_mem_up;
        }

        // At this point we know the verification succeeded, use OpenSSL convention for a valid signature
        // NOTE: an invalid signature would map on '0' as return value, but sss_asymmetric_verify_digest does not
        // distinguish between an error and a wrong signature.
        nRet = 1;

        // EmbSe_Print(LOG_FLOW_ON, "Clean up SSS data structures.\n");
        sss_asymmetric_context_free(&asymm);
        sss_key_object_free(&pubKey);

        EmbSe_Print(LOG_FLOW_ON, "Verification PASS\n");
    }
    else {
#ifdef PUBLIC_KEY_HANDOVER_TO_SW
        EmbSe_Print(LOG_FLOW_ON, "No matching key in Secure Element. Invoking OpenSSL API: ECDSA_do_verify.\n");
        /* Create a duplicate key */
        dup_eckey = EC_KEY_dup(eckey);
        if (dup_eckey == NULL) {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL verify: Failed to duplicate key.\n");
            nRet = -1;
            goto clean_mem_up;
        }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        /* Attach OpenSSL's SW methods to duplicate key */
        if (!ECDSA_set_method(dup_eckey, ECDSA_OpenSSL())) {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL ECDSA_set_method failure..\n");
            nRet = -1;
            EC_KEY_free(dup_eckey);
            goto clean_mem_up;
        }
#else
        /* Attach OpenSSL's SW methods to duplicate key */
        if (!EC_KEY_set_method(dup_eckey, EC_KEY_OpenSSL())) {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL EC_KEY_set_method failure..\n");
            nRet = -1;
            EC_KEY_free(dup_eckey);
            goto clean_mem_up;
        }
#endif // (OPENSSL_VERSION_NUMBER < 0x10100000L)
        /* Invoke OpenSSL verify and return result */
        nRet = ECDSA_do_verify(dgst, dgst_len, sig, dup_eckey);
        if (nRet == 1) {
            EmbSe_Print(LOG_FLOW_ON, "Verification by OpenSSL PASS\n");
        }
        else {
            EmbSe_Print(LOG_FLOW_ON, "Verification by OpenSSL FAIL (nRet=%d)\n", nRet);
        }
        EC_KEY_free(dup_eckey);
#else
        EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Verify expected a reference key.\n");
        nRet = -1;
        goto clean_mem_up;
#endif // PUBLIC_KEY_HANDOVER_TO_SW
    }
clean_mem_up:
    if (pSignatureDER) {
        OPENSSL_free(pSignatureDER);
    }

    return nRet;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
/**
 * Engine API implementation for computing shared secret, based on local private key, remote public key and an
 * optional  KDF(Key Derivation Function).
 *
 * @param[out] sh_secret buffer that will contain the computed shared secret (raw value if KDF is NULL).
 * @param[in]  sec_len   length of computed shared secret.
 * @param[in]  pub_key   public key of remote entity.
 * @param[in]  ecdh      reference to private key object of local entity.
 * @param[in] (*KDF)     reference to a function that implements Key Derivation Function (hash on raw secret)
 *
 * @param: (*KDF)in- Reference to buffer containing the generated shared secret.
 * @param: (*KDF)inlen- Length of the input
 * @param: (*KDF)out - Buffer that returns final output on running KDF
 * @param: (*KDF)outlen - returns length of computed output on running KDF
 * @return: On failure, returns -1; On success returns length of computed secret.
 */
static int EmbSe_Compute_Key(void *sh_secret,
    size_t sec_len,
    const EC_POINT *pub_key,
    EC_KEY *ecdh,
    void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
#else
static int EmbSe_Simple_Compute_Key(unsigned char **pout, size_t *poutlen, const EC_POINT *pub_key, const EC_KEY *ecdh)
#endif
{
    U16 sw;
    sss_status_t status;
    sss_object_t keyPair;
    sss_derive_key_t deriveKeyContext;
    int field_size_bits = 0;
    const EC_GROUP *key_group = NULL;
    U8 *pubKeyBuf = NULL;
    size_t pubKeyBufLen = 0;
    U8 pubKeyDerBuf[256];
    U16 pubKeyDerBufLen = sizeof(pubKeyDerBuf);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    int ret = -1;
#else
    int ret = 0;
#endif
    U8 *shSecBuf = NULL;
    size_t shSecBufLen_Bits = 0;
    size_t shSecBufLen = 0;
    uint32_t keyId;
    int nid;
    size_t maxSharedSecretByteCount = 66;
    uint32_t cipherType = 0;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Compute_Key invoked (ecdh)\n");
    EmbSe_Print(LOG_DBG_ON, "Requested secret = %d\n", sec_len);
#else
    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Simple_Compute_Key invoked (ecdh)\n");
#endif
    /* Get the key group */
    key_group = EC_KEY_get0_group(ecdh);
    if (!key_group) {
        EmbSe_Print(LOG_ERR_ON, "Unable to extract ECDH key group.\n");
        goto err;
    }
    else { /* Calculate length of field element for the key group */
        field_size_bits = EC_GROUP_get_degree(key_group);
        if (!field_size_bits) {
            EmbSe_Print(LOG_ERR_ON, "Unable to extract ECDH key field length.\n");
            goto err;
        }
    }

    nid = EC_GROUP_get_curve_name(key_group);
    if (nid == 0) {
        EmbSe_Print(LOG_ERR_ON, "Unable to get curve name.\n");
        goto err;
    }
    else {
        EmbSe_Print(LOG_DBG_ON, "** nid = %d **\n", nid);
    }

    sw = getCipherTypeFromNid(nid, &cipherType);
    if (sw != SW_OK) {
        EmbSe_Print(LOG_ERR_ON, "Unable to get cipherType from nid=%d\n", nid);
        goto err;
    }

    /* Extract Public Key Data  */
    /****************************/
    // Check if pub key is on the curve group
    if (!EC_POINT_is_on_curve(key_group, pub_key, NULL)) {
        EmbSe_Print(LOG_ERR_ON, "ECDH Public key error(incompatible group).\n");
        goto err;
    }
    // Get the size of public key -> pass NULL for buffer
    pubKeyBufLen = EC_POINT_point2oct(key_group, pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL, pubKeyBufLen, NULL);
    // Allocate memory for public key data & check allocation
    pubKeyBuf = SSS_MALLOC(pubKeyBufLen * sizeof(U8));
    if (!pubKeyBuf) {
        EmbSe_Print(LOG_ERR_ON, "malloc failure for ECDH public key data.\n");
        goto err;
    }
    // Get public key data
    if (!EC_POINT_point2oct(key_group, pub_key, POINT_CONVERSION_UNCOMPRESSED, pubKeyBuf, pubKeyBufLen, NULL)) {
        EmbSe_Print(LOG_ERR_ON, "ECDH public key data error (EC_POINT_point2oct).\n");
        goto err;
    }

    /* Secure Element Call (if applicable) */
    /***************************************/
    if (field_size_bits < 0) {
        goto err;
    }
    shSecBufLen = (size_t)((field_size_bits + 7UL) / 8UL);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    shSecBuf = SSS_MALLOC(shSecBufLen * sizeof(U8));
#else
    shSecBuf = OPENSSL_malloc(shSecBufLen * sizeof(U8));
#endif

    shSecBufLen_Bits = shSecBufLen * 8;

    sw = getEcKeyReference(ecdh, &keyId);
    if (sw == SW_OK) {
        sss_session_t cpSession;
        sss_key_store_t cpKs;
        sss_object_t extPubkey;
        sss_object_t derivedKey;
        uint32_t keyId_extPubKey = 0x7D000013;
        uint32_t keyId_derivedKey = 0x7D000014;

        EmbSe_Print(LOG_FLOW_ON,
            "SSS based (ECDH) compute_key (keyId=0x%08X, pubKeyLen=%zu, shSecBufLen=%zu)\n",
            keyId,
            pubKeyBufLen,
            shSecBufLen);

// Create OpenSSL context & keystore on the fly
// This is used to contain the public key and the calculated shared secret
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
        status = sss_session_open(&cpSession, kType_SSS_OpenSSL, 0, kSSS_ConnectionType_Plain, ".");
        EMBSE_ENSURE_OR_GO_ERR_WITH_MSG(status == kStatus_SSS_Success, "ECDH: OpenSSL session open failed.\n");
#elif SSS_HAVE_HOSTCRYPTO_MBEDTLS
        status = sss_session_open(&cpSession, kType_SSS_mbedTLS, 0, kSSS_ConnectionType_Plain, ".");
        EMBSE_ENSURE_OR_GO_ERR_WITH_MSG(status == kStatus_SSS_Success, "ECDH: Mbedtls session open failed.\n");
#elif SSS_HAVE_HOSTCRYPTO_USER
        status = sss_session_open(&cpSession, kType_SSS_Software, 0, kSSS_ConnectionType_Plain, ".");
        EMBSE_ENSURE_OR_GO_ERR_WITH_MSG(status == kStatus_SSS_Success, "ECDH: UserCrypto session open failed.\n");
#endif

        status = sss_key_store_context_init(&cpKs, &cpSession);
        EMBSE_ENSURE_OR_GO_ERR_WITH_MSG(status == kStatus_SSS_Success, "ECDH: sss_key_store_context_init failed.\n");

        status = sss_key_store_allocate(&cpKs, 0x7D000012);
        EMBSE_ENSURE_OR_GO_ERR_WITH_MSG(status == kStatus_SSS_Success, "ECDH: sss_key_store_allocate failed.\n");

        // Public Key
        status = sss_key_object_init(&extPubkey, &cpKs);
        EMBSE_ENSURE_OR_GO_ERR_WITH_MSG(
            status == kStatus_SSS_Success, "ECDH: sss_key_object_init failed (extPubkey).\n");

        status = sss_key_object_allocate_handle(&extPubkey,
            keyId_extPubKey,
            kSSS_KeyPart_Public,
            (sss_cipher_type_t)cipherType,
            pubKeyDerBufLen,
            kKeyObject_Mode_Transient);
        EMBSE_ENSURE_OR_GO_ERR_WITH_MSG(
            status == kStatus_SSS_Success, "ECDH: sss_key_object_allocate_handle failed (extPubkey).\n");

        // Encapsulate Raw public key in proper ASN.1 structure
        sw = decoratePublicKey(nid, pubKeyDerBuf, &pubKeyDerBufLen, pubKeyBuf, pubKeyBufLen);
        if (sw != SW_OK) {
            EmbSe_Print(LOG_ERR_ON, "ECDH: decoratePublicKey failed (err=0x%04X).\n", sw);
            goto err;
        }

        EmbSe_PrintPayload(LOG_DBG_ON, pubKeyDerBuf, pubKeyDerBufLen, "pubKeyDerBuf");
        status = sss_key_store_set_key(&cpKs, &extPubkey, pubKeyDerBuf, pubKeyDerBufLen, field_size_bits, NULL, 0);
        EMBSE_ENSURE_OR_GO_ERR_WITH_MSG(
            status == kStatus_SSS_Success, "ECDH: sss_key_store_set_key failed (extPubkey).\n");

        // Shared secret (Symmetric Key)
        status = sss_key_object_init(&derivedKey, &cpKs);
        EMBSE_ENSURE_OR_GO_ERR_WITH_MSG(
            status == kStatus_SSS_Success, "ECDH: sss_key_object_init failed (derivedKey).\n");

        status = sss_key_object_allocate_handle(&derivedKey,
            keyId_derivedKey,
            kSSS_KeyPart_Default,
            kSSS_CipherType_AES,
            maxSharedSecretByteCount,
            kKeyObject_Mode_Transient);
        EMBSE_ENSURE_OR_GO_ERR_WITH_MSG(
            status == kStatus_SSS_Success, "ECDH: sss_key_object_allocate_handle failed (derivedKey).\n");

        // Keypair stored in secure element
        status = sss_key_object_init(&keyPair, &gpCtx->ks);
        EMBSE_ENSURE_OR_GO_ERR_WITH_MSG(
            status == kStatus_SSS_Success, "ECDH: sss_key_object_init for keyPair failed\n");

        status = sss_key_object_get_handle(&keyPair, keyId);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "ECDH: sss_key_object_get_handle for pubKey failed\n");
            sss_key_object_free(&keyPair);
            goto err;
        }

        status = sss_derive_key_context_init(
            &deriveKeyContext, &gpCtx->session, &keyPair, kAlgorithm_SSS_ECDH, kMode_SSS_ComputeSharedSecret);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "ECDH: sss_derive_key_context_init for kMode_SSS_ComputeSharedSecret failed\n");
            sss_key_object_free(&keyPair);
            goto err;
        }

        EmbSe_Print(LOG_FLOW_ON, " After sss_derive_key_context_init.\n");

        status = sss_derive_key_dh(&deriveKeyContext, &extPubkey, &derivedKey);
        if (status != kStatus_SSS_Success) {
            EmbSe_Print(LOG_ERR_ON, "ECDH: sss_derive_key_dh failed\n");
            sss_key_object_free(&keyPair);
            goto err;
        }

        // Retrieve the shared secret into shSecBuf
        status = sss_key_store_get_key(&cpKs, &derivedKey, shSecBuf, &shSecBufLen, &shSecBufLen_Bits);
        EMBSE_ENSURE_OR_GO_ERR_WITH_MSG(status == kStatus_SSS_Success, "ECDH: sss_key_store_get_key failed.\n");

        // What did we get? Don't print this to console!
        // EmbSe_Print(LOG_DBG_ON, "ECDH: shSecBufLen_Bits=%d\n", shSecBufLen_Bits);
        // EmbSe_PrintPayload(LOG_DBG_ON, shSecBuf, shSecBufLen, "shSecBuf");
    }
    else if (sw == ERR_NO_PRIVATE_KEY) {
        EmbSe_Print(LOG_ERR_ON, "Expecting private key (by value or reference): 0x%04X.\n", sw);
        goto err;
    }
    else if (sw == ERR_PATTERN_COMPARE_FAILED) {
#ifdef PRIVATE_KEY_HANDOVER_TO_SW
        EC_KEY *dup_ecdh = NULL;
        int ecdh_ret = -1;

        // Delegate to OpenSSL SW implementation
        EmbSe_Print(LOG_FLOW_ON, "No matching key in SE. Invoking OpenSSL API: ECDH_compute_key.\n");
        /* Create a duplicate key */
        dup_ecdh = EC_KEY_dup(ecdh);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        /* Attach OpenSSL's SW method to duplicate key */
        if (!ECDH_set_method(dup_ecdh, ECDH_OpenSSL())) {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL ECDH_set_method failure.\n");
            goto err;
        }
#else
        /* Attach OpenSSL's SW method to duplicate key */
        if (!EC_KEY_set_method(dup_ecdh, EC_KEY_OpenSSL())) {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL EC_KEY_set_method failure..\n");
            goto err;
        }
#endif
        /* Invoke OpenSSL ECDH_compute_key and return result */
        // int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,
        // void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
        ecdh_ret = ECDH_compute_key(shSecBuf, shSecBufLen, pub_key, dup_ecdh, NULL);
        EC_KEY_free(dup_ecdh);
        if (0 < ecdh_ret) {
            EmbSe_Print(LOG_FLOW_ON, "ECDH_compute_key by OpenSSL PASS\n");
            shSecBufLen = (U16)ecdh_ret;
        }
        else {
            EmbSe_Print(LOG_ERR_ON, "ECDH_compute_key by OpenSSL FAILS with %d.\n", ecdh_ret);
            goto err;
        }
#else
        EmbSe_Print(LOG_ERR_ON, "EmbSe_Compute_Key expected a reference key: 0x%04X.\n", sw);
        goto err;
#endif
    }
    else {
        EmbSe_Print(LOG_ERR_ON, "EmbSe_Compute_Key unexpected key type: 0x%04X.\n", sw);
        goto err;
    }

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    /* Finally run the KDF, if provided */
    memset(sh_secret, 0, shSecBufLen);
    if (KDF != 0) {
        if (KDF(shSecBuf, shSecBufLen, sh_secret, &sec_len) == NULL) {
            EmbSe_Print(LOG_ERR_ON, "KDF failed.\n");
            goto err;
        }
        ret = sec_len;
    }
    else {
        /* When KDF=NULL, return raw secret, copy asked length */
        if (sec_len > shSecBufLen) {
            sec_len = shSecBufLen;
        }
        memcpy(sh_secret, shSecBuf, sec_len);
        ret = sec_len;
    }
#else
    *pout = shSecBuf;
    *poutlen = shSecBufLen;
    ret = 1;
#endif

    // Never print shared secret
    // EmbSe_PrintPayload(LOG_DBG_ON, sh_secret, sec_len, "Shared Secret: ");

err:

    /* Free all allocated memory */
    if (pubKeyBuf) {
        SSS_FREE(pubKeyBuf);
    }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if (shSecBuf) {
        SSS_FREE(shSecBuf);
    }
#endif
    return ret;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
ECDSA_METHOD EmbSe_ECDSA = {"e2se_ecdsa", *EmbSe_ECDSA_Do_Sign, EmbSe_ECDSA_Sign_Setup, EmbSe_ECDSA_Do_Verify, 0, NULL};

ECDH_METHOD EmbSe_ECDH = {"e2se_ecdh", *EmbSe_Compute_Key, 0, NULL};
#else
// Renamed 'ossl_ecdsa_sign' from openssl-1.1.0j/crypto/ec/ecdsa_ossl.c
static int my_ossl_ecdsa_sign(int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int *siglen,
    const BIGNUM *kinv,
    const BIGNUM *r,
    EC_KEY *eckey)
{
    AX_UNUSED_ARG(type);
    ECDSA_SIG *s;
    int evp_siglen;
    RAND_seed(dgst, dlen);
    s = ECDSA_do_sign_ex(dgst, dlen, kinv, r, eckey);
    if (s == NULL) {
        *siglen = 0;
        return 0;
    }
    evp_siglen = i2d_ECDSA_SIG(s, &sig);
    if (evp_siglen < 0) {
        ECDSA_SIG_free(s);
        return 0;
    }
    *siglen = evp_siglen;
    ECDSA_SIG_free(s);
    return 1;
}

// Renamed 'ossl_ecdsa_verify' from openssl-1.1.0j/crypto/ec/ecdsa_ossl.c
static int my_ossl_ecdsa_verify(
    int type, const unsigned char *dgst, int dgst_len, const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    AX_UNUSED_ARG(type);
    ECDSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL) {
        return (ret);
    }
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL) {
        goto err;
    }
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sigbuf, der, derlen) != 0) {
        goto err;
    }
    ret = ECDSA_do_verify(dgst, dgst_len, s, eckey);
err:
    if (derlen > 0) {
        OPENSSL_clear_free(der, derlen);
    }
    ECDSA_SIG_free(s);
    return (ret);
}

int EmbSe_Simple_Key_gen(EC_KEY *key)
{
    int (*openssl_Key_gen_sw)(EC_KEY * key) = NULL;
    EC_KEY_METHOD_get_keygen((EC_KEY_METHOD *)EmbSe_EC_Default, &openssl_Key_gen_sw);
    return openssl_Key_gen_sw(key);
}

static EVP_PKEY *EmbSe_LoadPrivKey(ENGINE *eng, const char *keyInput, UI_METHOD *ui_method, void *ui_data)
{
    EVP_PKEY *key = NULL;
    BIO *bioKeyMaterial = BIO_new_file(keyInput, "r");
    if (bioKeyMaterial) {
        key = PEM_read_bio_PrivateKey(bioKeyMaterial, NULL, NULL, NULL);
        BIO_free(bioKeyMaterial);
    }
    return key;
}

int setup_ec_key_method(void)
{
    EmbSe_EC_Default = EC_KEY_get_default_method();
    EmbSe_EC = EC_KEY_METHOD_new(NULL);
    if (EmbSe_EC == NULL) {
        return 0;
    }
    // NOTE: Equivalent of set_name does not exist for OpenSSL 1.1
    // EC_KEY_METHOD_set_name(EmbSe_EC, "e2se_ecdsa");
    EC_KEY_METHOD_set_sign(EmbSe_EC, my_ossl_ecdsa_sign, EmbSe_ECDSA_Sign_Setup, EmbSe_ECDSA_Do_Sign);
    EC_KEY_METHOD_set_verify(EmbSe_EC, my_ossl_ecdsa_verify, EmbSe_ECDSA_Do_Verify);
    EC_KEY_METHOD_set_compute_key(EmbSe_EC, EmbSe_Simple_Compute_Key);
    EC_KEY_METHOD_set_keygen(EmbSe_EC, EmbSe_Simple_Key_gen);
    return 1;
}

int setup_load_priv_key_method(ENGINE *e)
{
    ENGINE_set_load_privkey_function(e, EmbSe_LoadPrivKey);
    return 1;
}

#endif // (OPENSSL_VERSION_NUMBER < 0x10100000L)

#endif //#if SSS_HAVE_ECC
