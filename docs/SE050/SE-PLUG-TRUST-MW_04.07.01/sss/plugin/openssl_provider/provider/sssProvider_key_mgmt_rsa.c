/**
 * @file sssProvider_key_mgmt_rsa.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022,2024,2025 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for RSA key management
 *
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_RSA

/* ********************** Include files ********************** */
#include "sssProvider_main.h"
#include <fsl_sss_util_asn1_der.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <string.h>

/* ********************** Defines **************************** */

#define SSS_DEFAULT_RSA_KEY_ID 0xEF000011
#define SE05x_MAGIC_NUM_SIZE 8
#define SE05x_MAGIC_NUM                                \
    {                                                  \
        0xB6, 0xB5, 0xA6, 0xA5, 0xB6, 0xB5, 0xA6, 0xA5 \
    }

#define SSS_ENABLE_RSA_KEYMGMT_IMPORT_FUNC
#define RSA_SIGNATURE_REFKEY_ID 0xB6B5A6A5

/* ********************** Private funtions ******************* */

/* Return:
 * 0 on error
 * 1 on success
 */
static int sss_get_rsa_key_len_cipher_type(uint32_t bits, uint32_t *cipherType, uint16_t *KeyBitLen)
{
    int i = 0;
    for (i = 0; i < MAX_SSS_TYPE_KEY_MAP_ENTRIES; i++) {
        if (sss_type_key_map[i].keyBitLen == bits) {
            *cipherType = sss_type_key_map[i].cipherType;
            if ((sss_type_key_map[i].keyBitLen / 8u) > UINT16_MAX) {
                return 0;
            }
            *KeyBitLen = sss_type_key_map[i].keyBitLen / 8u;
            return 1;
        }
    }
    return 0;
}

static void *sss_rsa_keymgmt_load(const void *reference, size_t reference_sz)
{
    sss_provider_store_obj_t *pStoreCtx = NULL;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (!reference || reference_sz != sizeof(pStoreCtx)) {
        return NULL;
    }

    pStoreCtx                               = *(sss_provider_store_obj_t **)reference;
    *(sss_provider_store_obj_t **)reference = NULL;
    return pStoreCtx;
}

#ifdef SSS_ENABLE_RSA_KEYMGMT_IMPORT_FUNC
static void *sss_rsa_keymgmt_new(void *provctx)
{
    sss_provider_store_obj_t *pStoreCtx = OPENSSL_zalloc(sizeof(sss_provider_store_obj_t));

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (pStoreCtx != NULL) {
        pStoreCtx->pProvCtx = provctx;
    }

    return pStoreCtx;
}
#endif /*SSS_ENABLE_RSA_KEYMGMT_IMPORT_FUNC*/

static void sss_rsa_keymgmt_free(void *keydata)
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pStoreCtx != NULL) {
        if (pStoreCtx->pEVPPkey != NULL) {
            EVP_PKEY_free(pStoreCtx->pEVPPkey);
            pStoreCtx->pEVPPkey = NULL;
        }
    }

    if (keydata != NULL) {
        OPENSSL_free(keydata);
    }
}

static int sss_rsa_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    smStatus_t smStatus = SM_NOT_OK;
    sss_status_t status;
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    sss_se05x_session_t *pSession       = (sss_se05x_session_t *)&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->session;
    OSSL_PARAM *p;
    int ret                 = 0;
    int pkey_bits           = 0;
    int pkey_security_bits  = 0;
    uint8_t public_key[550] = {0};
    size_t public_key_len   = sizeof(public_key);
    size_t pbKeyBitLen      = sizeof(public_key) * 8;
    uint8_t modulus[512]    = {0};
    size_t modLen           = sizeof(modulus);

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (params == NULL) {
        return 1;
    }

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);

    if (pStoreCtx->isEVPKey) {
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pEVPPkey != NULL);

        /* EVP_PKEY_size() returns the maximum suitable size for the output buffers
    for almost all operations that can be done with pkey */
        pStoreCtx->maxSize = EVP_PKEY_size(pStoreCtx->pEVPPkey);

        pkey_bits = EVP_PKEY_bits(pStoreCtx->pEVPPkey);
        ENSURE_OR_GO_CLEANUP(pkey_bits > 0);

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if (p != NULL && !OSSL_PARAM_set_int(p, pkey_bits)) {
            goto cleanup;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if (p != NULL && !OSSL_PARAM_set_int(p, pStoreCtx->maxSize)) { /* Signature size */
            goto cleanup;
        }

        pkey_security_bits = EVP_PKEY_security_bits(pStoreCtx->pEVPPkey);
        ENSURE_OR_GO_CLEANUP(pkey_security_bits > 0);

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if (p != NULL && !OSSL_PARAM_set_int(p, pkey_security_bits)) {
            goto cleanup;
        }
    }
    else {
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        pSession = (sss_se05x_session_t *)&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->session;
        ENSURE_OR_GO_CLEANUP(pSession != NULL);

        // Get the size of the key
        smStatus = Se05x_API_ReadSize(&(pSession->s_ctx), pStoreCtx->keyid, &(pStoreCtx->key_len));
        if (smStatus != SM_OK) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if (p != NULL && !OSSL_PARAM_set_int(p, (pStoreCtx->key_len) * 8)) {
            goto cleanup;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if (p != NULL && !OSSL_PARAM_set_int(p, pStoreCtx->key_len)) { /* Signature size */
            goto cleanup;
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY); /*Public Key*/
        if (p != NULL) {
            BIGNUM *bn_pub_key = NULL;
            status             = sss_key_store_get_key(&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks,
                &pStoreCtx->object,
                public_key,
                &public_key_len,
                &pbKeyBitLen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
            bn_pub_key   = BN_bin2bn(public_key, public_key_len, NULL);
            p->data_size = public_key_len;
            if (!OSSL_PARAM_set_BN(p, bn_pub_key)) {
                BN_free(bn_pub_key);
                goto cleanup;
            }
            BN_free(bn_pub_key);
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N);
        if (p != NULL) {
            BIGNUM *bn_n = NULL;
            smStatus     = Se05x_API_ReadRSA(
                &pSession->s_ctx, pStoreCtx->object.keyId, 0, 0, kSE05x_RSAPubKeyComp_MOD, modulus, &modLen);
            ENSURE_OR_GO_CLEANUP(smStatus == SM_OK);

            bn_n         = BN_bin2bn(modulus, modLen, NULL);
            p->data_size = modLen;
            if (!OSSL_PARAM_set_BN(p, bn_n)) {
                BN_free(bn_n);
                goto cleanup;
            }
            BN_free(bn_n);
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
        if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p, "SHA256"))) {
            goto cleanup;
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
        if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p, "SHA256"))) {
            goto cleanup;
        }
    }

    ret = 1;
cleanup:
    return ret;
}

static const OSSL_PARAM *sss_rsa_keymgmt_gettable_params(void *provctx)
{
    static OSSL_PARAM gettable[] = {OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END};
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(provctx);
    return gettable;
}

static const char *sss_rsa_keymgmt_query_operation_name(int operation_id)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (operation_id == OSSL_OP_SIGNATURE) {
        return "RSA";
    }
    else if (operation_id == OSSL_OP_ASYM_CIPHER) {
        return "RSAENC-SE05X";
    }
    else {
        return "RSA";
    }
}

static int sss_rsa_keymgmt_has(const void *keydata, int selection)
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    int ok                              = 1;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pStoreCtx == NULL) {
        return 0;
    }

    if (pStoreCtx->isEVPKey) {
        if (pStoreCtx->pEVPPkey == NULL) {
            return 0;
        }

        if (EVP_PKEY_id(pStoreCtx->pEVPPkey) == EVP_PKEY_RSA) {
            if (selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
                int ret = (pStoreCtx->isPrivateKey) ? (ok) : (0);
                return ret;
            }
            else if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
                int ret = (pStoreCtx->isPrivateKey) ? (0) : (ok);
                return ret;
            }
            else if (selection == OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
                return ok;
            }
            else {
                // Any other - return 0.
                return 0;
            }
        }
        else {
            // Any other - return 0.
            return 0;
        }
    }
    else {
        if (selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            if (pStoreCtx->object.objectType == kSSS_KeyPart_Pair ||
                pStoreCtx->object.objectType == kSSS_KeyPart_Private) {
                return ok;
            }
            else {
                return 0;
            }
        }
        else if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            if (pStoreCtx->object.objectType == kSSS_KeyPart_Public) {
                return ok;
            }
            else {
                return 0;
            }
        }
        else if (selection == OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
            if (pStoreCtx->object.cipherType == kSSS_CipherType_RSA ||
                pStoreCtx->object.cipherType == kSSS_CipherType_RSA_CRT) {
                return ok;
            }
            else {
                return 0;
            }
        }
        else {
            // Any other - return 0.
            return 0;
        }
    }
}

#ifdef SSS_ENABLE_RSA_KEYMGMT_IMPORT_FUNC
static int sss_rsa_keymgmt_import(void *keydata, int selection, OSSL_PARAM params[])
{
    sss_status_t status                 = kStatus_SSS_Fail;
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    BIGNUM *bn_coeff       = NULL;
    size_t coeff_len       = 0;
    uint8_t *coeff_data    = NULL;
    uint32_t factor2       = 0;
    int res                = 0;
    unsigned int magic_num = {0};
    BIGNUM *bn_n           = NULL;
    size_t n_len           = 0;

    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
        OSSL_PARAM *param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_D);
        if (param != NULL) {
            param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);
            ENSURE_OR_GO_CLEANUP(param != NULL);

            res = OSSL_PARAM_get_BN(param, &bn_coeff);
            ENSURE_OR_GO_CLEANUP(res == 1);

            coeff_len = BN_num_bytes(bn_coeff);
            ENSURE_OR_GO_CLEANUP(coeff_len != 0);

            coeff_data = (uint8_t *)OPENSSL_malloc(coeff_len);
            ENSURE_OR_GO_CLEANUP(coeff_data != NULL);

            res = BN_bn2bin(bn_coeff, coeff_data);
            ENSURE_OR_GO_CLEANUP(res == (int)coeff_len);

            magic_num = coeff_data[0] | (coeff_data[1] << 8) | (coeff_data[2] << 16) | (coeff_data[3] << 24);

            param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N);
            ENSURE_OR_GO_CLEANUP(param != NULL);

            res = OSSL_PARAM_get_BN(param, &bn_n);
            ENSURE_OR_GO_CLEANUP(res == 1);

            n_len = BN_num_bytes(bn_n);
            ENSURE_OR_GO_CLEANUP(n_len != 0);

            pStoreCtx->key_len = (uint16_t)n_len;
            ENSURE_OR_GO_CLEANUP(pStoreCtx->key_len != 0);

            if (magic_num != RSA_SIGNATURE_REFKEY_ID) {
                sssProv_Print(LOG_DBG_ON,
                    "Key not handled in sssProvider (Not a ref "
                    "key). Fall back to default provider\n");
                status = kStatus_SSS_Fail;
                goto cleanup;
            }
            else {
                param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_FACTOR2);
                ENSURE_OR_GO_CLEANUP(param != NULL);

                if (!OSSL_PARAM_get_uint32(param, &factor2)) {
                    goto cleanup;
                }

                pStoreCtx->keyid = factor2;
                ENSURE_OR_GO_CLEANUP(pStoreCtx->keyid != 0);

                status = sss_key_object_init(&(pStoreCtx->object), &pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks);
                ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

                status = sss_key_object_get_handle(&(pStoreCtx->object), pStoreCtx->keyid);
                ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

                pStoreCtx->isEVPKey = 0;
            }
        }
        else {
            sssProv_Print(LOG_DBG_ON, "Key not handled in sssProvider. Fall back to default provider\n");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
    }

cleanup:
    if (coeff_data != NULL) {
        OPENSSL_free(coeff_data);
    }
    if (bn_coeff != NULL) {
        BN_free(bn_coeff);
    }
    if (bn_n != NULL) {
        BN_free(bn_n);
    }
    if (status != kStatus_SSS_Success) {
        return 0;
    }
    return 1;
}

static const OSSL_PARAM *sss_rsa_keymgmt_import_types(int selection)
{
    static OSSL_PARAM importable_params[4] = {0};
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(selection);

    importable_params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0);
    importable_params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0);
    importable_params[2] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0);
    importable_params[3] = OSSL_PARAM_construct_end();
    return importable_params;
}
#endif /*SSS_ENABLE_RSA_KEYMGMT_IMPORT_FUNC*/

static int sss_rsa_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    OSSL_PARAM params[16]               = {0};
    uint8_t i                           = 0;
    uint8_t modulus[512]                = {0};
    size_t modLen                       = sizeof(modulus);
    uint8_t pubExponent[4]              = {0};
    size_t pubExponentLen               = sizeof(pubExponent);
    uint8_t privexponent[1]             = {0x00};
    uint8_t prime1[1]                   = {0x01};
    uint8_t prime2[4]                   = {0x00};
    uint8_t exponent1[1]                = {0x00};
    uint8_t cofficient[4]               = {0xB6, 0xB5, 0xA6, 0xA5}; /*Magic Number*/
    smStatus_t sm_status                = SM_NOT_OK;
    sss_se05x_session_t *pSession       = (sss_se05x_session_t *)&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->session;
    OSSL_PARAM params_tmp[2]            = {
        0,
    };

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pStoreCtx->isEVPKey == 1) {
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pEVPPkey != NULL);

        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            params_tmp[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, modulus, modLen);
            params_tmp[1] = OSSL_PARAM_construct_end();
            ENSURE_OR_GO_CLEANUP(EVP_PKEY_get_params(pStoreCtx->pEVPPkey, params_tmp) == 1);
            modLen      = params_tmp[0].return_size;
            params[i++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, modulus, modLen);

            params_tmp[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, pubExponent, pubExponentLen);
            params_tmp[1] = OSSL_PARAM_construct_end();
            ENSURE_OR_GO_CLEANUP(EVP_PKEY_get_params(pStoreCtx->pEVPPkey, params_tmp) == 1);
            pubExponentLen = params_tmp[0].return_size;
            params[i++]    = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, pubExponent, pubExponentLen);
        }

        params[i++] = OSSL_PARAM_construct_end();
    }
    else {
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            sm_status = Se05x_API_ReadRSA(
                &pSession->s_ctx, pStoreCtx->object.keyId, 0, 0, kSE05x_RSAPubKeyComp_MOD, modulus, &modLen);
            ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

            sm_status = Se05x_API_ReadRSA(&pSession->s_ctx,
                pStoreCtx->object.keyId,
                0,
                0,
                kSE05x_RSAPubKeyComp_PUB_EXP,
                pubExponent,
                &pubExponentLen);
            ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

            // reverse the moduluse
            {
                int m       = 0;
                int n       = modLen - 1;
                uint8_t tmp = 0;
                for (; m < n; m++, n--) {
                    if ((n < 0) || (n >= (int)sizeof(modulus))) {
                        return 0;
                    }
                    tmp        = modulus[m];
                    modulus[m] = modulus[n];
                    modulus[n] = tmp;
                }
            }

            params[i++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, modulus, modLen); /* Modulus */
            params[i++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, pubExponent, pubExponentLen); /* Public Exponent */
        }

        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            params[i++] = OSSL_PARAM_construct_BN(
                OSSL_PKEY_PARAM_RSA_D, &privexponent[0], sizeof(privexponent)); /* Private Exponent */

            params[i++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, &prime1[0], sizeof(prime1)); /* 0x01 -Reserved  */

            memcpy(&prime2[0], &pStoreCtx->keyid, sizeof(pStoreCtx->keyid));
            params[i++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, &prime2[0], sizeof(prime2)); /*Key id Information*/

            params[i++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, &exponent1[0], sizeof(exponent1));
            params[i++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, &exponent1[0], sizeof(exponent1));

            params[i++] = OSSL_PARAM_construct_BN(
                OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &cofficient[0], sizeof(cofficient)); /* Magic Number */
        }

        params[i++] = OSSL_PARAM_construct_end();
    }

    return param_cb(params, cbarg);

cleanup:
    return 0;
}

static const OSSL_PARAM *sss_rsa_keymgmt_export_types(int selection)
{
    static OSSL_PARAM exporatble[9] = {0};
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    exporatble[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_RSA_N, 0, 0);
    exporatble[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_RSA_E, 0, 0);
    exporatble[2] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0);
    exporatble[3] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL);
    exporatble[4] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL);
    exporatble[5] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL),
    exporatble[6] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
    exporatble[7] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL),
    exporatble[8] = OSSL_PARAM_construct_end();
    (void)(selection);
    return exporatble;
}

static void *sss_rsa_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    sss_provider_store_obj_t *pStoreCtx = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(selection);
    (void)(params);

    if ((pStoreCtx = OPENSSL_zalloc(sizeof(sss_provider_store_obj_t))) == NULL) {
        return NULL;
    }

    pStoreCtx->isEVPKey = 0;
    pStoreCtx->pProvCtx = provctx;
    return pStoreCtx;
}

static int sss_keymgmt_rsa_gen_set_params(void *keydata, const OSSL_PARAM params[])
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    const OSSL_PARAM *p;
    int ret          = 0;
    int bits         = 0;
    int index        = 0;
    uint32_t factor2 = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(keydata);

    ENSURE_OR_GO_CLEANUP(params != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS);
    if (p != NULL) {
        if (OSSL_PARAM_get_int(p, &bits)) {
            ENSURE_OR_GO_CLEANUP(bits > 0);
            index = sss_get_rsa_key_len_cipher_type(bits, &pStoreCtx->object.cipherType, &pStoreCtx->key_len);
            ENSURE_OR_GO_CLEANUP(index != 0);
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES);
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, &pStoreCtx->primes)) {
            goto cleanup;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR2);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &factor2)) {
            goto cleanup;
        }
        pStoreCtx->keyid = factor2;
    }

#if 0
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    if (p != NULL) {
        if (!OSSL_PARAM_get_BN(p, &pStoreCtx->rsa_e)) {
            goto cleanup;
        }
    }
#endif
    ret = 1;
cleanup:
    return ret;
}

static const OSSL_PARAM *sss_keymgmt_rsa_gen_settable_params(void *keydata, void *vprovctx)
{
    static OSSL_PARAM settable[] = {OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
        OSSL_PARAM_END};
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(keydata);
    (void)(vprovctx);
    return settable;
}

static void *sss_keymgmt_rsa_gen(void *keydata, OSSL_CALLBACK *osslcb, void *cbarg)
{
    sss_status_t status                 = kStatus_SSS_Fail;
    smStatus_t smStatus                 = SM_NOT_OK;
    sss_se05x_session_t *pSession       = NULL;
    SE05x_Result_t exists               = kSE05x_Result_NA;
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    uint32_t cipherType                 = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(osslcb);
    (void)(cbarg);

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);

    cipherType = pStoreCtx->object.cipherType;
    if (pStoreCtx->keyid == 0) {
        pStoreCtx->keyid = SSS_DEFAULT_RSA_KEY_ID;
    }

    pSession = (sss_se05x_session_t *)&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->session;

    smStatus = Se05x_API_CheckObjectExists(&(pSession->s_ctx), pStoreCtx->keyid, &exists);
    if (exists == kSE05x_Result_SUCCESS) {
        sssProv_Print(LOG_DBG_ON, "Delete key at location - 0x%X from SE05x) \n", pStoreCtx->keyid);
        smStatus = Se05x_API_DeleteSecureObject(&(pSession->s_ctx), pStoreCtx->keyid);
        ENSURE_OR_GO_CLEANUP(smStatus == SM_OK);
    }

    status = sss_key_object_init(&pStoreCtx->object, &pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&pStoreCtx->object,
        pStoreCtx->keyid,
        kSSS_KeyPart_Pair,
        cipherType,
        (pStoreCtx->key_len * 8),
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    sssProv_Print(LOG_FLOW_ON, "Generate RSA key inside SE05x \n");
    sssProv_Print(LOG_FLOW_ON, "NOTE: Key is created with Persistent Option \n");
    sssProv_Print(LOG_DBG_ON, "(At key id 0x%X from SE05x) \n", pStoreCtx->keyid);
    status = sss_key_store_generate_key(
        &pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks, &pStoreCtx->object, (pStoreCtx->key_len * 8), 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    return keydata;
cleanup:
    return NULL;
}

static void sss_keymgmt_rsa_gen_cleanup(void *keydata)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(keydata);
    return;
}

static void *sss_rsa_keymgmt_dup(const void *keydata, int selection)
{
    sss_provider_store_obj_t *pStoreCtx   = (sss_provider_store_obj_t *)keydata;
    sss_provider_store_obj_t *outStoreCtx = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(selection);

    outStoreCtx = OPENSSL_zalloc(sizeof(sss_provider_store_obj_t));
    if (outStoreCtx == NULL) {
        return NULL;
    }

    if (pStoreCtx != NULL) {
        outStoreCtx->keyid        = pStoreCtx->keyid;
        outStoreCtx->key_len      = pStoreCtx->key_len;
        outStoreCtx->maxSize      = pStoreCtx->maxSize;
        outStoreCtx->isPrivateKey = pStoreCtx->isPrivateKey;
        outStoreCtx->isEVPKey     = pStoreCtx->isEVPKey;

        memcpy(&(outStoreCtx->object), &(pStoreCtx->object), sizeof(pStoreCtx->object));
        outStoreCtx->pProvCtx = pStoreCtx->pProvCtx;

        if (pStoreCtx->pEVPPkey != NULL) {
            outStoreCtx->pEVPPkey = EVP_PKEY_dup(pStoreCtx->pEVPPkey);
        }

        return outStoreCtx;
    }
    else {
        OPENSSL_free(outStoreCtx);
        return NULL;
    }
}

const OSSL_DISPATCH sss_rsa_keymgmt_dispatch[] = {{OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sss_rsa_keymgmt_load},
#ifdef SSS_ENABLE_RSA_KEYMGMT_IMPORT_FUNC
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))sss_rsa_keymgmt_new},
#endif /*SSS_ENABLE_RSA_KEYMGMT_IMPORT_FUNC*/
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sss_rsa_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))sss_rsa_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))sss_rsa_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))sss_rsa_keymgmt_query_operation_name},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sss_rsa_keymgmt_has},
#ifdef SSS_ENABLE_RSA_KEYMGMT_IMPORT_FUNC
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))sss_rsa_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))sss_rsa_keymgmt_import_types},
#endif /*SSS_ENABLE_RSA_KEYMGMT_IMPORT_FUNC*/
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))sss_rsa_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))sss_rsa_keymgmt_export_types},
    {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))sss_rsa_keymgmt_dup},

    /* To generate the key in SE */
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))sss_rsa_keymgmt_gen_init},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))sss_keymgmt_rsa_gen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))sss_keymgmt_rsa_gen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))sss_keymgmt_rsa_gen},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))sss_keymgmt_rsa_gen_cleanup},
    {0, NULL}};

#endif //#if SSS_HAVE_RSA
