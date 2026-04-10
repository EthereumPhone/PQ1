/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <keymaster/se050_keymaster_attestation_record.h>
#include <keymaster/se050_keymaster_certificate_chain.h>
#include <keymaster/se050_keymaster_testutils.h>
#include <keymaster/se050_keymaster_utils.h>

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <algorithm>
#include <vector>

#include <type_traits>

#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <hardware/keymaster1.h>
#define LOG_TAG "NXPKeymasterDevice"
#include <cutils/log.h>

#include "attestation_record.h"
#include <keymaster/android_keymaster.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/android_keymaster_utils.h>
#include <keymaster/authorization_set.h>
#include <keymaster/keymaster_context.h>
#include <keymaster/soft_keymaster_context.h>
#include <keymaster/soft_keymaster_logger.h>

#include "openssl_utils.h"

#include "openssl_err.h"
#include <ec_key.h>
#include <rsa_key.h>

namespace keymaster {

size_t CountTags(const AuthorizationSet* params, keymaster_tag_t tag) {
    size_t params_size = params->size();
    size_t count = 0;
    const keymaster_key_param_t* key_params = params->begin();
    for (size_t i = 0; i < params_size; i++) {
        if (key_params[i].tag == tag)
            count++;
    }

    return count;
}

bool AuthorizeOperation(const AuthorizationSet& auth, keymaster_tag_t tag, uint8_t value) {
    size_t params_size = auth.size();
    const keymaster_key_param_t* key_params = auth.begin();

    for (size_t i = 0; i < params_size; i++) {
        if (key_params[i].tag == tag) {
            if (key_params[i].enumerated == value) {
                return true;
            }
        }
    }
    return false;
}

bool AuthorizeOperation(const AuthorizationSet& auth, keymaster_tag_t tag) {
    size_t params_size = auth.size();
    const keymaster_key_param_t* key_params = auth.begin();
    for (size_t i = 0; i < params_size; i++) {
        if (key_params[i].tag == tag) {
            return true;
        }
    }
    return false;
}

keymaster_error_t GetSSSAlgorithm(const sss_algorithm_t algorithm, sss_algorithm_t* digest_algo) {
    switch (algorithm) {
    case kAlgorithm_SSS_SHA1:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1:
    case kAlgorithm_SSS_ECDSA_SHA1:
        *digest_algo = kAlgorithm_SSS_SHA1;
        break;
    case kAlgorithm_SSS_SHA224:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA224:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA224:
    case kAlgorithm_SSS_ECDSA_SHA224:
        *digest_algo = kAlgorithm_SSS_SHA224;
        break;
    case kAlgorithm_SSS_SHA256:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256:
    case kAlgorithm_SSS_ECDSA_SHA256:
        *digest_algo = kAlgorithm_SSS_SHA256;
        break;
    case kAlgorithm_SSS_SHA384:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA384:
    case kAlgorithm_SSS_ECDSA_SHA384:
        *digest_algo = kAlgorithm_SSS_SHA384;
        break;
    case kAlgorithm_SSS_SHA512:
    case kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512:
    case kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512:
    case kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA512:
    case kAlgorithm_SSS_ECDSA_SHA512:
        *digest_algo = kAlgorithm_SSS_SHA512;
        break;
    default:
        return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }
    return KM_ERROR_OK;
}

/*Function to check that the data value is smaller than the RSA modulus.
 * Required for RSA operations*/
keymaster_error_t RawSignCheckDataValue(uint8_t* inputData, size_t data_length, uint8_t** rsaN,
                                        size_t rsaNlen) {
    if (rsaNlen < data_length)
        return KM_ERROR_INVALID_INPUT_LENGTH;

    else if (rsaNlen > data_length)
        return KM_ERROR_OK;

    /*ALOGI("data_length: %zu", data_length);
    ALOGI("rsaNlen: %zu", rsaNlen);
    ALOGI("%s:rsaN: %d", __FUNCTION__, **rsaN);*/
    keymaster_error_t km_error = KM_ERROR_INVALID_ARGUMENT;

    for (size_t i = 0; i < data_length; i++) {
        if (*(*rsaN + i) > *(inputData + i)) {
            km_error = KM_ERROR_OK;
            return KM_ERROR_OK;
            break;
        } else if (*(inputData + i) > *(*rsaN + i)) {
            return KM_ERROR_INVALID_ARGUMENT;
            break;
        }
    }
    return km_error;
}

/*Function to parse ECC Authorization tags*/
keymaster_error_t parse_ec_param_set(const AuthorizationSet& params,
                                     AuthorizationSet* updated_params) {
    updated_params->Reinitialize(params);
    uint32_t extracted_key_size;
    uint32_t key_size;
    keymaster_ec_curve_t extracted_ecc_curve;
    keymaster_ec_curve_t ecc_curve;
    if (!updated_params->GetTagValue(TAG_KEY_SIZE, &extracted_key_size) &&
        !updated_params->GetTagValue(TAG_EC_CURVE, &extracted_ecc_curve))
        return KM_ERROR_UNSUPPORTED_KEY_SIZE;
    if (updated_params->GetTagValue(TAG_KEY_SIZE, &extracted_key_size)) {
        // ALOGD("Parse param_set: TAG_KEY_SIZE present");
        keymaster_error_t error = EcKeySizeToCurve(extracted_key_size, &ecc_curve);
        if (error != KM_ERROR_OK)
            return error;

        extracted_ecc_curve = ecc_curve;
        if (!updated_params->GetTagValue(TAG_EC_CURVE, &extracted_ecc_curve))
            updated_params->push_back(TAG_EC_CURVE, ecc_curve);
        else if (extracted_ecc_curve != ecc_curve)
            return KM_ERROR_INVALID_ARGUMENT;
    }
    if (updated_params->GetTagValue(TAG_EC_CURVE, &extracted_ecc_curve)) {
        // ALOGD("Parse param_set: TAG_EC_CURVE present");
        keymaster_error_t error = EcCurveToKeySize(extracted_ecc_curve, &key_size);
        if (error != KM_ERROR_OK)
            return error;

        extracted_key_size = key_size;
        if (!updated_params->GetTagValue(TAG_KEY_SIZE, &extracted_key_size))
            updated_params->push_back(TAG_KEY_SIZE, key_size);
        else if (extracted_key_size != key_size)
            return KM_ERROR_INVALID_ARGUMENT;
    }

    return KM_ERROR_OK;
}

/*Reset all SSS Policies to default values*/
void policy_set_reset(sss_policy_u* policy) {
    if (policy->type == KPolicy_Common) {
        policy->policy.common.forbid_All = 0;
        policy->policy.common.can_Read = 1;
        policy->policy.common.can_Write = 1;
        policy->policy.common.can_Delete = 1;
        policy->policy.common.req_Sm = 0;
        policy->policy.common.req_pcr_val = 0;
    } else if (policy->type == KPolicy_Asym_Key) {
        policy->policy.asymmkey.can_Sign = 0;
        policy->policy.asymmkey.can_Verify = 0;
        policy->policy.asymmkey.can_Encrypt = 0;
        policy->policy.asymmkey.can_Decrypt = 0;
        policy->policy.asymmkey.can_Import_Export = 0;
        policy->policy.asymmkey.forbid_Derived_Output = 0;
        policy->policy.asymmkey.can_Gen = 1;
        policy->policy.asymmkey.can_KA = 0;
        policy->policy.asymmkey.can_Attest = 0;
        policy->policy.asymmkey.can_Read = 1;
        policy->policy.asymmkey.can_Write = 1;
        policy->policy.asymmkey.can_KD = 0;
        policy->policy.asymmkey.can_Wrap = 0;
    } else if (policy->type == KPolicy_Sym_Key) {
        policy->policy.symmkey.can_Sign = 0;
        policy->policy.symmkey.can_Verify = 0;
        policy->policy.symmkey.can_Encrypt = 0;
        policy->policy.symmkey.can_Decrypt = 0;
        policy->policy.symmkey.can_Import_Export = 0;
        policy->policy.symmkey.forbid_Derived_Output = 0;
        policy->policy.symmkey.can_TLS_KDF = 0;
        policy->policy.symmkey.allow_kdf_ext_rnd = 0;
        policy->policy.symmkey.can_TLS_PMS_KD = 0;
        policy->policy.symmkey.can_HKDF = 0;
        policy->policy.symmkey.can_PBKDF = 0;
        policy->policy.symmkey.can_Wrap = 0;
        policy->policy.symmkey.can_Desfire_Auth = 0;
        policy->policy.symmkey.can_Desfire_Dump = 0;
        policy->policy.symmkey.can_Desfire_KD = 0;
        policy->policy.symmkey.forbid_external_iv = 0;
        policy->policy.symmkey.can_usage_hmac_pepper = 0;
        policy->policy.symmkey.can_KD = 0;
        policy->policy.symmkey.can_Write = 1;
        policy->policy.symmkey.can_Gen = 1;
    }
}

/*Update SSS Policeis according to authorization tags passed*/
keymaster_error_t create_policy_set(const AuthorizationSet& org_params, sss_policy_u* common,
                                    sss_policy_u* key_policy) {
    /*
     *Common policies for key object
     */
    policy_set_reset(common);
    policy_set_reset(key_policy);
#if ((SSS_HAVE_SE05X_AUTH_USERID) || (SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03))
    common->auth_obj_id = EX_SSS_AUTH_SE05X_UserID_AUTH_ID;
    key_policy->auth_obj_id = EX_SSS_AUTH_SE05X_UserID_AUTH_ID;
#else
    common->auth_obj_id = 0x00000000;
    key_policy->auth_obj_id = 0x00000000;
#endif
    // common->auth_obj_id = EX_SSS_AUTH_SE05X_PIN_AUTH_ID;
    // key_policy->auth_obj_id = EX_SSS_AUTH_SE05X_PIN_AUTH_ID;
    /*
     *Key specific policies for key object
     */

    for (auto& entry : org_params) {
        if (entry.tag == TAG_PURPOSE) {
            if (entry.enumerated == KM_PURPOSE_ENCRYPT) {
                ALOGI("Policy:Encrypt");
                if (key_policy->type == KPolicy_Sym_Key)
                    key_policy->policy.symmkey.can_Encrypt = 1;
                else if (key_policy->type == KPolicy_Asym_Key)
                    key_policy->policy.asymmkey.can_Encrypt = 1;
            } else if (entry.enumerated == KM_PURPOSE_DECRYPT) {
                ALOGI("Policy:Decrypt");
                if (key_policy->type == KPolicy_Sym_Key)
                    key_policy->policy.symmkey.can_Decrypt = 1;
                else if (key_policy->type == KPolicy_Asym_Key)
                    key_policy->policy.asymmkey.can_Decrypt = 1;
            } else if (entry.enumerated == KM_PURPOSE_SIGN) {
                ALOGI("Policy:Sign");
                if (key_policy->type == KPolicy_Sym_Key)
                    key_policy->policy.symmkey.can_Sign = 1;
                else if (key_policy->type == KPolicy_Asym_Key)
                    key_policy->policy.asymmkey.can_Sign = 1;
            } else if (entry.enumerated == KM_PURPOSE_VERIFY) {
                ALOGI("Policy:Verify");
                if (key_policy->type == KPolicy_Sym_Key)
                    key_policy->policy.symmkey.can_Verify = 1;
                else if (key_policy->type == KPolicy_Asym_Key)
                    key_policy->policy.asymmkey.can_Verify = 1;
            } else if (entry.enumerated == KM_PURPOSE_DERIVE_KEY) {
                ALOGI("Policy:KD");
                if (key_policy->type == KPolicy_Sym_Key)
                    key_policy->policy.symmkey.can_KD = 1;
                else if (key_policy->type == KPolicy_Asym_Key)
                    key_policy->policy.asymmkey.can_KD = 1;
            }
            /*
            else if(entry.enumerated == KM_PURPOSE_WRAP)
              key_policy->policy.key.can_Wrap = 1;
            */
        }
    }

    return KM_ERROR_OK;
}

sss_status_t parseTPkeyObject(const keymaster_blob_t* key_data, uint32_t* keyId,
                              keymaster_algorithm_t algorithm) {
    ALOGI("%s called", __func__);
    sss_status_t status = kStatus_SSS_Fail;
    uint8_t data[200] = {0};
    uint8_t magic[] = TP_MAGIC;
    size_t magic_size = sizeof(magic);
    if (!key_data || !key_data->data) {
        ALOGI("if(!key_data || !key_data->data)");
        return kStatus_SSS_Fail;
    }
    if (key_data->data_length == 0) {
        ALOGI("if(key_data->data_length == 0)");
        return kStatus_SSS_Fail;
    }

    memcpy(&data[0], &key_data->data[0], sizeof(data));

    if (algorithm == KM_ALGORITHM_RSA) {
        uint8_t* rsaN = NULL;
        size_t rsaNlen = 0;
        uint8_t* rsaE = NULL;
        size_t rsaElen = 0;
        status = sss_util_asn1_rsa_parse_private_allow_invalid_key(
            data, sizeof(data), kSSS_CipherType_RSA_CRT, &rsaN, &rsaNlen, NULL, NULL, &rsaE,
            &rsaElen, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        ALOGI("sss_util_asn1_rsa_parse_private_allow_invalid_key : 0x%08x", status);

        if (status == kStatus_SSS_Success) {
            if (!rsaN) {
                if (rsaE)
                    free(rsaE);
                return kStatus_SSS_Fail;
            }

            if (memcmp(&rsaN[0], &magic[0], magic_size)) {
                free(rsaN);
                if (rsaE)
                    free(rsaE);
                return kStatus_SSS_Fail;
            }

            // ALOGI("TP key exist in SecureElement ");

            if (!rsaE) {
                free(rsaN);
                return kStatus_SSS_Fail;
            }
            if (rsaE[0] == 0xA5) {

                *keyId = (rsaE[1] << 8 * 3) | (rsaE[2] << 8 * 2) | (rsaE[3] << 8 * 1) | rsaE[4];
            } else {
                ALOGE("unable to parse keyID, invalid private Exponent");
                return kStatus_SSS_Fail;
            }
            // ALOGI("KeyId = 0x%08X", *keyId);
            free(rsaN);
            free(rsaE);
            return kStatus_SSS_Success;
        } else {
            if (rsaN)
                free(rsaN);
            if (rsaE)
                free(rsaE);
            return status;
        }
    } else if (algorithm == KM_ALGORITHM_EC) {
        uint16_t publicIndex = 0, privateIndex = 0;
        size_t pubLen = 0, privLen = 0;
        uint8_t privKey[70];
        status = sss_util_pkcs8_asn1_get_ec_pair_key_index(
            data, key_data->data_length, &publicIndex, &pubLen, &privateIndex, &privLen);
        ALOGI("sss_util_pkcs8_asn1_get_ec_pair_key_index : 0x%08x", status);
        if (status == kStatus_SSS_Success) {
            if (privLen <= 0) {
                return kStatus_SSS_Fail;
            }
            memcpy(&privKey[0], &data[privateIndex], privLen);
            if (memcmp(&privKey[0], &magic[0], magic_size)) {
                return kStatus_SSS_Fail;
            }
            *keyId = (privKey[magic_size] << 8 * 3) | (privKey[magic_size + 1] << 8 * 2) |
                     (privKey[magic_size + 2] << 8 * 1) | (privKey[magic_size + 3]);
            return kStatus_SSS_Success;
        } else {
            return status;
        }
    } else {
        ALOGE("Incompatible Algorithm");
        return status;
    }
}

sss_status_t verifyCipherTypeToKMAlgo(sss_cipher_type_t cipher, keymaster_algorithm_t algorithm) {
    if (cipher == kSSS_CipherType_Binary)
        return kStatus_SSS_Success;

    else if (cipher == kSSS_CipherType_EC_NIST_P) {
        if (algorithm == KM_ALGORITHM_EC)
            return kStatus_SSS_Success;
        else
            return kStatus_SSS_Fail;
    } else if (cipher == kSSS_CipherType_RSA || cipher == kSSS_CipherType_RSA_CRT) {
        if (algorithm == KM_ALGORITHM_RSA)
            return kStatus_SSS_Success;
        else
            return kStatus_SSS_Fail;
    } else {
        return kStatus_SSS_Fail;
    }
}

Se050KeymasterUtils::~Se050KeymasterUtils() {}

Se050KeymasterUtils::Se050KeymasterUtils() {
    p_boot_ctx = nullptr;
    p_rng_ctx = nullptr;
    ALOGI("Initializing Device utils");
}

Se050KeymasterUtils::Se050KeymasterUtils(ex_sss_boot_ctx_t* boot_ctx, sss_rng_context_t* rng_ctx) {
    p_boot_ctx = boot_ctx;
    p_rng_ctx = rng_ctx;
    ALOGI("Initializing Device utils with pointers");
}

sss_status_t Se050KeymasterUtils::addTPauthorizationTags(sss_object_t keyObject,
                                                         AuthorizationSet* hw_enforced) {
    smStatus_t sm_status = SM_NOT_OK;
    /* Push back algo */
    if ((keyObject.cipherType == kSSS_CipherType_RSA_CRT) ||
        (keyObject.cipherType == kSSS_CipherType_RSA)) {
        hw_enforced->push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA));
    } else if (keyObject.cipherType == kSSS_CipherType_EC_NIST_P) {
        hw_enforced->push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_EC));
    }
    /* Push back key size */
    sss_se05x_session_t* se05x_session = (sss_se05x_session_t*)&p_boot_ctx->session;
    uint16_t size = 0;
    sm_status = Se05x_API_ReadSize(&se05x_session->s_ctx, keyObject.keyId, &size);
    if (sm_status != SM_OK) {
        return kStatus_SSS_Fail;
    }
    hw_enforced->push_back(Authorization(TAG_KEY_SIZE, (uint32_t)size));
    return kStatus_SSS_Success;
}

void Se050KeymasterUtils::GetFreeMem() {
    uint32_t freeMem_PERSISTENT = 0;
    // uint32_t freeMem_TRANSIENT_RESET = 0;
    uint32_t freeMem_TRANSIENT_DESELECT = 0;
    sss_se05x_session_t* se05x_session = (sss_se05x_session_t*)&p_boot_ctx->session;
    smStatus_t status = SM_NOT_OK;
    status = Se05x_API_GetFreeMemory(&se05x_session->s_ctx, kSE05x_MemoryType_PERSISTENT,
                                     &freeMem_PERSISTENT);
    if (SM_OK == status) {
        ALOGI("Persistent memory left = %d", freeMem_PERSISTENT);
    } else {
        ALOGE("Could not read kSE05x_MemoryType_PERSISTENT");
    }

    /*status = Se05x_API_GetFreeMemory(&se05x_session->s_ctx, kSE05x_MemoryType_TRANSIENT_RESET,
    &freeMem_TRANSIENT_RESET); if (SM_OK == status) {
        ALOGI("Transient_Reset memory left = %d", freeMem_TRANSIENT_RESET);
    }
    else {
        ALOGE("Could not read kSE05x_MemoryType_TRANSIENT_RESET");
    }*/

    status = Se05x_API_GetFreeMemory(&se05x_session->s_ctx, kSE05x_MemoryType_TRANSIENT_DESELECT,
                                     &freeMem_TRANSIENT_DESELECT);
    if (SM_OK == status) {
        ALOGI("Transient_Deselect memory left = %d", freeMem_TRANSIENT_DESELECT);
    } else {
        ALOGE("Could not read kSE05x_MemoryType_TRANSIENT_DESELECT");
    }
    return;
}

/*This API is used to get the modulus value of RSA
 * key stored inside SE.*/
keymaster_error_t Se050KeymasterUtils::RsaOperationParsePubKey(sss_object_t* keyObject,
                                                               uint8_t** rsaN, size_t* rsaNlen) {
    sss_status_t status;
    uint8_t key[550];
    size_t keybytelen = sizeof(key);
    size_t keybitlen = sizeof(key) * 8;
    uint8_t* rsaE = NULL;
    size_t rsaElen;
    keymaster_error_t km_error = KM_ERROR_OK;
    if ((keyObject->keyId == 0x00000003) && ((keyObject->cipherType == kSSS_CipherType_RSA_CRT) ||
                                             (keyObject->cipherType == kSSS_CipherType_RSA))) {
        ALOGW("Non readable key exist at keyID : 0x%08X. Returning dummy key", keyObject->keyId);
        uint8_t dummy_rsa_pub[] = rsa_pub;
        memcpy(key, dummy_rsa_pub, sizeof(dummy_rsa_pub));
        keybytelen = sizeof(dummy_rsa_pub);
    } else {
        status = sss_key_store_get_key(&p_boot_ctx->ks, keyObject, key, &keybytelen, &keybitlen);
        ALOGI("%s: get_key : 0x%x", __FUNCTION__, status);
        if (status != kStatus_SSS_Success) {
            km_error = KM_ERROR_UNKNOWN_ERROR;
            goto exit;
        }
    }
    status = sss_util_asn1_rsa_parse_public(key, keybitlen, rsaN, rsaNlen, &rsaE, &rsaElen);
    ALOGI("%s: parse rsa : 0x%x", __FUNCTION__, status);
    if (status != kStatus_SSS_Success) {
        km_error = KM_ERROR_UNKNOWN_ERROR;
        goto exit;
    }
    /*ALOGI("%s: modulus:%d", __FUNCTION__, **rsaN);
    ALOGI("%s: modulusLen:%zu", __FUNCTION__, *rsaNlen);
    ALOGI("%s: exponent:%d", __FUNCTION__, *rsaE);
    ALOGI("%s: exponentLen:%zu", __FUNCTION__, rsaElen);*/
exit:
    if (rsaE)
        free(rsaE);
    return km_error;
}

/*This API is used to get the modulus value of EC
 * key stored inside SE.*/
keymaster_error_t Se050KeymasterUtils::EcOperationParsePubKey(sss_object_t* keyObject,
                                                              size_t* pubKeylen) {

    sss_se05x_object_t* p_keyObject = (sss_se05x_object_t*)keyObject;
    switch (p_keyObject->curve_id) {
    case kSE05x_ECCurve_NIST_P192:
        *pubKeylen = 192;
        break;

    case kSE05x_ECCurve_NIST_P224:
        *pubKeylen = 224;
        break;

    case kSE05x_ECCurve_NIST_P256:
        *pubKeylen = 256;
        break;

    case kSE05x_ECCurve_NIST_P384:
        *pubKeylen = 384;
        break;

    case kSE05x_ECCurve_NIST_P521:
        *pubKeylen = 521;
        break;

    default:
        ALOGE("curve_id invalid");
        return KM_ERROR_INVALID_KEY_BLOB;
        break;
    }

    return KM_ERROR_OK;
}

/*Parse HMAC operation tags and check for correct combination of tags*/
keymaster_error_t Se050KeymasterUtils::UpdateHmacOperationDescription(
    const AuthorizationSet* params, const AuthorizationSet sw_enforced,
    const AuthorizationSet hw_enforced, const keymaster_purpose_t purpose,
    sss_algorithm_t* algorithm, sss_km_operation_t* operation) {
    ALOGI("%s function called", __FUNCTION__);
    uint32_t mac_length;
    uint32_t min_mac_length;
    int count = 0;
    bool authorized_tag = false;
    keymaster_error_t km_error = KM_ERROR_OK;
    count = 0;
    authorized_tag = false;
    if (!hw_enforced.GetTagValue(TAG_MIN_MAC_LENGTH, &min_mac_length)) {
        ALOGE("AuthorizationSet does not contain TAG_MIN_MAC_LENGTH");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    keymaster_digest_t digest;
    if (!AuthorizeOperation(sw_enforced, TAG_PURPOSE, purpose) &&
        !AuthorizeOperation(hw_enforced, TAG_PURPOSE, purpose))
        return KM_ERROR_INCOMPATIBLE_PURPOSE;

    if (!params->GetTagValue(TAG_DIGEST, &digest))
        return KM_ERROR_UNSUPPORTED_DIGEST;
    if (!params->GetTagValue(TAG_MAC_LENGTH, &mac_length) && purpose == KM_PURPOSE_SIGN)
        return KM_ERROR_UNSUPPORTED_MAC_LENGTH;
    if (purpose == KM_PURPOSE_SIGN && mac_length % 8 != 0)
        return KM_ERROR_UNSUPPORTED_MAC_LENGTH;
    if (purpose == KM_PURPOSE_SIGN && mac_length < min_mac_length)
        return KM_ERROR_INVALID_MAC_LENGTH;
    switch (digest) {
    case KM_DIGEST_SHA1:
        if (purpose == KM_PURPOSE_SIGN && mac_length > 160)
            km_error = KM_ERROR_UNSUPPORTED_MAC_LENGTH;
        *algorithm = kAlgorithm_SSS_HMAC_SHA1;
        break;
    case KM_DIGEST_SHA_2_224:
        // FIXME:This error code is return here because currently we do not support HMAC with SHA224
        // in SE
        km_error = KM_ERROR_UNSUPPORTED_DIGEST;
        /*if (purpose == KM_PURPOSE_SIGN && mac_length > 224)
            return KM_ERROR_UNSUPPORTED_MAC_LENGTH;*/
        //*algorithm = /*kAlgorithm_SSS_HMAC_SHA224*/ kAlgorithm_SSS_HMAC_SHA256;
        break;
    case KM_DIGEST_SHA_2_256:
        if (purpose == KM_PURPOSE_SIGN && mac_length > 256)
            km_error = KM_ERROR_UNSUPPORTED_MAC_LENGTH;
        *algorithm = kAlgorithm_SSS_HMAC_SHA256;
        break;
    case KM_DIGEST_SHA_2_384:
        if (purpose == KM_PURPOSE_SIGN && mac_length > 384)
            km_error = KM_ERROR_UNSUPPORTED_MAC_LENGTH;
        *algorithm = kAlgorithm_SSS_HMAC_SHA384;
        break;
    case KM_DIGEST_SHA_2_512:
        if (purpose == KM_PURPOSE_SIGN && mac_length > 512)
            km_error = KM_ERROR_UNSUPPORTED_MAC_LENGTH;
        *algorithm = kAlgorithm_SSS_HMAC_SHA512;
        break;
    default:
        km_error = KM_ERROR_UNSUPPORTED_DIGEST;
    }
    if (km_error != KM_ERROR_OK)
        return km_error;
    // ALOGI("MAcLength = %d", mac_length);

    operation->op_handle.op_mac.mac_length = mac_length / 8;
    return KM_ERROR_OK;
}

/*Parse AES operation tags and check for correct combination of tags*/
keymaster_error_t Se050KeymasterUtils::UpdateAesOperationDescription(
    const AuthorizationSet* params, const AuthorizationSet sw_enforced,
    const AuthorizationSet hw_enforced, const keymaster_purpose_t purpose,
    sss_algorithm_t* algorithm, keymaster_key_param_set_t* out_params,
    sss_km_operation_t* operation) {
    ALOGI("%s Function called", __FUNCTION__);
    sss_status_t status;
    keymaster_block_mode_t block_mode;
    keymaster_padding_t padding;
    keymaster_blob_t nonce;
    uint32_t mac;
    int count = 0;
    bool authorized_tag = false;
    count = CountTags(params, TAG_BLOCK_MODE);
    if (count != 1)
        return KM_ERROR_UNSUPPORTED_BLOCK_MODE;
    count = CountTags(params, TAG_PADDING);
    if (count != 1)
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;

    params->GetTagValue(TAG_BLOCK_MODE, &block_mode);
    params->GetTagValue(TAG_PADDING, &padding);

    /*Authorize Padding*/
    if (!AuthorizeOperation(sw_enforced, TAG_PADDING, padding) &&
        !AuthorizeOperation(hw_enforced, TAG_PADDING, padding))
        return KM_ERROR_INCOMPATIBLE_PADDING_MODE;

    /*Authorize Block Mode*/
    if (!AuthorizeOperation(sw_enforced, TAG_BLOCK_MODE, block_mode) &&
        !AuthorizeOperation(hw_enforced, TAG_BLOCK_MODE, block_mode))
        return KM_ERROR_INCOMPATIBLE_BLOCK_MODE;

    count = 0;
    authorized_tag = false;

    if (padding != KM_PAD_NONE && padding != KM_PAD_PKCS7)
        return KM_ERROR_INCOMPATIBLE_PADDING_MODE;

    // FIXME: Remove this check. PKCS7 Not supported
    if (padding == KM_PAD_PKCS7)
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;

    // ALOGI("Check Block Mode");
    switch (block_mode) {
    case KM_MODE_ECB:
        ALOGI("Block Mode: ECB");
        *algorithm = kAlgorithm_SSS_AES_ECB;
        memset(operation->op_handle.op_symm.iv, 0x00, sizeof(operation->op_handle.op_symm.iv));
        operation->op_handle.op_symm.ivLen = 0;
        break;

    case KM_MODE_CBC:
        ALOGI("Block Mode: CBC");
        if (params->GetTagValue(TAG_NONCE, &nonce)) {
            if (!AuthorizeOperation(sw_enforced, TAG_CALLER_NONCE) &&
                !AuthorizeOperation(hw_enforced, TAG_CALLER_NONCE) && purpose == KM_PURPOSE_ENCRYPT)
                return KM_ERROR_CALLER_NONCE_PROHIBITED;
            if (nonce.data_length != AES_BLOCK_SIZE) {
                ALOGE("Expected %d-byte IV for AES operation, but got %zu bytes", AES_BLOCK_SIZE,
                      nonce.data_length);
                return KM_ERROR_INVALID_NONCE;
            }
            memcpy(operation->op_handle.op_symm.iv, nonce.data, nonce.data_length);
        } else {  // Generate 16-byte random IV and assign to iv
            status = sss_rng_get_random(p_rng_ctx, operation->op_handle.op_symm.iv, AES_BLOCK_SIZE);
            if (status != kStatus_SSS_Success) {
                return KM_ERROR_UNKNOWN_ERROR;
            }
            AuthorizationSet nonce_params(
                AuthorizationSetBuilder()
                    .Authorization(TAG_NONCE, operation->op_handle.op_symm.iv, AES_BLOCK_SIZE)
                    .build());
            nonce_params.CopyToParamSet(out_params);
        }
        *algorithm = kAlgorithm_SSS_AES_CBC;
        operation->op_handle.op_symm.ivLen = AES_BLOCK_SIZE;
        break;

    case KM_MODE_CTR:
        ALOGI("Block Mode: CTR");
        if (params->GetTagValue(TAG_NONCE, &nonce)) {
            if (!AuthorizeOperation(sw_enforced, TAG_CALLER_NONCE) &&
                !AuthorizeOperation(hw_enforced, TAG_CALLER_NONCE) && purpose == KM_PURPOSE_ENCRYPT)
                return KM_ERROR_CALLER_NONCE_PROHIBITED;
            if (nonce.data_length != AES_BLOCK_SIZE) {
                ALOGE("Expected %d-byte IV for AES operation, but got %zu bytes", AES_BLOCK_SIZE,
                      nonce.data_length);
                return KM_ERROR_INVALID_NONCE;
            }
            memcpy(operation->op_handle.op_symm.iv, nonce.data, nonce.data_length);
        } else {
            /* Generate 16-byte random IV and assign to iv*/
            status = sss_rng_get_random(p_rng_ctx, operation->op_handle.op_symm.iv, AES_BLOCK_SIZE);
            if (status != kStatus_SSS_Success) {
                return KM_ERROR_UNKNOWN_ERROR;
            }

            AuthorizationSet nonce_params(
                AuthorizationSetBuilder()
                    .Authorization(TAG_NONCE, operation->op_handle.op_symm.iv, AES_BLOCK_SIZE)
                    .build());
            nonce_params.CopyToParamSet(out_params);
        }
        *algorithm = kAlgorithm_SSS_AES_CTR;
        operation->op_handle.op_symm.ivLen = AES_BLOCK_SIZE;
        break;

    case KM_MODE_GCM:
        ALOGI("Block Mode: GCM");
        if (!params->GetTagValue(TAG_MAC_LENGTH, &mac))
            return KM_ERROR_UNSUPPORTED_MAC_LENGTH;

        if ((mac > 128) || ((mac % 8) != 0))
            return KM_ERROR_UNSUPPORTED_MAC_LENGTH;

        else if (mac < 128)
            return KM_ERROR_INVALID_MAC_LENGTH;

        if (params->GetTagValue(TAG_NONCE, &nonce)) {
            if (!AuthorizeOperation(sw_enforced, TAG_CALLER_NONCE) &&
                !AuthorizeOperation(hw_enforced, TAG_CALLER_NONCE) && purpose == KM_PURPOSE_ENCRYPT)
                return KM_ERROR_CALLER_NONCE_PROHIBITED;
            if (nonce.data_length != GCM_NONCE_SIZE) {
                ALOGE("Expected %d-byte nonce for AES-GCM, but got %zu bytes", GCM_NONCE_SIZE,
                      nonce.data_length);
                return KM_ERROR_INVALID_NONCE;
            }
            memcpy(operation->op_handle.op_symm.iv, nonce.data, nonce.data_length);
        } else {
            /*Generate 12-byte random NONCE and assign to iv*/
            status = sss_rng_get_random(p_rng_ctx, operation->op_handle.op_symm.iv, GCM_NONCE_SIZE);
            if (status != kStatus_SSS_Success) {
                return KM_ERROR_UNKNOWN_ERROR;
            }
            AuthorizationSet nonce_params(
                AuthorizationSetBuilder()
                    .Authorization(TAG_NONCE, operation->op_handle.op_symm.iv, GCM_NONCE_SIZE)
                    .build());
            nonce_params.CopyToParamSet(out_params);
        }
        *algorithm = kAlgorithm_SSS_AES_GCM;
        operation->op_handle.op_symm.ivLen = GCM_NONCE_SIZE;
        break;

    default:
        return KM_ERROR_UNSUPPORTED_BLOCK_MODE;
    }

    operation->op_handle.op_symm.block_mode = block_mode;
    operation->op_handle.op_symm.padding = padding;
    return KM_ERROR_OK;
}

/*Parse RSA Operation tags and check for correct combination of tags*/
keymaster_error_t Se050KeymasterUtils::UpdateRsaOperationDescription(
    const AuthorizationSet* params, const AuthorizationSet sw_enforced,
    const AuthorizationSet hw_enforced, sss_object_t* keyObject, keymaster_purpose_t purpose,
    sss_algorithm_t* algorithm, sss_km_operation_t* operation) {
    keymaster_padding_t padding_mode;
    keymaster_digest_t digest;
    size_t rsaNlen, digest_size;
    keymaster_error_t km_error = KM_ERROR_OK;
    uint8_t* rsaN = NULL;

    if (!AuthorizeOperation(sw_enforced, TAG_PURPOSE, purpose) &&
        !AuthorizeOperation(hw_enforced, TAG_PURPOSE, purpose))
        return KM_ERROR_INCOMPATIBLE_PURPOSE;

    /* Sign / Verify operations for RSA*/
    if (purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_VERIFY) {
        if (params->GetTagValue(TAG_PADDING, &padding_mode)) {
            // if (padding_mode != KM_PAD_RSA_PKCS1_1_5_SIGN && padding_mode != KM_PAD_RSA_PSS &&
            //     padding_mode != KM_PAD_NONE)
            //     return KM_ERROR_UNSUPPORTED_PADDING_MODE;

            // Checks based on padding mode selected
            switch (padding_mode) {
            case KM_PAD_NONE:
                if (params->GetTagValue(TAG_DIGEST, &digest)) {
                    if (digest != KM_DIGEST_NONE) /* Sign/Verify Operations with no padding should
                                                   specify DIGEST::NONE*/
                        km_error = KM_ERROR_INCOMPATIBLE_DIGEST;

                    /* Tags passed are correct, set algorithm now*/
                    *algorithm = kAlgorithm_SSS_RSASSA_NO_PADDING;
                } else {
                    km_error = KM_ERROR_UNSUPPORTED_DIGEST;
                }
                break;

            case KM_PAD_RSA_PKCS1_1_5_SIGN:
                if (!params->GetTagValue(TAG_DIGEST,
                                         &digest)) { /* Sign/Verify operations with PKCS1_V1_5
                                                      * padding need a digest tag*/
                    km_error = KM_ERROR_UNSUPPORTED_DIGEST;
                    break;
                }

                switch (digest) {
                case KM_DIGEST_NONE: /* Message should not be hashed. Check if size is correct
                                      (finish). Set algorithm.*/
                    *algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH;
                    break;
                    /*Message should be hashed. Set algorithm based
                    on digest*/

                case KM_DIGEST_SHA1:
                    *algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1;
                    break;

                case KM_DIGEST_SHA_2_224:
                    *algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224;
                    break;

                case KM_DIGEST_SHA_2_256:
                    *algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
                    break;

                case KM_DIGEST_SHA_2_384:
                    *algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384;
                    break;

                case KM_DIGEST_SHA_2_512:
                    *algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512;
                    break;

                default:
                    *algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
                    break;
                }

                break;

            case KM_PAD_RSA_PSS:
                if (!params->GetTagValue(TAG_DIGEST,
                                         &digest)) {  // Sign / Verify operations with padding PSS
                                                      // require not NONE digests
                    km_error = KM_ERROR_UNSUPPORTED_DIGEST;
                    break;
                }

                if (digest == KM_DIGEST_NONE) {
                    km_error = KM_ERROR_INCOMPATIBLE_DIGEST;
                    break;
                }

                // RSA_KeySizeBytes >= 2 + D*2 ///////Check this here

                km_error = RsaOperationParsePubKey(keyObject, &rsaN, &rsaNlen);
                // ALOGI("RsaOperationParsePubKey retval : %d", km_error);
                if (km_error != KM_ERROR_OK)
                    break;

                // Set algorithm according to digest
                switch (digest) {
                case KM_DIGEST_SHA1:
                    *algorithm = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA1;
                    digest_size = 20;
                    break;

                case KM_DIGEST_SHA_2_224:
                    *algorithm = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA224;
                    digest_size = 28;
                    break;

                case KM_DIGEST_SHA_2_256:
                    *algorithm = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256;
                    digest_size = 32;
                    break;

                case KM_DIGEST_SHA_2_384:
                    *algorithm = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA384;
                    digest_size = 48;
                    break;

                case KM_DIGEST_SHA_2_512:
                    *algorithm = kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA512;
                    digest_size = 64;
                    break;

                default:
                    km_error = KM_ERROR_INCOMPATIBLE_DIGEST;
                }
                if (km_error != KM_ERROR_OK)
                    break;
                km_error =
                    (rsaNlen >= (2 * digest_size) + 2) ? KM_ERROR_OK : KM_ERROR_INCOMPATIBLE_DIGEST;
                break;
            default:
                km_error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
                break;
            }

        } else {
            km_error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
        }
        if (km_error != KM_ERROR_OK)
            goto error;

    }

    // Encrypt / Decrypt operations for RSA
    else if (purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_DECRYPT) {
        if (params->GetTagValue(TAG_PADDING, &padding_mode)) {
            // if (padding_mode != KM_PAD_RSA_PKCS1_1_5_ENCRYPT && padding_mode != KM_PAD_RSA_OAEP
            // &&
            //     padding_mode != KM_PAD_NONE)
            //     return KM_ERROR_UNSUPPORTED_PADDING_MODE;

            switch (padding_mode) {
            case KM_PAD_NONE:
                *algorithm = kAlgorithm_SSS_SHA1;
                break;

            case KM_PAD_RSA_PKCS1_1_5_ENCRYPT:
                *algorithm = kAlgorithm_SSS_RSAES_PKCS1_V1_5;  // Common algorithm. PKCS1_V1_5
                                                               // does not need a digest

                break;

            case KM_PAD_RSA_OAEP:
                if (!params->GetTagValue(TAG_DIGEST, &digest)) {
                    // ALOGI("%d: Tag digest not present", __LINE__);
                    km_error = KM_ERROR_INCOMPATIBLE_DIGEST;
                    break;
                }

                if (digest == KM_DIGEST_NONE) {
                    // ALOGI("%d: Tag digest not present", __LINE__);
                    km_error = KM_ERROR_INCOMPATIBLE_DIGEST;
                    break;
                }

                if (digest == KM_DIGEST_SHA1)
                    *algorithm = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1;

                else if (digest == KM_DIGEST_SHA_2_224) {
                    km_error = KM_ERROR_UNSUPPORTED_DIGEST;
                    // *algorithm = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA224;
                }

                else if (digest == KM_DIGEST_SHA_2_256) {
                    km_error = KM_ERROR_UNSUPPORTED_DIGEST;
                    // *algorithm = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256;
                }

                else if (digest == KM_DIGEST_SHA_2_384) {
                    km_error = KM_ERROR_UNSUPPORTED_DIGEST;
                    // *algorithm = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA384;
                }

                else if (digest == KM_DIGEST_SHA_2_512) {
                    km_error = KM_ERROR_UNSUPPORTED_DIGEST;
                    // *algorithm = kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA512;
                }

                else {
                    // ALOGI("%d: Tag digest not present", __LINE__);
                    km_error = KM_ERROR_INCOMPATIBLE_DIGEST;
                }

                break;

            default:
                km_error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
            }
        } else {
            km_error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
        }
        if (km_error != KM_ERROR_OK)
            goto error;
    }

    if (purpose == KM_PURPOSE_SIGN) {
        /*Authorize Padding*/
        if (!AuthorizeOperation(sw_enforced, TAG_PADDING, padding_mode) &&
            !AuthorizeOperation(hw_enforced, TAG_PADDING, padding_mode)) {
            // ALOGE("%d:KM_ERROR_INCOMPATIBLE_PADDING_MODE", __LINE__);
            km_error = KM_ERROR_INCOMPATIBLE_PADDING_MODE;
            goto error;
        }
        /*Authorize Digest*/
        if (!AuthorizeOperation(sw_enforced, TAG_DIGEST, digest) &&
            !AuthorizeOperation(hw_enforced, TAG_DIGEST, digest)) {
            // ALOGI("%d:KM_ERROR_INCOMPATIBLE_DIGEST", __LINE__);
            km_error = KM_ERROR_INCOMPATIBLE_DIGEST;
            goto error;
        }
    }

    if (!params->GetTagValue(TAG_PADDING, &padding_mode))
        operation->op_handle.op_asymm.padding = KM_PAD_NONE;
    else
        operation->op_handle.op_asymm.padding = padding_mode;

    if (!params->GetTagValue(TAG_DIGEST, &digest))
        operation->op_handle.op_asymm.digest = KM_DIGEST_NONE;
    else
        operation->op_handle.op_asymm.digest = digest;
    km_error = KM_ERROR_OK;

error:
    if (rsaN)
        free(rsaN);
    return km_error;
}

/*Calculate hash value on raw data passed ot keymaster*/
keymaster_error_t Se050KeymasterUtils::SignOperationCalculateDigest(uint8_t* data,
                                                                    size_t data_length,
                                                                    sss_algorithm_t algorithm,
                                                                    size_t* digestLen) {
    keymaster_error_t km_error;
    uint8_t input[2048];
    uint8_t output[64];
    // size_t outputLen = sizeof(output);
    *digestLen = sizeof(output);
    sss_digest_t digest_ctx;
    sss_mode_t mode = kMode_SSS_Digest;
    sss_algorithm_t digest_algo;
    sss_status_t status;
    size_t i = 0;

    memcpy(&input, data, data_length);
    km_error = GetSSSAlgorithm(algorithm, &digest_algo);
    if (km_error != KM_ERROR_OK)
        return km_error;

        // ALOGI("DigestAlgo = %d", digest_algo);
#if SSS_HAVE_HOSTCRYPTO_ANY
    status = sss_digest_context_init(&digest_ctx, &p_boot_ctx->host_session, digest_algo, mode);
#else
    status = kStatus_SSS_Fail;
#endif
    ALOGI("sss_digest_context_init : 0x%x", status);
    if (status != kStatus_SSS_Success) {
        return KM_ERROR_INCOMPATIBLE_DIGEST;
    }

    status = sss_digest_init(&digest_ctx);
    ALOGI("sss_digest_init status : 0x%x", status);
    if (status != kStatus_SSS_Success) {
        km_error = KM_ERROR_INCOMPATIBLE_DIGEST;
        goto cleanup;
    }
    while (data_length > 1000) {
        status = sss_digest_update(&digest_ctx, &input[0 + i * 1000], 1000);
        ALOGI("sss_digest_update status : 0x%x", status);
        i++;
        data_length = data_length - 1000;
    }
    // ALOGI("data_length = %zu", data_length);
    status = sss_digest_update(&digest_ctx, &input[0 + i * 1000], data_length);
    ALOGI("sss_digest_update status : 0x%x", status);
    status = sss_digest_finish(&digest_ctx, output, digestLen);
    ALOGI("sss_digest_finish status : 0x%x", status);
    if (status != kStatus_SSS_Success) {
        km_error = KM_ERROR_INCOMPATIBLE_DIGEST;
        goto cleanup;
    }

    switch (digest_algo) {
    case kAlgorithm_SSS_SHA1:
        *digestLen = 20;
        break;
    case kAlgorithm_SSS_SHA224:
        *digestLen = 28;
        break;
    case kAlgorithm_SSS_SHA256:
        *digestLen = 32;
        break;
    case kAlgorithm_SSS_SHA384:
        *digestLen = 48;
        break;
    case kAlgorithm_SSS_SHA512:
        *digestLen = 64;
        break;
    default:
        km_error = KM_ERROR_INCOMPATIBLE_DIGEST;
        goto cleanup;
    }
    /*for (i = 0; i < *digestLen; i++)
        ALOGI("digest[%d] = %d", i, output[i]);*/
    km_error = KM_ERROR_OK;
    memcpy(data, &output, *digestLen);
cleanup:
    sss_digest_context_free(&digest_ctx);
    return km_error;
}

keymaster_error_t Se050KeymasterUtils::process_mac_operation(sss_km_operation_t* operation,
                                                             const keymaster_blob_t* input,
                                                             const keymaster_blob_t* signature,
                                                             uint8_t* mac, size_t* mac_length) {
    keymaster_error_t km_error = KM_ERROR_OK;
    sss_status_t status;
    sss_km_mac_context_t macCtx = operation->op_handle.op_mac;
    sss_mode_t mode = macCtx.mac_ctx.mode;
    uint8_t data[2048] = {0};
    uint8_t sig[512] = {0};
    size_t sig_len = 0;
    if (input->data) {
        memcpy(&data[0], input->data, input->data_length);
    }
    switch (mode) {
    case kMode_SSS_Mac:
        if (input->data_length > 0) {
            status = sss_mac_update(&macCtx.mac_ctx, &data[0], input->data_length);
            ALOGD("sss_mac_update : 0x%x", status);
            if (status != kStatus_SSS_Success) {
                km_error = KM_ERROR_OPERATION_CANCELLED;
                goto cleanup;
            }
        }
        status = sss_mac_finish(&macCtx.mac_ctx, mac, mac_length);
        ALOGD("sss_mac_finish : 0x%x", status);
        if (status != kStatus_SSS_Success) {
            km_error = KM_ERROR_OPERATION_CANCELLED;
            goto cleanup;
        }
        // ALOGD("MacLength = %d", macCtx.mac_length);
        *mac_length = macCtx.mac_length;
        break;
    case kMode_SSS_Mac_Validate:
        if (signature == nullptr || signature->data == nullptr) {
            km_error = KM_ERROR_UNEXPECTED_NULL_POINTER;
            goto cleanup;
        }
        memcpy(sig, signature->data, signature->data_length);
        sig_len = signature->data_length;
        if (input->data_length > 0) {
            status = sss_mac_update(&macCtx.mac_ctx, &data[0], input->data_length);
            ALOGD("sss_mac_update : 0x%x", status);
            if (status != kStatus_SSS_Success) {
                km_error = KM_ERROR_OPERATION_CANCELLED;
                goto cleanup;
            }
        }
        status = sss_mac_finish(&macCtx.mac_ctx, sig, &sig_len);
        ALOGD("sss_mac_finish : 0x%x", status);
        if (status != kStatus_SSS_Success) {
            km_error = KM_ERROR_VERIFICATION_FAILED;
            goto cleanup;
        }

        break;
    default:
        km_error = KM_ERROR_UNSUPPORTED_PURPOSE;
        goto cleanup;
    }
    km_error = KM_ERROR_OK;
cleanup:
    free(operation->op_handle.op_mac.mac_ctx.keyObject);
    sss_mac_context_free(&operation->op_handle.op_mac.mac_ctx);
    free(operation);
    return km_error;
}

keymaster_error_t Se050KeymasterUtils::process_symmetric_operation(sss_km_operation_t* operation,
                                                                   const AuthorizationSet* params,
                                                                   const keymaster_blob_t* input,
                                                                   uint8_t* signature1,
                                                                   size_t* signaturelen) {
    ALOGI("%s function called ", __func__);
    keymaster_error_t km_error = KM_ERROR_OK;
    sss_status_t status;
    uint8_t data[2048] = {0};
    size_t dataLen = sizeof(data);
    uint8_t tag[AES_BLOCK_SIZE] = {0};
    size_t tagLen = sizeof(tag);
    size_t i;
    size_t dummy_size = 0;
    sss_mode_t mode;
    sss_km_symmetric_context_t symmCtx = operation->op_handle.op_symm;
    keymaster_blob_t aad;
    if (input->data) {
        memcpy(&data[0], input->data, input->data_length);
        /*for(i=0;i< input->data_length; i++)
        {
            ALOGI("input data[%zu] = %02x", i, data[i]);
        }
        ALOGI("input dataLen = %zu", input->data_length);*/
    }
    dataLen = input->data_length;
    if (symmCtx.block_mode == KM_MODE_GCM)
        mode = symmCtx.aead_ctx.mode;
    else
        mode = symmCtx.symm_ctx.mode;

    switch (mode) {
    case kMode_SSS_Encrypt:

        if (symmCtx.aead_ctx.keyObject) {
            dummy_size = AES_BLOCK_SIZE;
            if (symmCtx.block_mode == KM_MODE_GCM) {
                if (params->GetTagValue(TAG_ASSOCIATED_DATA, &aad)) {
                    status = sss_aead_update_aad(&(symmCtx.aead_ctx), aad.data, aad.data_length);
                    ALOGI("sss_aead_update_aad : %x", status);
                    if (status != kStatus_SSS_Success) {
                        km_error = KM_ERROR_OPERATION_CANCELLED;
                        goto cleanup;
                    }
                }
                if (dataLen > AES_BLOCK_SIZE) {
                    ALOGW("Input data is greater than AES_BLOCK_SIZE");
                    //*signaturelen = dataLen;
                    status = sss_aead_update(&(symmCtx.aead_ctx), data, dataLen, signature1,
                                             signaturelen);
                    ALOGI("sss_aead_update : %x", status);
                    if (status != kStatus_SSS_Success) {
                        km_error = KM_ERROR_OPERATION_CANCELLED;
                        goto cleanup;
                    }
                    status = sss_aead_finish(&(symmCtx.aead_ctx), NULL, 0,
                                             &signature1[*signaturelen], &dummy_size, tag, &tagLen);
                    *signaturelen += dummy_size;
                } else {
                    status = sss_aead_finish(&(symmCtx.aead_ctx), data, dataLen, signature1,
                                             signaturelen, tag, &tagLen);
                    //*signaturelen += dummy_size;
                }
                ALOGI("sss_aead_finish : %x", status);
                if (status != kStatus_SSS_Success) {
                    km_error = KM_ERROR_OPERATION_CANCELLED;
                    goto cleanup;
                }
                if (!data_.reserve(tagLen)) {
                    km_error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                    goto cleanup;
                }
                if (!data_.write(&tag[0], tagLen)) {
                    km_error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                    goto cleanup;
                }
            }
        }
        if (symmCtx.symm_ctx.keyObject) {
            if (symmCtx.block_mode == KM_MODE_ECB || symmCtx.block_mode == KM_MODE_CBC) {
                if (symmCtx.padding == KM_PAD_NONE) {
                    km_error = ((dataLen % AES_BLOCK_SIZE) == 0) ? KM_ERROR_OK
                                                                 : KM_ERROR_INVALID_INPUT_LENGTH;
                    if (km_error != KM_ERROR_OK)
                        goto cleanup;
                }
            }
            if (dataLen > AES_BLOCK_SIZE) {
                status =
                    sss_cipher_update(&symmCtx.symm_ctx, data, dataLen, signature1, signaturelen);
                if (status != kStatus_SSS_Success) {
                    km_error = KM_ERROR_OPERATION_CANCELLED;
                    goto cleanup;
                }
                status = sss_cipher_finish(&symmCtx.symm_ctx, NULL, 0, &signature1[*signaturelen],
                                           &dummy_size);
                *signaturelen = *signaturelen + dummy_size;
            } else {
                status =
                    sss_cipher_finish(&symmCtx.symm_ctx, data, dataLen, signature1, signaturelen);
            }
            ALOGD("sss_cipher_finish :0x%x", status);
            if (status != kStatus_SSS_Success) {
                km_error = KM_ERROR_OPERATION_CANCELLED;
                goto cleanup;
            }
            /*for (i = 0; i < *signaturelen; i++)
                ALOGI("Encrypted[%d] = %d", i, signature1[i]);*/
        }

        break;

    case kMode_SSS_Decrypt:

        if (symmCtx.aead_ctx.keyObject) {
            //*signaturelen = input->data_length;

            if (data_.available_read()) {
                tagLen = data_.available_read();
                memcpy(&tag[0], data_.peek_read(), tagLen);
                data_.Clear();
            }

            if (symmCtx.block_mode == KM_MODE_GCM) {
                if (params->GetTagValue(TAG_ASSOCIATED_DATA, &aad)) {
                    status = sss_aead_update_aad(&(symmCtx.aead_ctx), aad.data, aad.data_length);
                    ALOGI("sss_aead_update_aad : %x", status);
                    if (status != kStatus_SSS_Success) {
                        km_error = KM_ERROR_OPERATION_CANCELLED;
                        goto cleanup;
                    }
                }
                if (dataLen > AES_BLOCK_SIZE) {
                    dummy_size = AES_BLOCK_SIZE;
                    status =
                        sss_aead_update(&symmCtx.aead_ctx, data, dataLen, signature1, signaturelen);
                    if (status != kStatus_SSS_Success) {
                        km_error = KM_ERROR_OPERATION_CANCELLED;
                        goto cleanup;
                    }
                    status = sss_aead_finish(&symmCtx.aead_ctx, NULL, 0, &signature1[*signaturelen],
                                             &dummy_size, tag, &tagLen);
                    *signaturelen += dummy_size;
                } else {
                    /*status = sss_aead_finish(&symmCtx.aead_ctx, data, dataLen,
                                             &signature1[*signaturelen], &dummy_size, tag, &tagLen);

                    *signaturelen += dummy_size;*/
                    status = sss_aead_finish(&symmCtx.aead_ctx, data, dataLen, signature1,
                                             signaturelen, tag, &tagLen);

                    *signaturelen += dummy_size;
                }
                ALOGI("sss_aead_finish : %x", status);
                i = 0;
                while ((signature1[*signaturelen - 1 - i] == 0) && i < *signaturelen) {
                    i++;
                }
                *signaturelen = *signaturelen - i;
                if (status != kStatus_SSS_Success) {
                    km_error = KM_ERROR_VERIFICATION_FAILED;
                    goto cleanup;
                }
            }
        }
        if (symmCtx.symm_ctx.keyObject) {
            *signaturelen = input->data_length;
            if (dataLen > AES_BLOCK_SIZE) {
                dummy_size = 0;
                status =
                    sss_cipher_update(&symmCtx.symm_ctx, data, dataLen, signature1, signaturelen);
                if (status != kStatus_SSS_Success) {
                    km_error = KM_ERROR_OPERATION_CANCELLED;
                    goto cleanup;
                }
                status = sss_cipher_finish(&symmCtx.symm_ctx, NULL, 0, &signature1[*signaturelen],
                                           &dummy_size);
                *signaturelen = *signaturelen + dummy_size;
            } else {
                status =
                    sss_cipher_finish(&symmCtx.symm_ctx, data, dataLen, signature1, signaturelen);
            }
            ALOGD("sss_cipher_finish : %x", status);
            i = 0;
            while ((signature1[*signaturelen - 1 - i] == 0) && i < *signaturelen) {
                i++;
            }
            *signaturelen = *signaturelen - i;
            if (status != kStatus_SSS_Success) {
                km_error = KM_ERROR_OPERATION_CANCELLED;
                goto cleanup;
            }
        }
        break;

    default:
        ALOGE("Unsupported  Purpose");
        km_error = KM_ERROR_UNSUPPORTED_PURPOSE;
        goto cleanup;
        break;
    }

    km_error = KM_ERROR_OK;

cleanup:
    if (operation->op_handle.op_symm.symm_ctx.keyObject) {
        free(operation->op_handle.op_symm.symm_ctx.keyObject);
        sss_symmetric_context_free(&operation->op_handle.op_symm.symm_ctx);
    }
    if (operation->op_handle.op_symm.aead_ctx.keyObject) {
        free(operation->op_handle.op_symm.aead_ctx.keyObject);
        sss_aead_context_free(&operation->op_handle.op_symm.aead_ctx);
    }
    free(operation);
    return km_error;
}

keymaster_error_t Se050KeymasterUtils::process_asymmetric_operation(
    sss_km_operation_t* operation, const keymaster_blob_t* input, const keymaster_blob_t* signature,
    uint8_t* signature1, size_t* signaturelen) {
    keymaster_error_t km_error = KM_ERROR_OK;
    sss_status_t status;
    Buffer buff;
    uint8_t data[2048] = {0};
    size_t parsedKeyByteLen;
    uint8_t* rsaN = nullptr;
    size_t digestLen = 0;
    size_t buffer_size = 0;
    sss_mode_t mode;
    sss_km_asymmetric_context_t* asymmCtx = &operation->op_handle.op_asymm;
    if (!asymmCtx || !asymmCtx->asymm_ctx.keyObject) {
        km_error = KM_ERROR_UNEXPECTED_NULL_POINTER;
        goto cleanup;
    }

    if (asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_RSA ||
        asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_RSA_CRT) {
        buff.Reinitialize(asymmCtx->update_rsa_buf);
        buffer_size = buff.available_read();
        if (buffer_size) {
            memcpy(&data[0], buff.peek_read(), buffer_size);
            asymmCtx->update_rsa_buf.Clear();
        }
        if (input->data) {
            ALOGI("input data present");
            memcpy(&data[buffer_size], input->data, input->data_length);
            buffer_size = buffer_size + input->data_length;
        }
    } else if (asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_EC_NIST_P) {
        buff.Reinitialize(operation->op_handle.op_asymm.update_ec_buf);
        buffer_size = buff.available_read();
        if (buffer_size) {
            memcpy(&data[0], buff.peek_read(), buffer_size);
            asymmCtx->update_ec_buf.Clear();
        }
        if (input->data) {
            ALOGI("input data present");
            memcpy(&data[buffer_size], input->data, input->data_length);
            buffer_size = buffer_size + input->data_length;
        }
    }
    ALOGI("Buffer size = %zu", buffer_size);
    mode = asymmCtx->asymm_ctx.mode;

    switch (mode) {

    case kMode_SSS_Sign:

        if (!asymmCtx->asymm_ctx.keyObject) {
            km_error = KM_ERROR_UNEXPECTED_NULL_POINTER;
            goto cleanup;
        }
        if (asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_RSA ||
            asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_RSA_CRT) {
            // Parse data for RSA according to digest and padding tags
            km_error =
                RsaOperationParsePubKey(asymmCtx->asymm_ctx.keyObject, &rsaN, &parsedKeyByteLen);
            ALOGI("%s: rsaN = %d", __FUNCTION__, *rsaN);
            if (asymmCtx->padding == KM_PAD_RSA_PKCS1_1_5_SIGN &&
                asymmCtx->digest == KM_DIGEST_NONE) {
                if (km_error != KM_ERROR_OK)
                    goto cleanup;

                km_error = (parsedKeyByteLen >= buffer_size + 11) ? KM_ERROR_OK
                                                                  : KM_ERROR_INVALID_INPUT_LENGTH;
                if (km_error != KM_ERROR_OK)
                    goto cleanup;

            } else if (asymmCtx->padding == KM_PAD_NONE) {
                km_error = RawSignCheckDataValue(data, buffer_size, &rsaN, parsedKeyByteLen);
                if (km_error != KM_ERROR_OK)
                    goto cleanup;
            }
            digestLen = buffer_size;
        }
        if ((asymmCtx->padding != KM_PAD_NONE && asymmCtx->digest != KM_DIGEST_NONE &&
             (asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_RSA ||
              asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_RSA_CRT)) ||
            asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_EC_NIST_P) {
            km_error = SignOperationCalculateDigest(data, buffer_size,
                                                    asymmCtx->asymm_ctx.algorithm, &digestLen);
            if (km_error != KM_ERROR_OK) {
                ALOGE("SignOperationCalculateDigest return value: %d", km_error);
                goto cleanup;
            }
        }
        // ALOGI("digestLen = %zu", digestLen);
        /*for (i = 0; i < digestLen; i++)
            ALOGI("data[%d] = %d", i, data[i]);*/
        /*ALOGD("signaturelen = %zu", *signaturelen);
        ALOGD("algorithm = %d", asymmCtx->asymm_ctx.algorithm);
        ALOGD("mode = %d", asymmCtx->asymm_ctx.mode);*/
        status = sss_asymmetric_sign_digest(&asymmCtx->asymm_ctx, &data[0], digestLen, signature1,
                                            signaturelen);
        ALOGD("sss_asymmetric_sign_digest :0x%x", status);
        // ALOGI("signaturelen = %zu", *signaturelen);
        /*for (i = 0; i < *signaturelen; i++)
            ALOGI("signature[%d] = %x", i, signature1[i]);*/

        if (kStatus_SSS_Success != status) {
            km_error = KM_ERROR_OPERATION_CANCELLED;
            goto cleanup;
        }
        break;

    case kMode_SSS_Verify:
        if (signature->data == nullptr) {
            ALOGE("signature is NULL");
            km_error = KM_ERROR_UNEXPECTED_NULL_POINTER;
            goto cleanup;
        }
        if (!asymmCtx->asymm_ctx.keyObject) {
            km_error = KM_ERROR_UNEXPECTED_NULL_POINTER;
            goto cleanup;
        }

        if ((asymmCtx->padding != KM_PAD_NONE &&
             (asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_RSA ||
              asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_RSA_CRT)) ||
            asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_EC_NIST_P) {
            km_error = SignOperationCalculateDigest(data, buffer_size,
                                                    asymmCtx->asymm_ctx.algorithm, &digestLen);
            if (km_error != KM_ERROR_OK) {
                ALOGE("SignOperationCalculateDigest return value: %d", km_error);
                goto cleanup;
            }
        } else {
            digestLen = buffer_size;
        }
        memcpy(&signature1[0], signature->data, signature->data_length);
        /*for (i = 0; i < digestLen; i++)
            ALOGI("digest_input[%d] = %d", i, data[i]);*/
        /*for (i = 0; i < signature->data_length; i++)
            ALOGI("signature[%d] = %d", i, signature1[i]);*/
        status = sss_asymmetric_verify_digest(&asymmCtx->asymm_ctx, &data[0], digestLen, signature1,
                                              signature->data_length);
        ALOGD("sss_asymmetric_verify_digest :0x%x", status);
        if (kStatus_SSS_Success != status) {
            km_error = KM_ERROR_VERIFICATION_FAILED;
            goto cleanup;
        }

        km_error = KM_ERROR_OK;
        goto cleanup;
        break;

    case kMode_SSS_Encrypt:
        /*for (int i = 0; i<buffer_size; i++)
        {
          ALOGI("data[%d] : %d", i, data[i]);
        }*/
        if (asymmCtx->asymm_ctx.keyObject) {
            km_error =
                RsaOperationParsePubKey(asymmCtx->asymm_ctx.keyObject, &rsaN, &parsedKeyByteLen);
            if (km_error != KM_ERROR_OK)
                goto cleanup;

            if (asymmCtx->padding == KM_PAD_NONE) {
                digestLen = buffer_size;
                km_error = RawSignCheckDataValue(data, buffer_size, &rsaN, parsedKeyByteLen);
                // ALOGE("%d:km_error:%d", __LINE__, km_error);
                if (km_error != KM_ERROR_OK)
                    goto cleanup;
                if (parsedKeyByteLen > buffer_size) {
                    uint8_t temp[buffer_size];
                    if (buffer_size > 0) {
                        memcpy(&temp[0], &data[0], buffer_size);
                        memset(&data[0], 0x00, sizeof(data));
                        memcpy(&data[parsedKeyByteLen - buffer_size], &temp[0], buffer_size);
                    }
                    digestLen = parsedKeyByteLen;
                }
            } else if (asymmCtx->padding == KM_PAD_RSA_PKCS1_1_5_ENCRYPT &&
                       asymmCtx->digest == KM_DIGEST_NONE) {
                /*ALOGI("%d :: KeyByteLen: %zu", __LINE__, parsedKeyByteLen);
                ALOGI("%d :: inputLength: %zu", __LINE__, buffer_size);*/
                /* Check: message_length <= KeyByteLen - 11 */
                km_error = (parsedKeyByteLen >= buffer_size + 11) ? KM_ERROR_OK
                                                                  : KM_ERROR_INVALID_INPUT_LENGTH;
                if (km_error != KM_ERROR_OK)
                    goto cleanup;

                digestLen = buffer_size;

            } else  // Check for OAEP Encryption
            {
                // Check: message_length <= KeyByteLen - 2*digest_size -2
                switch (asymmCtx->asymm_ctx.algorithm) {
                case kAlgorithm_SSS_RSASSA_PKCS1_OEAP_SHA1:
                    km_error = (parsedKeyByteLen >= buffer_size + (2 * 20) + 2)
                                   ? KM_ERROR_OK
                                   : KM_ERROR_INVALID_INPUT_LENGTH;
                    break;
                case kAlgorithm_SSS_RSASSA_PKCS1_OEAP_SHA224:
                    km_error = (parsedKeyByteLen >= buffer_size + (2 * 28) + 2)
                                   ? KM_ERROR_OK
                                   : KM_ERROR_INVALID_INPUT_LENGTH;
                    break;
                case kAlgorithm_SSS_RSASSA_PKCS1_OEAP_SHA256:
                    km_error = (parsedKeyByteLen >= buffer_size + (2 * 32) + 2)
                                   ? KM_ERROR_OK
                                   : KM_ERROR_INVALID_INPUT_LENGTH;
                    break;
                case kAlgorithm_SSS_RSASSA_PKCS1_OEAP_SHA384:
                    km_error = (parsedKeyByteLen >= buffer_size + (2 * 48) + 2)
                                   ? KM_ERROR_OK
                                   : KM_ERROR_INVALID_INPUT_LENGTH;
                    break;
                case kAlgorithm_SSS_RSASSA_PKCS1_OEAP_SHA512:
                    km_error = (parsedKeyByteLen >= buffer_size + (2 * 64) + 2)
                                   ? KM_ERROR_OK
                                   : KM_ERROR_INVALID_INPUT_LENGTH;
                    break;
                default:
                    km_error = KM_ERROR_OK;
                    break;
                }
                if (km_error != KM_ERROR_OK)
                    goto cleanup;

                digestLen = buffer_size;
            }
            // ALOGI("data_length = %zu", digestLen);
            /*for (i = 0; i < digestLen; i++)
                ALOGI("data[%d] = %d", i, data[i]);*/

            status = sss_asymmetric_encrypt(&asymmCtx->asymm_ctx, &data[0], digestLen, signature1,
                                            signaturelen);
            ALOGD("sss_asymmetric_encrypt :0x%x", status);
            if (kStatus_SSS_Success != status) {
                km_error = KM_ERROR_OPERATION_CANCELLED;
                goto cleanup;
            }
        }
        break;

    case kMode_SSS_Decrypt:
        if (asymmCtx->asymm_ctx.keyObject) {
            status = sss_asymmetric_decrypt(&asymmCtx->asymm_ctx, &data[0], buffer_size, signature1,
                                            signaturelen);
            ALOGD("sss_asymmetric_decrypt :0x%x", status);
            if (kStatus_SSS_Success != status) {
                km_error = KM_ERROR_UNKNOWN_ERROR;
                goto cleanup;
            }
        }
        break;

    default:
        ALOGE("Unsupported  Purpose");
        km_error = KM_ERROR_UNSUPPORTED_PURPOSE;
        goto cleanup;
        break;
    }
    km_error = KM_ERROR_OK;

cleanup:
    free(operation->op_handle.op_asymm.asymm_ctx.keyObject);
    sss_asymmetric_context_free(&operation->op_handle.op_asymm.asymm_ctx);
    free(operation);
    if (rsaN) {
        free(rsaN);  // As we are allocating  memory for modulas in sss layer free the memory after
                     // use*/
    }
    return km_error;
}

static bool checkDigestAuthorization(const AuthorizationSet* params,
                                     const keymaster_digest_t km_digest) {
    bool exists = false;
    size_t params_size = params->size();
    const keymaster_key_param_t* key_params = params->begin();
    for (size_t i = 0; i < params_size; i++) {
        if ((key_params[i].tag == TAG_DIGEST) && (key_params[i].enumerated == km_digest)) {
            exists = true;
            break;
        }
    }

    return exists;
}

keymaster_error_t Se050KeymasterUtils::GenerateAttestation(const KeymasterKeyBlob* key_object,
                                                           const AuthorizationSet& attest_params,
                                                           const AuthorizationSet& request,
                                                           const AuthorizationSet& tee_enforced,
                                                           keymaster_cert_chain_t* cert_chain) {

    ALOGI("%s function called", __func__);
    sss_status_t status;
    sss_object_t* p_keyObject = nullptr;
    sss_key_part_t KeyType;
    sss_cipher_type_t cipherType = kSSS_CipherType_NONE;
    uint8_t key[550];
    size_t keybytelen = sizeof(key);
    size_t keybitlen = sizeof(key) * 8;
    keymaster_blob_t attestation_challenge = {};
    keymaster_algorithm_t sign_algorithm;

    if (!attest_params.GetTagValue(TAG_ALGORITHM, &sign_algorithm) &&
        !tee_enforced.GetTagValue(TAG_ALGORITHM, &sign_algorithm) &&
        !request.GetTagValue(TAG_ALGORITHM, &sign_algorithm)) {
        ALOGE("unable to find algorithm");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if ((sign_algorithm != KM_ALGORITHM_RSA) && (sign_algorithm != KM_ALGORITHM_EC)) {
        ALOGE("Incompatible algorithm for Attestation");
        return KM_ERROR_INCOMPATIBLE_ALGORITHM;
    }

    p_keyObject = (sss_object_t*)key_object->key_material;
    if (!p_keyObject)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    KeyType = (sss_key_part_t)p_keyObject->objectType;
    cipherType = (sss_cipher_type_t)p_keyObject->cipherType;
    /*ALOGI("Attestaion Object ID 0x%x", p_keyObject->keyId);
    ALOGI("CipherType: %d", cipherType);*/

    keymaster_digest_t km_digest = KM_DIGEST_SHA_2_256;
    attest_params.GetTagValue(TAG_ATTESTATION_CHALLENGE, &attestation_challenge);
    size_t tag_count = 0;
    tag_count = CountTags(&attest_params, TAG_DIGEST);
    if (tag_count == 1) {
        if (!attest_params.GetTagValue(TAG_DIGEST, &km_digest)) {
            return KM_ERROR_UNKNOWN_ERROR;
        }
        if ((!checkDigestAuthorization(&tee_enforced, km_digest)) &&
            (!checkDigestAuthorization(&request, km_digest))) {
            ALOGE("Not authorized to use this digest");
            return KM_ERROR_UNSUPPORTED_DIGEST;
        }
    } else if (tag_count == 0) {
        /* Fall back on SHA256 */

        /* App may not specify any digest at the time of key creation (as in VTS)
         * Don't check key creation tags, Always fallback on SHA256.
         */
    } else {
        ALOGE("More than one digests specified in attestation params, exiting");
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }

    if (attestation_challenge.data_length == 0)
        return KM_ERROR_INVALID_INPUT_LENGTH;
    if (attestation_challenge.data_length > kMaximumAttestationChallengeLength) {
        ALOGW("%zu-byte attestation challenge; only %zu bytes allowed",
              attestation_challenge.data_length, kMaximumAttestationChallengeLength);
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }
    status = sss_key_store_get_key(&p_boot_ctx->ks, p_keyObject, key, &keybytelen, &keybitlen);
    ALOGI("sss_key_store_get_key status %x", status);
    if (status != kStatus_SSS_Success) {
        return KM_ERROR_INVALID_KEY_BLOB;
    }

    BIO* bio = BIO_new_mem_buf(key, (int)sizeof(key));
    if (bio == NULL) {
        // ALOGI("BIO_new_mem_buf failed");
        return KM_ERROR_UNKNOWN_ERROR;
    }

    EVP_PKEY* pKey = d2i_PUBKEY_bio(bio, NULL);
    if (pKey == NULL) {
        // ALOGI("d2i_PUBKEY_bio failed ");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    EVP_PKEY_Ptr pkey(pKey);

    // ALOGD("Start making certificate");

    X509_Ptr certificate(X509_new());
    if (!certificate.get())
        return TranslateLastOpenSslError();

    // ALOGD("Set version");
    if (!X509_set_version(certificate.get(), 2 /* version 3, but zero-based */))
        return TranslateLastOpenSslError();

    // ALOGD("Set serial number");
    ASN1_INTEGER_Ptr serialNumber(ASN1_INTEGER_new());
    if (!serialNumber.get() || !ASN1_INTEGER_set(serialNumber.get(), 1) ||
        !X509_set_serialNumber(certificate.get(), serialNumber.get() /* Don't release; copied */))
        return TranslateLastOpenSslError();

    // ALOGD("Set subject name");
    X509_NAME_Ptr subjectName(X509_NAME_new());
    if (!subjectName.get() ||
        !X509_NAME_add_entry_by_txt(subjectName.get(), "CN", MBSTRING_ASC,
                                    reinterpret_cast<const uint8_t*>("Android Keystore Key"),
                                    -1 /* len */, -1 /* loc */, 0 /* set */) ||
        !X509_set_subject_name(certificate.get(), subjectName.get() /* Don't release; copied */))
        return TranslateLastOpenSslError();

    // ALOGD("Set issuer name");
    if (!subjectName.get() ||
        !X509_NAME_add_entry_by_txt(subjectName.get(), "CN", MBSTRING_ASC,
                                    reinterpret_cast<const uint8_t*>("Android Keystore Key"),
                                    -1 /* len */, -1 /* loc */, 0 /* set */) ||
        !X509_set_issuer_name(certificate.get(), subjectName.get() /* Don't release; copied */))
        return TranslateLastOpenSslError();

    // ALOGD("Set time");
    ASN1_TIME_Ptr notBefore(ASN1_TIME_new());
    uint64_t activeDateTime = 0;
    // authorizations().GetTagValue(TAG_ACTIVE_DATETIME, &activeDateTime);
    request.GetTagValue(TAG_ACTIVE_DATETIME, &activeDateTime);
    if (!notBefore.get() || !ASN1_TIME_set(notBefore.get(), activeDateTime / 1000) ||
        !X509_set_notBefore(certificate.get(), notBefore.get() /* Don't release; copied */))
        return TranslateLastOpenSslError();

    ASN1_TIME_Ptr notAfter(ASN1_TIME_new());
    uint64_t usageExpireDateTime = UINT64_MAX;
    request.GetTagValue(TAG_USAGE_EXPIRE_DATETIME, &usageExpireDateTime);
    time_t notAfterTime = std::min(static_cast<uint64_t>(UINT32_MAX), usageExpireDateTime / 1000);
    if (!notAfter.get() || !ASN1_TIME_set(notAfter.get(), notAfterTime) ||
        !X509_set_notAfter(certificate.get(), notAfter.get() /* Don't release; copied */))
        return TranslateLastOpenSslError();

    // ALOGD("Add extension");
    keymaster_error_t error = add_key_usage_extension(tee_enforced, request, certificate.get());
    if (error != KM_ERROR_OK) {
        return error;
    }

    // ALOGD("Set public key");

    if (!add_attestation_extension(attest_params, tee_enforced, request, certificate.get(), &error))
        return error;
    if (!add_public_key(pkey.get(), certificate.get(), &error))
        return error;

    ALOGD("Set public key done");
    uint8_t root_ca_cert[4096] = {0};
    size_t root_ca_cert_size = sizeof(root_ca_cert);
    sss_object_t root_ca_obj;
    uint32_t keyId = 0;
    if (sign_algorithm == KM_ALGORITHM_EC) {
        keyId = ATTESTATION_CERTIFICATE_ECC_KEYID;
    } else {
        keyId = ATTESTATION_CERTIFICATE_RSA_KEYID;
    }
    status = sss_key_object_init(&root_ca_obj, &p_boot_ctx->ks);
    ALOGE("sss_key_object_init attestation cert :0x%08X", status);
    if (status != kStatus_SSS_Success) {
        ALOGE("sss_key_object_init attestation cert failed");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    status = sss_key_object_get_handle(&root_ca_obj, keyId);
    ALOGE("sss_key_object_get_handle attestation cert :0x%08X", status);
    if (status != kStatus_SSS_Success) {
        ALOGE("sss_key_object_get_handle attestation cert failed");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    status = sss_key_store_get_key(&p_boot_ctx->ks, &root_ca_obj, root_ca_cert, &root_ca_cert_size,
                                   &keybitlen);
    ALOGE("sss_key_store_get_key attestation cert :0x%08X", status);
    if (status != kStatus_SSS_Success) {
        ALOGE("sss_key_store_get_key attestation cert failed");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if (!copy_attestation_chain(sign_algorithm, root_ca_cert, root_ca_cert_size, cert_chain,
                                &error))
        return error;

    // ALOGD("copy_attestation_chain Done");

    // ALOGD("cert_chain->entry_count = %zu", cert_chain->entry_count);
    // Copy subject key identifier from cert_chain->entries[1] as authority key_id.
    if (cert_chain->entry_count < 2) {
        // ALOGD("Entry count < 2");
        // cert_chain must have at least two entries, one for the cert we're trying to create and
        // one for the cert for the key that signs the new cert.
        return KM_ERROR_UNKNOWN_ERROR;
    }

    const uint8_t* p = cert_chain->entries[1].data;
    // ALOGD("Random Log");
    X509_Ptr signing_cert(d2i_X509(nullptr, &p, cert_chain->entries[1].data_length));
    if (!signing_cert.get()) {
        return TranslateLastOpenSslError();
    }
    // ALOGD("signing_cert created");

    // Set issuer to subject of batch certificate.
    X509_NAME* issuerSubject = X509_get_subject_name(signing_cert.get());
    if (!issuerSubject) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if (!X509_set_issuer_name(certificate.get(), issuerSubject)) {
        return TranslateLastOpenSslError();
    }

    /* NXP Certificate chains do not have Subject Public Key Info.
     *
     * authorityKeyIdentifier=authoritykeyidentifier
     *  specifies how to identify the public key being used to verify
     *  the signature on this certificate, and enables keys used by the
     *  same CA to be distinguished, where authoritykeyidentifier is
     *  one of the following:
     *
     *  keyid
     *      indicates that the subject key identifier is copied from the parent certificate.
     *  keyid:always
     *      indicates that the subject key identifier is copied from the parent certificate
     *      and an error is returned if the copy fails.
     *  issuer
     *      indicates that the issuer and serial number is copied from the issuer certificate
     *      if the keyid option fails or is not specified.
     *  issuer:always
     *      indicates that the issuer and serial number is always copied from the issuer
     *      certificate.
     *
     * We can skip adding authorityKeyIdentifier
     */

    // UniquePtr<X509V3_CTX> x509v3_ctx(new (std::nothrow) X509V3_CTX);
    // if (!x509v3_ctx.get())
    //     return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    // *x509v3_ctx = {};
    // X509V3_set_ctx(x509v3_ctx.get(), signing_cert.get(), certificate.get(), nullptr /* req */,
    //                nullptr /* crl */, 0 /* flags */);

    // X509_EXTENSION_Ptr auth_key_id(X509V3_EXT_nconf_nid(nullptr /* conf */, x509v3_ctx.get(),
    //                                                     NID_authority_key_identifier,
    //                                                     const_cast<char*>("keyid:always")));
    // if (!auth_key_id.get() ||
    //     !X509_add_ext(certificate.get(), auth_key_id.get() /* Don't release; copied */,
    //                   -1 /* insert at end */)) {
    //     return TranslateLastOpenSslError();
    // }

    status = key_attestation_sign_csr(certificate.get(), sign_algorithm, km_digest);
    if (status != kStatus_SSS_Success) {
        ALOGE("Failed to sign csr");
        return KM_ERROR_UNKNOWN_ERROR;
    }

    return get_certificate_blob(certificate.get(), &cert_chain->entries[0]);
}

sss_status_t Se050KeymasterUtils::key_attestation_sign_csr(X509* certificate,
                                                           keymaster_algorithm_t sign_algorithm,
                                                           const keymaster_digest_t km_digest) {
    sss_status_t status = kStatus_SSS_Fail;
    sss_algorithm_t algorithm = kAlgorithm_None;
    sss_object_t obj;
    sss_algorithm_t sss_digest_algo = kAlgorithm_None;
    uint8_t tbs_bytes[2000];
    uint8_t* p_tbs_bytes = &tbs_bytes[0];
    int len = 0;
    int type = 0;
    uint32_t keyId = 0;
    size_t i = 0;
    if (sign_algorithm == KM_ALGORITHM_RSA) {
        algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
        type = NID_sha256WithRSAEncryption;
        keyId = ATTESTATION_KEY_RSA_KEYID;

        switch (km_digest) {
        case KM_DIGEST_SHA1:
            algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1;
            type = NID_sha1WithRSAEncryption;
            break;
        case KM_DIGEST_SHA_2_224:
            algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224;
            type = NID_sha224WithRSAEncryption;
            break;
        case KM_DIGEST_SHA_2_256:
            algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
            type = NID_sha256WithRSAEncryption;
            break;
        case KM_DIGEST_SHA_2_384:
            algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384;
            type = NID_sha384WithRSAEncryption;
            break;
        case KM_DIGEST_SHA_2_512:
            algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512;
            type = NID_sha512WithRSAEncryption;
            break;
        default:
            ALOGE("Invalid digest algorithm");
            return kStatus_SSS_Fail;
        }

    } else {
        algorithm = kAlgorithm_SSS_ECDSA_SHA256;
        type = NID_ecdsa_with_SHA256;
        keyId = ATTESTATION_KEY_ECC_KEYID;
        switch (km_digest) {
        case KM_DIGEST_SHA1:
            algorithm = kAlgorithm_SSS_ECDSA_SHA1;
            type = NID_ecdsa_with_SHA1;
            break;
        case KM_DIGEST_SHA_2_224:
            algorithm = kAlgorithm_SSS_ECDSA_SHA224;
            type = NID_ecdsa_with_SHA224;
            break;
        case KM_DIGEST_SHA_2_256:
            algorithm = kAlgorithm_SSS_ECDSA_SHA256;
            type = NID_ecdsa_with_SHA256;
            break;
        case KM_DIGEST_SHA_2_384:
            algorithm = kAlgorithm_SSS_ECDSA_SHA384;
            type = NID_ecdsa_with_SHA384;
            break;
        case KM_DIGEST_SHA_2_512:
            algorithm = kAlgorithm_SSS_ECDSA_SHA512;
            type = NID_ecdsa_with_SHA512;
            break;
        default:
            ALOGE("Invalid digest algorithm");
            return kStatus_SSS_Fail;
        }
    }

    X509_ALGOR* tbs_algo = certificate->cert_info->signature;
    X509_ALGOR* algo1 = certificate->sig_alg;
    X509_ALGOR_set0(algo1, OBJ_nid2obj(type), V_ASN1_NULL, NULL);
    X509_ALGOR_set0(tbs_algo, OBJ_nid2obj(type), V_ASN1_NULL, NULL);

    X509_CINF* cinf = certificate->cert_info;
    len = i2d_X509_CINF(cinf, &p_tbs_bytes);

    /*Calculate digest for signing*/
    uint8_t digest[32] = {0};
    size_t digestLen = sizeof(digest);
    sss_digest_t digestCtx;
    GetSSSAlgorithm(algorithm, &sss_digest_algo);
#if SSS_HAVE_HOSTCRYPTO_ANY
    status = sss_digest_context_init(&digestCtx, &p_boot_ctx->host_session, sss_digest_algo,
                                     kMode_SSS_Digest);
#else
    status = kStatus_SSS_Fail;
#endif
    if (status != kStatus_SSS_Success) {
        ALOGE("sss_digest_context_init failed");
        return status;
    }

    status = sss_digest_init(&digestCtx);
    if (status != kStatus_SSS_Success) {
        ALOGE("sss_digest_init failed");
        return kStatus_SSS_Fail;
    }
    while (len > 500) {
        status = sss_digest_update(&digestCtx, &tbs_bytes[0 + i * 500], 500);
        if (status != kStatus_SSS_Success) {
            ALOGE("sss_digest_update failed; iteration=%zu", i);
            sss_digest_context_free(&digestCtx);
            return status;
        }
        i++;
        len = len - 500;
    }
    status = sss_digest_update(&digestCtx, &tbs_bytes[0 + i * 500], len);
    if (status != kStatus_SSS_Success) {
        ALOGE("sss_digest_update failed");
        sss_digest_context_free(&digestCtx);
        return status;
    }
    status = sss_digest_finish(&digestCtx, digest, &digestLen);
    sss_digest_context_free(&digestCtx);
    if (status != kStatus_SSS_Success) {
        ALOGE("sss_digest_finish failed");
        return kStatus_SSS_Fail;
    }

    /*Sign digest*/
    status = sss_key_object_init(&obj, &p_boot_ctx->ks);
    if (status != kStatus_SSS_Success) {
        ALOGE("sss_key_object_init failed");
        return status;
    }
    status = sss_key_object_get_handle(&obj, keyId);
    if (status != kStatus_SSS_Success) {
        ALOGE("sss_key_object_get_handle failed");
        return status;
    }
    sss_asymmetric_t asymmCtx;
    uint8_t signature[512];
    uint8_t* p_signature = &signature[0];
    size_t signatureLen = sizeof(signature);
    status = sss_asymmetric_context_init(&asymmCtx, &p_boot_ctx->session, &obj, algorithm,
                                         kMode_SSS_Sign);
    if (status != kStatus_SSS_Success) {
        ALOGE("sss_asymmetric_context_init failed");
        return status;
    }
    status = sss_asymmetric_sign_digest(&asymmCtx, digest, digestLen, signature, &signatureLen);
    if (status != kStatus_SSS_Success) {
        ALOGE("sss_asymmetric_sign_digest failed");
        return status;
    }

    /*Add signature to certificate structure*/
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    ASN1_BIT_STRING* sig = certificate->signature;
#else
    ASN1_BIT_STRING* sig;
    const X509_ALGOR* tmp_algo = NULL;
    X509_get0_signature((const ASN1_BIT_STRING**)&sig, &tmp_algo, (const X509*)certificate);
    X509_ALGOR* algo = (X509_ALGOR*)tmp_algo;
    X509_ALGOR_set0(algo, OBJ_nid2obj(type), V_ASN1_NULL, NULL);
#endif
    len = ASN1_BIT_STRING_set(sig, p_signature, signatureLen);

    BIO* bio = BIO_new(BIO_s_mem());

    int rc = PEM_write_bio_X509(bio, certificate);

    if (rc != 1) {
        ALOGE("PEM_write_bio_X509 failed");
        BIO_free(bio);
        return kStatus_SSS_Fail;
    }

    BUF_MEM* mem = NULL;
    BIO_get_mem_ptr(bio, &mem);

    if (!mem || !mem->data || !mem->length) {
        ALOGE("BIO_get_mem_ptr failed");
        BIO_free(bio);
        return kStatus_SSS_Fail;
    }

    BIO* certBio = BIO_new(BIO_s_mem());
    BIO_write(certBio, mem->data, mem->length);
    certificate = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
    if (!certificate) {
        ALOGE("unable to parse certificate in memory");
        BIO_free(certBio);
        BIO_free(bio);
        return kStatus_SSS_Fail;
    }

    BIO_free(certBio);
    BIO_free(bio);

    return status;
}

}  // namespace keymaster
