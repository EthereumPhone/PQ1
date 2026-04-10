/*
 * Copyright 2015 The Android Open Source Project
 * Copyright 2019,2020 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <keymaster/se050_keymaster_device.h>
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

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <hardware/keymaster1.h>
#define LOG_TAG "NXPKeymasterDevice"
#include <cutils/log.h>

#include <keymaster/android_keymaster.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/android_keymaster_utils.h>
#include <keymaster/authorization_set.h>
#include <keymaster/soft_keymaster_context.h>
#include <keymaster/soft_keymaster_logger.h>
#include <openssl/evp.h>

#include "openssl_utils.h"

#include "openssl_err.h"
#include <rsa_key.h>

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#define TEST_ROOT_FOLDER "/data/vendor/SE05X"
#endif

#if SSS_HAVE_APPLET_SE05X_IOT
#include <se05x_APDU.h>
#endif

#define I2C_DEV_ADDR "/dev/i2c-0:0x48"

/*
#if SSS_HAVE_APPLET_SE05X_IOT
#include "Applet_SE050_Ver.h"
#include "SE05x_MW_Ver.h"
#endif
*/
struct keystore_module se050_keymaster1_device_module = {
    .common =
        {
            .tag = HARDWARE_MODULE_TAG,
            .module_api_version = KEYMASTER_MODULE_API_VERSION_1_0,
            .hal_api_version = HARDWARE_HAL_API_VERSION,
            .id = KEYSTORE_HARDWARE_MODULE_ID,
            .name = "SE050-based Keymaster HAL",
            .author = "The Android Open Source Project",
            .methods = nullptr,
            .dso = 0,
            .reserved = {},
        },
};

struct keystore_module se050_keymaster2_device_module = {
    .common =
        {
            .tag = HARDWARE_MODULE_TAG,
            .module_api_version = KEYMASTER_MODULE_API_VERSION_2_0,
            .hal_api_version = HARDWARE_HAL_API_VERSION,
            .id = KEYSTORE_HARDWARE_MODULE_ID,
            .name = "SE050-based Keymaster HAL",
            .author = "The Android Open Source Project",
            .methods = nullptr,
            .dso = 0,
            .reserved = {},
        },
};

namespace keymaster {

// ex_sss_boot_ctx_t Se050KeymasterDevice::sss_ex_ctx;
// sss_rng_context_t Se050KeymasterDevice::sss_rng_ctx;
Se050KeymasterUtils* Se050KeymasterDevice::utils_;
const size_t kOperationTableSize = 16;

template <typename T> std::vector<T> make_vector(const T* array, size_t len) {
    return std::vector<T>(array, array + len);
}

// This helper class implements just enough of the C++ standard collection interface to be able to
// accept push_back calls, and it does nothing but count them.  It's useful when you want to count
// insertions but not actually store anything.  It's used in digest_set_is_full below to count the
// size of a set intersection.
struct PushbackCounter {
    struct value_type {
        template <typename T> value_type(const T&) {}
    };
    void push_back(const value_type&) { ++count; }
    size_t count = 0;
};

static std::vector<keymaster_digest_t> full_digest_list = {
    KM_DIGEST_MD5,       KM_DIGEST_SHA1,      KM_DIGEST_SHA_2_224,
    KM_DIGEST_SHA_2_256, KM_DIGEST_SHA_2_384, KM_DIGEST_SHA_2_512};
template <typename Iter> static bool digest_set_is_full(Iter begin, Iter end) {
    PushbackCounter counter;
    std::set_intersection(begin, end, full_digest_list.begin(), full_digest_list.end(),
                          std::back_inserter(counter));
    return counter.count == full_digest_list.size();
}

static keymaster_error_t add_digests(keymaster1_device_t* dev, keymaster_algorithm_t algorithm,
                                     keymaster_purpose_t purpose,
                                     Se050KeymasterDevice::DigestMap* map, bool* supports_all) {
    auto key = std::make_pair(algorithm, purpose);

    keymaster_digest_t* digests;
    size_t digests_length;
    keymaster_error_t error =
        dev->get_supported_digests(dev, algorithm, purpose, &digests, &digests_length);
    if (error != KM_ERROR_OK) {
        LOG_E("Error %d getting supported digests from keymaster1 device", error);
        return error;
    }
    std::unique_ptr<keymaster_digest_t, Malloc_Delete> digests_deleter(digests);

    auto digest_vec = make_vector(digests, digests_length);
    *supports_all = digest_set_is_full(digest_vec.begin(), digest_vec.end());
    (*map)[key] = std::move(digest_vec);
    return error;
}

static keymaster_error_t map_digests(keymaster1_device_t* dev, Se050KeymasterDevice::DigestMap* map,
                                     bool* supports_all) {
    map->clear();
    *supports_all = true;

    keymaster_algorithm_t sig_algorithms[] = {KM_ALGORITHM_RSA, KM_ALGORITHM_EC, KM_ALGORITHM_HMAC};
    keymaster_purpose_t sig_purposes[] = {KM_PURPOSE_SIGN, KM_PURPOSE_VERIFY};
    for (auto algorithm : sig_algorithms)
        for (auto purpose : sig_purposes) {
            bool alg_purpose_supports_all;
            keymaster_error_t error =
                add_digests(dev, algorithm, purpose, map, &alg_purpose_supports_all);
            if (error != KM_ERROR_OK)
                return error;
            *supports_all &= alg_purpose_supports_all;
        }

    keymaster_algorithm_t crypt_algorithms[] = {KM_ALGORITHM_RSA};
    keymaster_purpose_t crypt_purposes[] = {KM_PURPOSE_ENCRYPT, KM_PURPOSE_DECRYPT};
    for (auto algorithm : crypt_algorithms)
        for (auto purpose : crypt_purposes) {
            bool alg_purpose_supports_all;
            keymaster_error_t error =
                add_digests(dev, algorithm, purpose, map, &alg_purpose_supports_all);
            if (error != KM_ERROR_OK)
                return error;
            *supports_all &= alg_purpose_supports_all;
        }

    return KM_ERROR_OK;
}

/*Function to parse ECC keypair and verify that
 * the key and authorization tags match*/
static keymaster_error_t UpdateEccImportKeyDescription(keymaster_key_format_t key_format,
                                                       const keymaster_blob_t* key_data,
                                                       const AuthorizationSet& params,
                                                       AuthorizationSet* updated_params,
                                                       uint32_t* key_size) {
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey;
    keymaster_key_blob_t CheckBlob = {key_data->data, key_data->data_length};
    KeymasterKeyBlob key_material = (KeymasterKeyBlob)CheckBlob;
    keymaster_error_t error = KeyMaterialToEvpKey(key_format, key_material, KM_ALGORITHM_EC, &pkey);
    if (error != KM_ERROR_OK)
        return error;

    UniquePtr<EC_KEY, EC_KEY_Delete> ec_key(EVP_PKEY_get1_EC_KEY(pkey.get()));
    if (!ec_key.get())
        return TranslateLastOpenSslError();

    size_t extracted_key_size_bits;
    error = ec_get_group_size(EC_KEY_get0_group(ec_key.get()), &extracted_key_size_bits);
    if (error != KM_ERROR_OK)
        return error;

    error = parse_ec_param_set(params, updated_params);
    if (error != KM_ERROR_OK) {
        // ALOGE("Parse ecc key: Param set failed");
        return error;
    }

    // uint32_t key_size;
    if (!updated_params->GetTagValue(TAG_KEY_SIZE, key_size))
        return KM_ERROR_INVALID_ARGUMENT;

    if (extracted_key_size_bits != *key_size)
        return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
    // ALOGI("parsed_ec_size is : %zu", extracted_key_size_bits);
    return KM_ERROR_OK;
}

/*Function to parse RSA keypair and verify that
 * the key and authorization tags match*/
static keymaster_error_t UpdateRsaImportKeyDescription(const AuthorizationSet& key_description,
                                                       keymaster_key_format_t key_format,
                                                       const KeymasterKeyBlob& key_material,
                                                       AuthorizationSet* updated_description,
                                                       uint64_t* public_exponent,
                                                       uint32_t* key_size) {
    if (!updated_description || !public_exponent || !key_size)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey;
    keymaster_error_t error =
        KeyMaterialToEvpKey(key_format, key_material, KM_ALGORITHM_RSA, &pkey);
    if (error != KM_ERROR_OK)
        return error;

    UniquePtr<RSA, RsaKey::RSA_Delete> rsa_key(EVP_PKEY_get1_RSA(pkey.get()));
    if (!rsa_key.get())
        return TranslateLastOpenSslError();

    updated_description->Reinitialize(key_description);

    *public_exponent = BN_get_word(rsa_key->e);
    if (*public_exponent == 0xffffffffL)
        return KM_ERROR_INVALID_KEY_BLOB;
    if (!updated_description->GetTagValue(TAG_RSA_PUBLIC_EXPONENT, public_exponent))
        updated_description->push_back(TAG_RSA_PUBLIC_EXPONENT, *public_exponent);
    if (*public_exponent != BN_get_word(rsa_key->e)) {
        LOG_E("Imported public exponent (%u) does not match specified public exponent (%u)",
              *public_exponent, BN_get_word(rsa_key->e));
        return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
    }

    *key_size = RSA_size(rsa_key.get()) * 8;
    if (!updated_description->GetTagValue(TAG_KEY_SIZE, key_size))
        updated_description->push_back(TAG_KEY_SIZE, *key_size);
    if (RSA_size(rsa_key.get()) * 8 != *key_size) {
        LOG_E("Imported key size (%u bits) does not match specified key size (%u bits)",
              RSA_size(rsa_key.get()) * 8, *key_size);
        return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
    }

    keymaster_algorithm_t algorithm = KM_ALGORITHM_RSA;
    if (!updated_description->GetTagValue(TAG_ALGORITHM, &algorithm))
        updated_description->push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
    if (algorithm != KM_ALGORITHM_RSA)
        return KM_ERROR_IMPORT_PARAMETER_MISMATCH;

    return KM_ERROR_OK;
}

Se050KeymasterDevice::~Se050KeymasterDevice() {
    sss_rng_context_free(&sss_rng_ctx);
    ex_sss_session_close(&sss_ex_ctx);
    if (utils_) {
        delete utils_;
        ALOGI("utils deleted");
    }
    ALOGI("session closed");
}

Se050KeymasterDevice::Se050KeymasterDevice()
    : wrapped_km0_device_(nullptr), wrapped_km1_device_(nullptr),
      context_(new SoftKeymasterContext),
      impl_(new AndroidKeymaster(context_, kOperationTableSize)), configured_(false) {
    LOG_I("Creating device", 0);
    LOG_D("Device address: %p", this);
    initialize_device_struct(KEYMASTER_BLOBS_ARE_STANDALONE | KEYMASTER_SUPPORTS_EC);
}

Se050KeymasterDevice::Se050KeymasterDevice(SoftKeymasterContext* context)
    : wrapped_km0_device_(nullptr), wrapped_km1_device_(nullptr), context_(context),
      impl_(new AndroidKeymaster(context_, kOperationTableSize)), configured_(false) {
    LOG_I("Creating test device", 0);
    LOG_D("Device address: %p", this);
    initialize_device_struct(KEYMASTER_BLOBS_ARE_STANDALONE | KEYMASTER_SUPPORTS_EC);
}

keymaster_error_t Se050KeymasterDevice::SetHardwareDevice(keymaster0_device_t* keymaster0_device) {
    ENSURE_OR_GO_EXIT(keymaster0_device);
    LOG_D("Reinitializing Se050KeymasterDevice to use HW keymaster0", 0);

    if (!context_)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    supports_all_digests_ = false;
    /*keymaster_error_t error = context_->SetHardwareDevice(keymaster0_device);
    if (error != KM_ERROR_OK)
       return error;
    */
    initialize_device_struct(keymaster0_device->flags);

    module_name_ = km1_device_.common.module->name;
    module_name_.append("(Wrapping ");
    module_name_.append(keymaster0_device->common.module->name);
    module_name_.append(")");

    updated_module_ = *km1_device_.common.module;
    updated_module_.name = module_name_.c_str();

    km1_device_.common.module = &updated_module_;

    wrapped_km0_device_ = keymaster0_device;
    wrapped_km1_device_ = nullptr;
    return KM_ERROR_OK;

exit:
    return KM_ERROR_UNEXPECTED_NULL_POINTER;
}

keymaster_error_t Se050KeymasterDevice::SetHardwareDevice(keymaster1_device_t* keymaster1_device) {
    if (!keymaster1_device)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    LOG_D("Reinitializing Se050KeymasterDevice to use HW keymaster1", 0);

    if (!context_)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    keymaster_error_t error =
        map_digests(keymaster1_device, &km1_device_digests_, &supports_all_digests_);
    if (error != KM_ERROR_OK)
        return error;

    /*error = context_->SetHardwareDevice(keymaster1_device);
    if (error != KM_ERROR_OK)
        return error;
    */
    initialize_device_struct(keymaster1_device->flags);

    module_name_ = km1_device_.common.module->name;
    module_name_.append(" (Wrapping ");
    module_name_.append(keymaster1_device->common.module->name);
    module_name_.append(")");

    updated_module_ = *km1_device_.common.module;
    updated_module_.name = module_name_.c_str();

    km1_device_.common.module = &updated_module_;

    wrapped_km0_device_ = nullptr;
    wrapped_km1_device_ = keymaster1_device;
    return KM_ERROR_OK;
}

bool Se050KeymasterDevice::Keymaster1DeviceIsGood() {
    ALOGI(" inside Keymaster1DeviceIsGood");
    std::vector<keymaster_digest_t> expected_rsa_digests = {
        KM_DIGEST_NONE,      KM_DIGEST_MD5,       KM_DIGEST_SHA1,     KM_DIGEST_SHA_2_224,
        KM_DIGEST_SHA_2_256, KM_DIGEST_SHA_2_384, KM_DIGEST_SHA_2_512};
    std::vector<keymaster_digest_t> expected_ec_digests = {
        KM_DIGEST_NONE,      KM_DIGEST_SHA1,      KM_DIGEST_SHA_2_224,
        KM_DIGEST_SHA_2_256, KM_DIGEST_SHA_2_384, KM_DIGEST_SHA_2_512};

    for (auto& entry : km1_device_digests_) {
        if (entry.first.first == KM_ALGORITHM_RSA)
            if (!std::is_permutation(entry.second.begin(), entry.second.end(),
                                     expected_rsa_digests.begin()))
                return false;
        if (entry.first.first == KM_ALGORITHM_EC)
            if (!std::is_permutation(entry.second.begin(), entry.second.end(),
                                     expected_ec_digests.begin()))
                return false;
    }
    return true;
}

void Se050KeymasterDevice::initialize_device_struct(uint32_t flags) {
    memset(&km1_device_, 0, sizeof(km1_device_));

    km1_device_.common.tag = HARDWARE_DEVICE_TAG;
    km1_device_.common.version = 1;
    km1_device_.common.module = reinterpret_cast<hw_module_t*>(&se050_keymaster1_device_module);
    km1_device_.common.close = &close_device;

    km1_device_.flags = flags;

    km1_device_.context = this;

    // keymaster0 APIs
    km1_device_.generate_keypair = nullptr;
    km1_device_.import_keypair = nullptr;
    km1_device_.get_keypair_public = nullptr;
    km1_device_.delete_keypair = nullptr;
    km1_device_.delete_all = nullptr;
    km1_device_.sign_data = nullptr;
    km1_device_.verify_data = nullptr;

    // keymaster2 APIs
    memset(&km2_device_, 0, sizeof(km2_device_));

    km2_device_.flags = flags;
    km2_device_.context = this;

    km2_device_.common.tag = HARDWARE_DEVICE_TAG;
    km2_device_.common.version = 1;
    km2_device_.common.module = reinterpret_cast<hw_module_t*>(&se050_keymaster2_device_module);
    km2_device_.common.close = &close_device;

    km2_device_.configure = configure;
    km2_device_.add_rng_entropy = add_rng_entropy;
    km2_device_.generate_key = generate_key;
    km2_device_.get_key_characteristics = get_key_characteristics;
    km2_device_.import_key = import_key;
    km2_device_.export_key = export_key;
    km2_device_.attest_key = attest_key;
    km2_device_.upgrade_key = upgrade_key;
    km2_device_.delete_key = delete_key;
    km2_device_.delete_all_keys = delete_all_keys;
    km2_device_.begin = begin;
    km2_device_.update = update;
    km2_device_.finish = finish;
    km2_device_.abort = abort;
    sss_status_t status;
#if SSS_HAVE_APPLET_SE05X_IOT
    ALOGI("CONNECT TO SE05x:");
    // ALOGI("   HostLib Version: " SE05X_MW_PROD_NAME_VER_FULL);
    // ALOGI("   Compiled for Applet Version: " APPLET_SE050_PROD_NAME_VER_FULL);
    // ALOGI("   Compiled on: %s %s",__DATE__, __TIME__);
    // memset(&sss_ex_ctx, 0, sizeof(sss_ex_ctx));
    status = ex_sss_boot_open(&sss_ex_ctx, I2C_DEV_ADDR);
    ALOGD("SE05X ex_sss_boot_open 0x%08x", status);
    ENSURE_OR_RETURN(status == kStatus_SSS_Success);
    status = ex_sss_key_store_and_object_init(&sss_ex_ctx);
    ALOGD("SE05X ex_sss_key_store_and_object_init 0x%08x", status);
    ENSURE_OR_RETURN(status == kStatus_SSS_Success);
    status = sss_rng_context_init(&sss_rng_ctx, &sss_ex_ctx.session /* Session */);
    ALOGD("sss_rng_context_init status  :0x%x", status);
    ENSURE_OR_RETURN(status == kStatus_SSS_Success);
    utils_ = new Se050KeymasterUtils(&sss_ex_ctx, &sss_rng_ctx);
#endif
#if SSS_HAVE_HOSTCRYPTO_ANY
    status = ex_sss_boot_open_host_session(&sss_ex_ctx);
    ALOGD("Host ex_sss_boot_open 0x%08x", status);
    if (kStatus_SSS_Success != status) {
        ALOGD("Host session is already open");
    }
#endif

}  // namespace keymaster

keymaster_error_t CheckVersionInfo(const AuthorizationSet& tee_enforced,
                                   const AuthorizationSet& sw_enforced,
                                   const SoftKeymasterContext& context) {
    uint32_t os_version;
    uint32_t os_patchlevel;
    context.GetSystemVersion(&os_version, &os_patchlevel);

    uint32_t key_os_patchlevel;
    if (tee_enforced.GetTagValue(TAG_OS_PATCHLEVEL, &key_os_patchlevel) ||
        sw_enforced.GetTagValue(TAG_OS_PATCHLEVEL, &key_os_patchlevel)) {
        ALOGD("key_os_patchlevel = %d", key_os_patchlevel);
        ALOGD("os_patchlevel = %d", os_patchlevel);
        if (key_os_patchlevel < os_patchlevel)
            return KM_ERROR_KEY_REQUIRES_UPGRADE;
        else if (key_os_patchlevel > os_patchlevel)
            return KM_ERROR_INVALID_KEY_BLOB;
    }

    return KM_ERROR_OK;
}

hw_device_t* Se050KeymasterDevice::hw_device() {
    return &km1_device_.common;
}

keymaster1_device_t* Se050KeymasterDevice::keymaster_device() {
    return &km1_device_;
}

keymaster2_device_t* Se050KeymasterDevice::keymaster2_device() {
    return &km2_device_;
}

namespace {
/*
keymaster_key_characteristics_t* BuildCharacteristics(const AuthorizationSet& hw_enforced,
                                                      const AuthorizationSet& sw_enforced) {
    keymaster_key_characteristics_t* characteristics =
        reinterpret_cast<keymaster_key_characteristics_t*>(
            malloc(sizeof(keymaster_key_characteristics_t)));
    if (characteristics) {
        hw_enforced.CopyToParamSet(&characteristics->hw_enforced);
        sw_enforced.CopyToParamSet(&characteristics->sw_enforced);
    }
    return characteristics;
}
*/
template <typename RequestType>
void AddClientAndAppData(const keymaster_blob_t* client_id, const keymaster_blob_t* app_data,
                         RequestType* request) {
    request->additional_params.Clear();
    if (client_id)
        request->additional_params.push_back(TAG_APPLICATION_ID, *client_id);
    if (app_data)
        request->additional_params.push_back(TAG_APPLICATION_DATA, *app_data);
}

template <typename T> Se050KeymasterDevice* convert_device(const T* dev) {
    static_assert((std::is_same<T, keymaster0_device_t>::value ||
                   std::is_same<T, keymaster1_device_t>::value ||
                   std::is_same<T, keymaster2_device_t>::value),
                  "convert_device should only be applied to keymaster devices");
    return reinterpret_cast<Se050KeymasterDevice*>(dev->context);
}

template <keymaster_tag_t Tag, keymaster_tag_type_t Type, typename KeymasterEnum>
bool FindTagValue(const keymaster_key_param_set_t& params,
                  TypedEnumTag<Type, Tag, KeymasterEnum> tag, KeymasterEnum* value) {
    for (size_t i = 0; i < params.length; ++i)
        if (params.params[i].tag == tag) {
            *value = static_cast<KeymasterEnum>(params.params[i].enumerated);
            return true;
        }
    return false;
}

}  // namespace

/* static */
int Se050KeymasterDevice::close_device(hw_device_t* dev) {
    ALOGI("CLOSE SESSION");
    delete convert_device(reinterpret_cast<keymaster2_device_t*>(dev));
    return 0;
}

/* static */
keymaster_error_t Se050KeymasterDevice::configure(const keymaster2_device_t* dev,
                                                  const keymaster_key_param_set_t* params) {
    AuthorizationSet params_copy(*params);
    ConfigureRequest request;
    if (!params_copy.GetTagValue(TAG_OS_VERSION, &request.os_version) ||
        !params_copy.GetTagValue(TAG_OS_PATCHLEVEL, &request.os_patchlevel)) {
        LOG_E("Configuration parameters must contain OS version and patch level", 0);
        return KM_ERROR_INVALID_ARGUMENT;
    }
    ConfigureResponse response;
    convert_device(dev)->impl_->Configure(request, &response);
    if (response.error == KM_ERROR_OK)
        convert_device(dev)->configured_ = true;
    return response.error;
}

/* static */
keymaster_error_t Se050KeymasterDevice::add_rng_entropy(const keymaster2_device_t* dev,
                                                        const uint8_t* data, size_t data_length) {
    ALOGI("%s function called ", __func__);
    if (!dev) {
        ALOGE("dev is null");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (data_length > 2048) {
        ALOGE("Invalid Inpt Length");
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }

    sss_rng_context_t* p_rng_ctx = &(convert_device(dev)->sss_rng_ctx);
    sss_status_t status;
    uint8_t data1[2048] = {0};
    memcpy(&data1[0], data, data_length);
    status = sss_rng_get_random(p_rng_ctx, &data1[0], data_length);
    ALOGI("sss_rng_get_random status :0x%x", status);
    if (kStatus_SSS_Success == status)
        return KM_ERROR_OK;

    return KM_ERROR_INVALID_OPERATION_HANDLE;
}

template <typename Collection, typename Value> bool contains(const Collection& c, const Value& v) {
    return std::find(c.begin(), c.end(), v) != c.end();
}

bool Se050KeymasterDevice::FindUnsupportedDigest(keymaster_algorithm_t algorithm,
                                                 keymaster_purpose_t purpose,
                                                 const AuthorizationSet& params,
                                                 keymaster_digest_t* unsupported) const {
    if (!wrapped_km1_device_)
        return false;

    auto supported_digests = km1_device_digests_.find(std::make_pair(algorithm, purpose));
    if (supported_digests == km1_device_digests_.end())
        // Invalid algorith/purpose pair (e.g. EC encrypt).  Let the error be handled by HW module.
        return false;

    for (auto& entry : params)
        if (entry.tag == TAG_DIGEST)
            if (!contains(supported_digests->second, entry.enumerated)) {
                LOG_I("Digest %d requested but not supported by module %s", entry.enumerated,
                      wrapped_km1_device_->common.module->name);
                *unsupported = static_cast<keymaster_digest_t>(entry.enumerated);
                return true;
            }
    return false;
}

bool Se050KeymasterDevice::RequiresSoftwareDigesting(keymaster_algorithm_t algorithm,
                                                     keymaster_purpose_t purpose,
                                                     const AuthorizationSet& params) const {
    if (!wrapped_km1_device_)
        return true;

    switch (algorithm) {
    case KM_ALGORITHM_AES:
        LOG_D("Not performing software digesting for AES keys", algorithm);
        return false;
    case KM_ALGORITHM_HMAC:
    case KM_ALGORITHM_RSA:
    case KM_ALGORITHM_EC:
        break;
    }

    keymaster_digest_t unsupported;
    if (!FindUnsupportedDigest(algorithm, purpose, params, &unsupported)) {
        LOG_D("Requested digest(s) supported for algorithm %d and purpose %d", algorithm, purpose);
        return false;
    }

    return true;
}

bool Se050KeymasterDevice::KeyRequiresSoftwareDigesting(
    const AuthorizationSet& key_description) const {
    if (!wrapped_km1_device_)
        return true;

    keymaster_algorithm_t algorithm;
    if (!key_description.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        // The hardware module will return an error during keygen.
        return false;
    }

    for (auto& entry : key_description)
        if (entry.tag == TAG_PURPOSE) {
            keymaster_purpose_t purpose = static_cast<keymaster_purpose_t>(entry.enumerated);
            if (RequiresSoftwareDigesting(algorithm, purpose, key_description))
                return true;
        }

    return false;
}

keymaster_error_t
Se050KeymasterDevice::generate_key(const keymaster2_device_t* dev,  //
                                   const keymaster_key_param_set_t* params,
                                   keymaster_key_blob_t* key_blob,
                                   keymaster_key_characteristics_t* characteristics) {
    ALOGI("%s function called", __func__);
    if (!dev)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!convert_device(dev)->configured())
        return KM_ERROR_KEYMASTER_NOT_CONFIGURED;

    if (!key_blob)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    ex_sss_boot_ctx_t* p_boot_ctx = &(convert_device(dev)->sss_ex_ctx);
    sss_rng_context_t* p_rng_ctx = &(convert_device(dev)->sss_rng_ctx);

    keymaster_error_t km_error;
    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t keyObject;
    keymaster_blob_t Id = {nullptr, 0};
    AuthorizationSet hw_enforced, sw_enforced;
    AuthorizationSet org_params(*params);
    GenerateKeyRequest request;
    keymaster_algorithm_t algorithm;
    KeymasterKeyBlob key_object = {nullptr, 0};
    KeymasterKeyBlob blob;
    uint32_t key_size = 0;
    uint32_t keyId = 0;
    uint8_t rnd_keyID[3] = {0};
    sss_key_part_t KeyType = kSSS_KeyPart_NONE;
    sss_cipher_type_t cipherType = kSSS_CipherType_NONE;
    SE05x_Result_t exists = kSE05x_Result_NA;
    sss_policy_u policy_common;
    sss_policy_u policy_key;
    sss_policy_t key_policies;
    request.key_description.Reinitialize(*params);
    request.key_description.GetTagValue(TAG_ALGORITHM, &algorithm);
    policy_common.type = KPolicy_Common;

    if (algorithm == KM_ALGORITHM_HMAC) {
        policy_key.type = KPolicy_Sym_Key;
        ALOGI("alogortihm : KM_ALGORITHM_HMAC");

        if (!request.key_description.GetTagValue(TAG_KEY_SIZE, &key_size))
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;

        if (key_size % 8 != 0)
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;
        else if (key_size < 64 || key_size > 512)
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;

        uint8_t data[key_size / 8];
        status = sss_rng_get_random(p_rng_ctx, data, key_size / 8);
        if (status != kStatus_SSS_Success)
            return KM_ERROR_INVALID_OPERATION_HANDLE;

        keymaster_blob_t key_data = {data, key_size / 8};
        km_error = import_key(dev, params, KM_KEY_FORMAT_PKCS8, (const keymaster_blob_t*)&key_data,
                              key_blob, characteristics);
        for (size_t i = 0; i < characteristics->hw_enforced.length; i++) {
            if (characteristics->hw_enforced.params[i].tag == TAG_ORIGIN)
                characteristics->hw_enforced.params[i].enumerated = KM_ORIGIN_GENERATED;
        }
        return km_error;
    } else if (algorithm == KM_ALGORITHM_AES) {
        policy_key.type = KPolicy_Sym_Key;
        ALOGI("alogortihm : KM_ALGORITHM_AES ");
        if (!request.key_description.GetTagValue(TAG_KEY_SIZE, &key_size))
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;

        uint8_t data[key_size / 8];

        status = sss_rng_get_random(p_rng_ctx, data, key_size / 8);
        if (status != kStatus_SSS_Success)
            return KM_ERROR_INVALID_OPERATION_HANDLE;

        keymaster_blob_t key_data = {data, key_size / 8};

        km_error = import_key(dev, params, KM_KEY_FORMAT_PKCS8, (const keymaster_blob_t*)&key_data,
                              key_blob, characteristics);
        for (size_t i = 0; i < characteristics->hw_enforced.length; i++) {
            if (characteristics->hw_enforced.params[i].tag == TAG_ORIGIN)
                characteristics->hw_enforced.params[i].enumerated = KM_ORIGIN_GENERATED;
        }
        return km_error;

    } else if (algorithm == KM_ALGORITHM_EC) {
        km_error = parse_ec_param_set(org_params, &request.key_description);
        if (km_error != KM_ERROR_OK)
            return km_error;

        request.key_description.GetTagValue(TAG_KEY_SIZE, &key_size);
        ALOGI("alogortihm : KM_ALGORITHM_EC ");
        // ALOGI("EC tag key size %d ", key_size);
        KeyType = kSSS_KeyPart_Pair;
        cipherType = kSSS_CipherType_EC_NIST_P;
        policy_key.type = KPolicy_Asym_Key;
    } else if (algorithm == KM_ALGORITHM_RSA) {
        request.key_description.GetTagValue(TAG_KEY_SIZE, &key_size);
        ALOGI("alogortihm : KM_ALGORITHM_RSA ");
        // ALOGI("RSA tag key size %d ", key_size);
        if (key_size != 1024 && key_size != 2048 && key_size != 3072 && key_size != 4096)
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;
        KeyType = kSSS_KeyPart_Pair;
        cipherType = kSSS_CipherType_RSA_CRT;
        policy_key.type = KPolicy_Asym_Key;
    }

    /*Set common policies for keyObject
    Set key policies for keyObject based on tags*/
    km_error = create_policy_set(org_params, &policy_common, &policy_key);
    if (km_error != KM_ERROR_OK)
        return km_error;

    if (algorithm == KM_ALGORITHM_RSA) {
        policy_key.policy.asymmkey.can_Encrypt = 1;
        policy_key.policy.asymmkey.can_Decrypt = 1;
    }

    key_policies = {.nPolicies = 2, .policies = {&policy_common, &policy_key}};

    size_t keylen = key_size / 8;
    if (keylen != 0) {
        status = sss_key_object_init(&keyObject, &p_boot_ctx->ks);
        ALOGI("sss_key_object_init status  :0x%x", status);
        if (status != kStatus_SSS_Success) {
            return KM_ERROR_INVALID_OPERATION_HANDLE;
        }
        if (request.key_description.GetTagValue(TAG_INCLUDE_UNIQUE_ID)) {
            // ALOGI("unique Id included ");
            request.key_description.GetTagValue(TAG_UNIQUE_ID, &Id);
            if ((Id.data_length != 0) && Id.data) {
                keyId = (Id.data[0] << 8 * 3) | (Id.data[1] << 8 * 2) | (Id.data[2] << 8 * 1) |
                        Id.data[3];
            } else {
                goto retry;
            }
            // ALOGI("TAG_INCLUDE_UNIQUE_ID : %d", KM_TAG_INCLUDE_UNIQUE_ID & 0xFFFF);
            // ALOGI("TAG_UNIQUE_ID : %d", KM_TAG_UNIQUE_ID & 0xFFFF);
        } else {
        retry:
            ALOGW("Generating random AKM keyID");
            status = sss_rng_get_random(p_rng_ctx, rnd_keyID, sizeof(rnd_keyID));
            if (status != kStatus_SSS_Success)
                return KM_ERROR_INVALID_OPERATION_HANDLE;
            keyId = 0 | (0x7C << (3 * 8)) | (rnd_keyID[0] << (2 * 8)) | (rnd_keyID[1] << (1 * 8)) |
                    (rnd_keyID[2] << (0 * 8));
            sss_se05x_session_t* pSession = (sss_se05x_session_t*)&p_boot_ctx->session;
            if (!pSession)
                return KM_ERROR_UNEXPECTED_NULL_POINTER;
            smStatus_t ret = Se05x_API_CheckObjectExists(&pSession->s_ctx, keyId, &exists);
            ALOGI("Se05x_API_CheckObjectExists 0x%4x ", ret);
            if (SM_OK == ret) {
                if (exists == kSE05x_Result_SUCCESS) {
                    ALOGI("key with ID : 0x%X already exist", keyId);
                    goto retry;
                }
            } else
                return KM_ERROR_UNKNOWN_ERROR;
        }
        ALOGI("Using KeyId : 0x%2X", keyId);
        status = sss_key_object_allocate_handle(&keyObject, keyId, KeyType, cipherType, keylen,
                                                kKeyObject_Mode_Persistent);
        ALOGI("sss_key_object_allocate_handle : 0x%x", status);
        if (status != kStatus_SSS_Success) {
            return KM_ERROR_INVALID_OPERATION_HANDLE;
        }
        // ALOGI("KeySize before generate_key: %d", key_size);
        // ALOGI("KeyId before generating: 0x%x", keyObject.keyId);
        status = sss_key_store_generate_key(&p_boot_ctx->ks, &keyObject, key_size, &key_policies);
        ALOGI("sss_key_store_generate_key : 0x%x", status);
        if (status != kStatus_SSS_Success) {
            return KM_ERROR_INVALID_OPERATION_HANDLE;
        }
        sss_key_store_save(&p_boot_ctx->ks); /*Note : file write is failing so no status check*/
        key_object.key_material_size = sizeof(keyObject);
        uint8_t* buf = reinterpret_cast<uint8_t*>(malloc(key_object.key_material_size));
        if (!buf)
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        memcpy(buf, &keyObject, key_object.key_material_size);
        key_object.key_material = buf;
        hw_enforced = request.key_description;
        convert_device(dev)->context_->CreateKeyBlob(request.key_description, KM_ORIGIN_GENERATED,
                                                     key_object, &blob, &hw_enforced, &sw_enforced);
        for (auto& entry : sw_enforced) {
            if (entry.tag == KM_TAG_ORIGIN) {
                hw_enforced.push_back(entry);
                int index = sw_enforced.find(entry.tag, -1);
                sw_enforced.erase(index);
            }
        }
    } else {
        ALOGE("keylen is 0");
    }
    if (status != kStatus_SSS_Success)
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    // ALOGI("Object ID 0x%x", keyObject.keyId);
    key_blob->key_material_size = blob.key_material_size;
    uint8_t* tmp = reinterpret_cast<uint8_t*>(malloc(key_blob->key_material_size));
    if (!tmp)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(tmp, blob.key_material, key_blob->key_material_size);
    key_blob->key_material = tmp;
    // ALOGI("Keyblob pointer %p", key_blob->key_material);

    if (characteristics) {
        hw_enforced.CopyToParamSet(&characteristics->hw_enforced);
        sw_enforced.CopyToParamSet(&characteristics->sw_enforced);
    }
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t Se050KeymasterDevice::get_key_characteristics(
    const keymaster2_device_t* dev, const keymaster_key_blob_t* key_blob,
    const keymaster_blob_t* client_id, const keymaster_blob_t* app_data,
    keymaster_key_characteristics_t* characteristics) {
    ALOGI("%s function called ", __func__);
    if (!dev || !key_blob || !key_blob->key_material)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!convert_device(dev)->configured())
        return KM_ERROR_KEYMASTER_NOT_CONFIGURED;

    if (!characteristics)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    sss_status_t status;
    sss_object_t* p_keyObject = nullptr;
    GetKeyCharacteristicsRequest request;
    KeymasterKeyBlob key_object = {nullptr, 0};
    AuthorizationSet hw_enforced, sw_enforced;
    AddClientAndAppData(client_id, app_data, &request);
    ex_sss_boot_ctx_t* p_boot_ctx = &(convert_device(dev)->sss_ex_ctx);
    keymaster_error_t error = convert_device(dev)->context_->ParseKeyBlob(
        KeymasterKeyBlob(*key_blob), request.additional_params, &key_object, &hw_enforced,
        &sw_enforced);
    if (error != KM_ERROR_OK) {
        ALOGE("ParseKeyBlob failed with error %d", error);
        return error;
    }

    error = CheckVersionInfo(hw_enforced, sw_enforced, *(convert_device(dev)->context_));
    if (error != KM_ERROR_OK) {
        ALOGE("CheckVersionInfo failed with error %d", error);
        return error;
    }

    p_keyObject = (sss_object_t*)key_object.key_material;
    if (!p_keyObject)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    p_keyObject->keyStore = &p_boot_ctx->ks;

    ALOGI("keyId :0x%2x", p_keyObject->keyId);
    status = sss_key_object_get_handle(p_keyObject, p_keyObject->keyId);
    ALOGI("sss_key_object_get_handle 0x%8x ", status);
    if (kStatus_SSS_Success != status)
        return KM_ERROR_INVALID_KEY_BLOB;

    for (auto& entry : sw_enforced) {
        if (entry.tag == KM_TAG_ORIGIN) {
            hw_enforced.push_back(entry);
            int index = sw_enforced.find(entry.tag, -1);
            sw_enforced.erase(index);
        }
    }
    hw_enforced.CopyToParamSet(&characteristics->hw_enforced);
    sw_enforced.CopyToParamSet(&characteristics->sw_enforced);
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t Se050KeymasterDevice::import_key(
    const keymaster2_device_t* dev, const keymaster_key_param_set_t* params,
    keymaster_key_format_t key_format, const keymaster_blob_t* key_data,
    keymaster_key_blob_t* key_blob, keymaster_key_characteristics_t* characteristics) {
    ALOGI("%s function called ", __func__);
    if (!dev || !params || !key_data)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!convert_device(dev)->configured())
        return KM_ERROR_KEYMASTER_NOT_CONFIGURED;

    if (!key_blob)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    key_format = KM_KEY_FORMAT_PKCS8;
    SE05x_Result_t exists = kSE05x_Result_NA;
    sss_status_t status;
    keymaster_error_t km_error;
    uint32_t key_size = 0;
    const uint8_t* setKey = key_data->data;
    size_t Keylen = key_data->data_length;
    // ALOGI("Keylen is : %zu", Keylen);
    // ALOGI("data length is : %zu", sizeof(*key_data->data));
    uint32_t keyId = 0;
    uint8_t rnd_keyID[3] = {0};
    /*for (int i=0 ; i<Keylen ; i++){
      ALOGI("setKey[%d] : 0x%02x = %d",i,setKey[i],setKey[i]);
    }*/

    ex_sss_boot_ctx_t* p_boot_ctx = &(convert_device(dev)->sss_ex_ctx);
    sss_rng_context_t* p_rng_ctx = &(convert_device(dev)->sss_rng_ctx);

    sss_object_t keyObject;
    sss_key_part_t KeyType = kSSS_KeyPart_NONE;
    sss_cipher_type_t cipherType = kSSS_CipherType_NONE;
    sss_policy_u policy_common;
    sss_policy_u policy_key;
    sss_policy_t key_policies;
    GenerateKeyRequest request;
    keymaster_algorithm_t algorithm;
    keymaster_blob_t Id;
    AuthorizationSet hw_enforced, sw_enforced;
    KeymasterKeyBlob key_object = {nullptr, 0};
    KeymasterKeyBlob blob;
    AuthorizationSet org_params(*params);
    request.key_description.Reinitialize(*params);
    request.key_description.GetTagValue(TAG_UNIQUE_ID, &Id);
    keymaster_key_origin_t origin = KM_ORIGIN_IMPORTED;

    policy_common.type = KPolicy_Common;
    if (!request.key_description.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    }

    status = parseTPkeyObject(key_data, &keyId, algorithm);
    if (status == kStatus_SSS_Success) {
        ALOGI("TP Object parsed successfully");
        status = sss_key_object_init(&keyObject, &p_boot_ctx->ks);
        if (status != kStatus_SSS_Success) {
            ALOGE("sss_key_object_init failed");
            return KM_ERROR_INVALID_KEY_BLOB;
        }
        ALOGI("KeyId = 0x%8X", keyId);
        status = sss_key_object_get_handle(&keyObject, keyId);
        if (status != kStatus_SSS_Success) {
            ALOGE("sss_key_object_get_handle failed");
            return KM_ERROR_INVALID_KEY_BLOB;
        }
        status = verifyCipherTypeToKMAlgo((sss_cipher_type_t)keyObject.cipherType, algorithm);
        if (status != kStatus_SSS_Success) {
            return KM_ERROR_INVALID_TAG;
        }
        status = utils_->addTPauthorizationTags(keyObject, &hw_enforced);
        if (status != kStatus_SSS_Success) {
            return KM_ERROR_INVALID_KEY_BLOB;
        }
        ALOGI("TP key existance verified successfully");
        origin = KM_ORIGIN_GENERATED;
        goto createBlob;
    }

    if (algorithm == KM_ALGORITHM_HMAC) {
        policy_key.type = KPolicy_Sym_Key;
        ALOGI("alogortihm : KM_ALGORITHM_HMAC");

        if (!request.key_description.GetTagValue(TAG_KEY_SIZE, &key_size)) {
            key_size = key_data->data_length * 8;
            if (key_size < 64) {
                while ((key_size % 8 != 0) || (key_size < 64)) {
                    key_size++;
                    if (key_size > 2056)
                        return KM_ERROR_UNSUPPORTED_KEY_SIZE;
                }
            }
            // return KM_ERROR_UNSUPPORTED_KEY_SIZE;
        }

        int i = CountTags(&org_params, TAG_DIGEST);
        if (i != 1)
            return KM_ERROR_UNSUPPORTED_DIGEST;

        keymaster_digest_t digest;
        if (!request.key_description.GetTagValue(TAG_DIGEST, &digest))
            return KM_ERROR_UNSUPPORTED_DIGEST;
        if (digest == KM_DIGEST_NONE)
            return KM_ERROR_UNSUPPORTED_DIGEST;

        if (key_size % 8 != 0)
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;
        else if (key_size < 64 || key_size > 2056)
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;

        uint32_t min_mac_length;
        if (!request.key_description.GetTagValue(TAG_MIN_MAC_LENGTH, &min_mac_length))
            return KM_ERROR_MISSING_MIN_MAC_LENGTH;

        if (min_mac_length % 8 != 0)
            return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;

        if (min_mac_length < 64)
            return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;

        KeyType = kSSS_KeyPart_Default;
        cipherType = kSSS_CipherType_HMAC;
        Keylen = key_size / 8;

    } else if (algorithm == KM_ALGORITHM_AES) {
        for (size_t i = 0; i < org_params.size(); i++) {
            if (org_params[i].tag == TAG_PURPOSE) {
                if (org_params[i].enumerated == KM_PURPOSE_SIGN)
                    org_params.erase(i);
            }
        }

        for (size_t i = 0; i < org_params.size(); i++) {
            if (org_params[i].tag == TAG_PURPOSE) {
                if (org_params[i].enumerated == KM_PURPOSE_VERIFY)
                    org_params.erase(i);
            }
        }

        policy_key.type = KPolicy_Sym_Key;
        ALOGI("alogortihm : KM_ALGORITHM_AES ");
        request.key_description.GetTagValue(TAG_KEY_SIZE, &key_size);
        if (key_size != 128 && key_size != 192 && key_size != 256)
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;
        KeyType = kSSS_KeyPart_Default;
        cipherType = kSSS_CipherType_AES;
    } else if (algorithm == KM_ALGORITHM_EC) {
        ALOGI("alogortihm : KM_ALGORITHM_EC ");
        km_error = UpdateEccImportKeyDescription(key_format, key_data, org_params,
                                                 &request.key_description, &key_size);
        if (km_error != KM_ERROR_OK)
            return km_error;

        KeyType = kSSS_KeyPart_Pair;
        cipherType = kSSS_CipherType_EC_NIST_P;
        policy_key.type = KPolicy_Asym_Key;

    } else if (algorithm == KM_ALGORITHM_RSA) {
        ALOGI("alogortihm : KM_ALGORITHM_RSA ");
        KeymasterKeyBlob CheckBlob = {key_data->data, key_data->data_length};
        uint64_t public_exponent;
        km_error =
            UpdateRsaImportKeyDescription(org_params, key_format, CheckBlob,
                                          &request.key_description, &public_exponent, &key_size);
        if (km_error != KM_ERROR_OK)
            return km_error;

        KeyType = kSSS_KeyPart_Pair;
        cipherType = kSSS_CipherType_RSA_CRT;
        policy_key.type = KPolicy_Asym_Key;
    }

    km_error = create_policy_set(org_params, &policy_common, &policy_key);
    if (km_error != KM_ERROR_OK)
        return km_error;

    if (algorithm == KM_ALGORITHM_RSA) {
        policy_key.policy.asymmkey.can_Encrypt = 1;
        policy_key.policy.asymmkey.can_Decrypt = 1;
    } else if (algorithm == KM_ALGORITHM_HMAC) {
        policy_key.policy.symmkey.can_Sign = 1;
    }
    key_policies = {.nPolicies = 2, .policies = {&policy_common, &policy_key}};

    status = sss_key_object_init(&keyObject, &p_boot_ctx->ks);
    ALOGI("sss_key_object_init :0x%x", status);
    if (status != kStatus_SSS_Success) {
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    }
    if (request.key_description.GetTagValue(TAG_INCLUDE_UNIQUE_ID)) {
        // ALOGI("unique Id included ");
        request.key_description.GetTagValue(TAG_UNIQUE_ID, &Id);
        if ((Id.data_length != 0) && Id.data) {
            keyId =
                (Id.data[0] << 8 * 3) | (Id.data[1] << 8 * 2) | (Id.data[2] << 8 * 1) | Id.data[3];
        } else {
            goto retry;
        }
        // ALOGI("TAG_INCLUDE_UNIQUE_ID : %d", KM_TAG_INCLUDE_UNIQUE_ID & 0xFFFF);
        // ALOGI("TAG_UNIQUE_ID : %d", KM_TAG_UNIQUE_ID & 0xFFFF);
    } else {
    retry:
        ALOGW("Generating random AKM keyID");
        status = sss_rng_get_random(p_rng_ctx, rnd_keyID, sizeof(rnd_keyID));
        if (status != kStatus_SSS_Success)
            return KM_ERROR_INVALID_OPERATION_HANDLE;
        keyId = 0 | (0x7C << (3 * 8)) | (rnd_keyID[0] << (2 * 8)) | (rnd_keyID[1] << (1 * 8)) |
                (rnd_keyID[2] << (0 * 8));
        sss_se05x_session_t* pSession = (sss_se05x_session_t*)&p_boot_ctx->session;
        if (!pSession)
            return KM_ERROR_UNEXPECTED_NULL_POINTER;
        smStatus_t ret = Se05x_API_CheckObjectExists(&pSession->s_ctx, keyId, &exists);
        ALOGI("Se05x_API_CheckObjectExists 0x%4x ", ret);
        if (SM_OK == ret) {
            if (exists == kSE05x_Result_SUCCESS) {
                ALOGI("key with ID : 0x%X already exist", keyId);
                goto retry;
            }
        } else
            return KM_ERROR_UNKNOWN_ERROR;
    }
    ALOGI("Using KeyId : 0x%2X", keyId);
    // ALOGI("Keylen before allocate_handle is: %zu", Keylen);
    status = sss_key_object_allocate_handle(&keyObject, keyId, KeyType, cipherType, Keylen,
                                            kKeyObject_Mode_Persistent);
    ALOGI("sss_key_object_allocate_handle : 0x%x", status);
    if (status != kStatus_SSS_Success) {
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    }
    // ALOGI("key_size before setkey : %d", key_size);
    // ALOGI("Using KeyId for importing: 0x%x", keyObject.keyId);
    status = sss_key_store_set_key(&p_boot_ctx->ks, &keyObject, setKey, Keylen, key_size,
                                   &key_policies, 0);
    ALOGI("sss_key_store_set_key : 0x%x", status);
    if (status != kStatus_SSS_Success) {
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    }
    sss_key_store_save(&p_boot_ctx->ks);

createBlob:
    AuthorizationSet hw_auth(request.key_description);
    for (auto& entry : hw_enforced) {
        hw_auth.push_back(entry);
    }
    key_object.key_material_size = sizeof(keyObject);
    uint8_t* buf = reinterpret_cast<uint8_t*>(malloc(key_object.key_material_size));
    if (!buf)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(buf, &keyObject, key_object.key_material_size);
    key_object.key_material = buf;
    convert_device(dev)->context_->CreateKeyBlob(request.key_description, origin, key_object, &blob,
                                                 &hw_auth, &sw_enforced);
    for (auto& entry : sw_enforced) {
        if (entry.tag == KM_TAG_ORIGIN) {
            hw_auth.push_back(entry);
            int index = sw_enforced.find(entry.tag, -1);
            sw_enforced.erase(index);
        }
    }
    key_blob->key_material_size = blob.key_material_size;
    key_blob->key_material = reinterpret_cast<uint8_t*>(malloc(key_blob->key_material_size));
    if (!key_blob->key_material)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(const_cast<uint8_t*>(key_blob->key_material), blob.key_material,
           key_blob->key_material_size);

    /*ALOGI("Object ID 0x%x", keyObject.keyId);
    ALOGI("KeyBlob pointer %p", key_blob->key_material);
    ALOGI("Object ID 0x%x", keyObject.keyId);*/
    if (characteristics) {
        hw_auth.CopyToParamSet(&characteristics->hw_enforced);
        sw_enforced.CopyToParamSet(&characteristics->sw_enforced);
    }
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t Se050KeymasterDevice::export_key(const keymaster2_device_t* dev,
                                                   keymaster_key_format_t export_format,
                                                   const keymaster_key_blob_t* key_to_export,
                                                   const keymaster_blob_t* client_id,
                                                   const keymaster_blob_t* app_data,
                                                   keymaster_blob_t* export_data) {
    ALOGI("%s function called ", __func__);
    if (!dev)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!convert_device(dev)->configured())
        return KM_ERROR_KEYMASTER_NOT_CONFIGURED;

    if (!key_to_export || !key_to_export->key_material)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (export_format == KM_KEY_FORMAT_PKCS8) {
        return KM_ERROR_UNSUPPORTED_KEY_FORMAT;
    }

    if (!export_data)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    export_data->data = nullptr;
    export_data->data_length = 0;

    ex_sss_boot_ctx_t* p_boot_ctx = &(convert_device(dev)->sss_ex_ctx);

    sss_status_t status;
    uint8_t key[550] = {0};
    size_t keybytelen = sizeof(key);
    size_t keybitlen = sizeof(key) * 8;
    sss_object_t* p_keyObject = nullptr;
    ExportKeyRequest request;
    KeymasterKeyBlob key_object = {nullptr, 0};
    request.key_format = export_format;
    request.SetKeyMaterial(*key_to_export);
    AuthorizationSet hw_enforced, sw_enforced;
    AddClientAndAppData(client_id, app_data, &request);

    keymaster_error_t error = convert_device(dev)->context_->ParseKeyBlob(
        KeymasterKeyBlob(*key_to_export), request.additional_params, &key_object, &hw_enforced,
        &sw_enforced);
    if (error != KM_ERROR_OK) {
        ALOGE("keyblob parsing failed");
        return error;
    }

    p_keyObject = (sss_object_t*)key_object.key_material;
    // ALOGI("cipherType = %d", p_keyObject->cipherType);
    if (p_keyObject->cipherType == kSSS_CipherType_AES)
        return KM_ERROR_UNSUPPORTED_KEY_FORMAT;
    if ((p_keyObject->keyId == 0x00000003) &&
        ((p_keyObject->cipherType == kSSS_CipherType_RSA_CRT) ||
         (p_keyObject->cipherType == kSSS_CipherType_RSA))) {
        ALOGW("Non readable key exist at keyID : 0x%08X. Returning dummy key", p_keyObject->keyId);
        uint8_t dummy_rsa_pub[] = rsa_pub;
        memcpy(key, dummy_rsa_pub, sizeof(dummy_rsa_pub));
        keybytelen = sizeof(dummy_rsa_pub);
    } else {
        status = sss_key_store_get_key(&p_boot_ctx->ks, p_keyObject, key, &keybytelen, &keybitlen);
        // ALOGI("KEYBITlEN: %zu", keybitlen);
        if (status != kStatus_SSS_Success) {
            return KM_ERROR_INVALID_OPERATION_HANDLE;
        }
    }
    export_data->data_length = keybytelen;
    uint8_t* tmp = reinterpret_cast<uint8_t*>(malloc(export_data->data_length));
    if (!tmp)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(tmp, key, export_data->data_length);
    export_data->data = tmp;
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t Se050KeymasterDevice::attest_key(const keymaster2_device_t* dev,
                                                   const keymaster_key_blob_t* key_to_attest,
                                                   const keymaster_key_param_set_t* attest_params,
                                                   keymaster_cert_chain_t* cert_chain) {
    ALOGI("%s function called ", __func__);
    if (!dev || !key_to_attest || !attest_params || !cert_chain)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!convert_device(dev)->configured())
        return KM_ERROR_KEYMASTER_NOT_CONFIGURED;

    *cert_chain = {};
    KeymasterKeyBlob key_object = {nullptr, 0};
    AuthorizationSet hw_enforced, sw_enforced;
    AttestKeyRequest request;
    AttestKeyResponse response;
    keymaster_cert_chain_t attest_chain = {nullptr, 0};
    attest_chain = {};
    keymaster_blob_t attestation_application_id;
    request.SetKeyMaterial(*key_to_attest);
    request.attest_params.Reinitialize(*attest_params);
    keymaster_error_t error = convert_device(dev)->context_->ParseKeyBlob(
        KeymasterKeyBlob(*key_to_attest), request.attest_params, &key_object, &hw_enforced,
        &sw_enforced);
    if (error != KM_ERROR_OK) {
        ALOGE("keyblob parsing failed");
        return error;
    }

    if (!request.attest_params.GetTagValue(TAG_ATTESTATION_APPLICATION_ID,
                                           &attestation_application_id))
        return KM_ERROR_ATTESTATION_APPLICATION_ID_MISSING;
    // else
    //    sw_enforced.push_back(TAG_ATTESTATION_APPLICATION_ID, attestation_application_id);
    for (auto& entry : sw_enforced) {
        if (entry.tag == KM_TAG_ORIGIN) {
            hw_enforced.push_back(entry);
            int index = sw_enforced.find(entry.tag, -1);
            sw_enforced.erase(index);
        }
    }

    error =
        utils_->GenerateAttestation(&key_object, request.attest_params, sw_enforced, hw_enforced,
                                    /*cert_chain*/ &attest_chain);
    ALOGD("GenerateAttestation returned %d", error);
    if (error != KM_ERROR_OK) {
        ALOGE("Attastaion failed with error %d ", error);
        return error;
    }

    // ALOGI("entry count = %zu", attest_chain.entry_count);
    cert_chain->entries = reinterpret_cast<keymaster_blob_t*>(
        malloc(attest_chain.entry_count * sizeof(*cert_chain->entries)));
    if (!cert_chain->entries)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    cert_chain->entry_count = attest_chain.entry_count;
    // copy cert_chain contents
    // cert_chain must have at least two entries, one for the cert we're
    // trying to create and one for the cert for the key that signs the new cert
    // cert_chain->entry_count = 2;
    for (keymaster_blob_t& entry : array_range(cert_chain->entries, cert_chain->entry_count))
        entry = {};

    size_t i = 0;
    for (keymaster_blob_t& entry : array_range(attest_chain.entries, attest_chain.entry_count)) {
        cert_chain->entries[i].data = reinterpret_cast<uint8_t*>(malloc(entry.data_length));
        if (!cert_chain->entries[i].data) {
            keymaster_free_cert_chain(cert_chain);
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        cert_chain->entries[i].data_length = entry.data_length;
        memcpy(const_cast<uint8_t*>(cert_chain->entries[i].data), entry.data, entry.data_length);
        ++i;
        // ALOGI("cert_chain is %s", cert_chain->entries[i].data);
    }
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t Se050KeymasterDevice::upgrade_key(const keymaster2_device_t* dev,
                                                    const keymaster_key_blob_t* key_to_upgrade,
                                                    const keymaster_key_param_set_t* upgrade_params,
                                                    keymaster_key_blob_t* upgraded_key) {
    if (!dev || !key_to_upgrade || !upgrade_params)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!upgraded_key)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    if (!convert_device(dev)->configured())
        return KM_ERROR_KEYMASTER_NOT_CONFIGURED;

    UpgradeKeyRequest request;
    request.SetKeyMaterial(*key_to_upgrade);
    request.upgrade_params.Reinitialize(*upgrade_params);

    UpgradeKeyResponse response;
    convert_device(dev)->impl_->UpgradeKey(request, &response);
    if (response.error != KM_ERROR_OK)
        return response.error;

    upgraded_key->key_material_size = response.upgraded_key.key_material_size;
    uint8_t* tmp = reinterpret_cast<uint8_t*>(malloc(upgraded_key->key_material_size));
    if (!tmp)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(tmp, response.upgraded_key.key_material, response.upgraded_key.key_material_size);
    upgraded_key->key_material = tmp;

    return KM_ERROR_OK;
}

/* static */
keymaster_error_t Se050KeymasterDevice::delete_key(const keymaster2_device_t* dev,
                                                   const keymaster_key_blob_t* key) {
    ALOGI("%s function called ", __func__);
    if (!dev)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!convert_device(dev)->configured())
        return KM_ERROR_KEYMASTER_NOT_CONFIGURED;

    if (!key || !key->key_material)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    ex_sss_boot_ctx_t* p_boot_ctx = &(convert_device(dev)->sss_ex_ctx);

    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t* p_keyObject = nullptr;
    KeymasterKeyBlob key_object = {nullptr, 0};
    AuthorizationSet hw_enforced, sw_enforced, params;
    // ALOGI("blob material size before delete %zu", key->key_material_size);

    keymaster_error_t error = convert_device(dev)->context_->ParseKeyBlob(
        KeymasterKeyBlob(*key), params, &key_object, &hw_enforced, &sw_enforced);
    if (error != KM_ERROR_OK) {
        ALOGE("ParseKeyBlob failed with error %d", error);
        return error;
    }
    p_keyObject = (sss_object_t*)key_object.key_material;
    /*ALOGI("keyobject pointing to %p", p_keyObject);
    ALOGI("Object ID 0x%x", p_keyObject->keyId);*/
    if (!p_keyObject)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    status = sss_key_store_erase_key(&p_boot_ctx->ks, p_keyObject);
    ALOGI("sss_key_store_erase_key : 0x%x", status);
    /*As vts is not able to create sss .bin files so right now we are not checking return status*/
    if (kStatus_SSS_Success != status) {
        if (!SE05X_OBJID_TP_MASK(p_keyObject->keyId) && p_keyObject->keyId) {
            ALOGI("Not erasing Trust Provisioned objects");
        } else {
            /*unable to delete key object*/
            return KM_ERROR_INVALID_OPERATION_HANDLE;
        }
    } else {
#if !SSS_HAVE_APPLET_SE05X_IOT
        status = sss_key_store_save(&p_boot_ctx->ks);
        ALOGI("sss_key_store_save : 0x%x", status);
        if (kStatus_SSS_Success != status)
            return KM_ERROR_INVALID_OPERATION_HANDLE;
#endif
    }
    KeymasterKeyBlob blob(*key);
    return convert_device(dev)->context_->DeleteKey(blob);
}

/* static */
keymaster_error_t Se050KeymasterDevice::delete_all_keys(const keymaster2_device_t* dev) {

    ALOGI("%s function called ", __func__);
    if (!dev)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    ex_sss_boot_ctx_t* p_boot_ctx = &(convert_device(dev)->sss_ex_ctx);

#if SSS_HAVE_APPLET_SE05X_IOT
    smStatus_t se05x_status = SM_NOT_OK;
    sss_se05x_session_t* se05x_session = (sss_se05x_session_t*)&p_boot_ctx->session;
    se05x_status = Se05x_API_DeleteAll_Iterative(&se05x_session->s_ctx);
    ALOGD("Se05x_API_DeleteAll_Iterative Status: %x", se05x_status);
    if (se05x_status == SM_OK)
        return KM_ERROR_OK;
    else
        return KM_ERROR_UNKNOWN_ERROR;

    return KM_ERROR_OK;
#elif SSS_HAVE_HOSTCRYPTO_MBEDTLS
    sss_mbedtls_key_store_t* P_keystore = (sss_mbedtls_key_store_t*)&p_boot_ctx->ks;
    if (NULL != P_keystore->objects) {
        uint32_t i;
        for (i = 0; i < P_keystore->max_object_count; i++) {
            if (P_keystore->objects[i] != NULL) {
                sss_mbedtls_key_object_free(P_keystore->objects[i]);
                P_keystore->objects[i] = NULL;
            }
        }
        free(P_keystore->objects);
        P_keystore->objects = NULL;
        // ALOGI("All Key deleted successfully");
        return KM_ERROR_OK;
    }
    return KM_ERROR_UNEXPECTED_NULL_POINTER;
#endif
}

/* static */
keymaster_error_t Se050KeymasterDevice::begin(const keymaster2_device_t* dev,
                                              keymaster_purpose_t purpose,
                                              const keymaster_key_blob_t* key,
                                              const keymaster_key_param_set_t* in_params,
                                              keymaster_key_param_set_t* out_params,
                                              keymaster_operation_handle_t* operation_handle) {

    if (!dev || !key || !key->key_material) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }

    if (!convert_device(dev)->configured())
        return KM_ERROR_KEYMASTER_NOT_CONFIGURED;

    if (!operation_handle)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    ALOGI("%s function called ", __func__);
    AuthorizationSet params(*in_params);
    AuthorizationSet hw_enforced, sw_enforced;
    KeymasterKeyBlob key_object;
    sss_status_t status;
    keymaster_error_t km_error;
    ex_sss_boot_ctx_t* p_boot_ctx = &(convert_device(dev)->sss_ex_ctx);

    km_error = convert_device(dev)->context_->ParseKeyBlob(KeymasterKeyBlob(*key), params,
                                                           &key_object, &hw_enforced, &sw_enforced);
    if (km_error != KM_ERROR_OK) {
        ALOGE("ParseKeyBlob failed with error %d", km_error);
        return km_error;
    }

    km_error = CheckVersionInfo(hw_enforced, sw_enforced, *(convert_device(dev)->context_));
    if (km_error != KM_ERROR_OK) {
        ALOGE("CheckVersionInfo failed with error %d", km_error);
        return km_error;
    }

    sss_object_t* p_keyObject = (sss_object_t*)malloc(sizeof(sss_object_t));
    if (!p_keyObject)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(p_keyObject, key_object.key_material, sizeof(sss_object_t));

    if (out_params) {
        out_params->params = nullptr;
        out_params->length = 0;
    }
    sss_mode_t mode = kMode_SSS_Verify;
    sss_algorithm_t algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
    // sss_key_part_t KeyType = (sss_key_part_t)p_keyObject->objectType;
    sss_cipher_type_t cipherType = (sss_cipher_type_t)p_keyObject->cipherType;
    keymaster_digest_t digest;
    sss_km_operation_t* operation =
        (sss_km_operation_t*)malloc(sizeof(sss_km_operation_t) * (sizeof(Buffer)));
    if (!operation) {
        km_error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        goto error;
    }
    switch (purpose) {
    case KM_PURPOSE_ENCRYPT:
        mode = kMode_SSS_Encrypt;
        break;
    case KM_PURPOSE_DECRYPT:
        mode = kMode_SSS_Decrypt;
        break;
    case KM_PURPOSE_SIGN:
        mode = kMode_SSS_Sign;
        break;
    case KM_PURPOSE_VERIFY:
        mode = kMode_SSS_Verify;
        break;
    default:
        ALOGE("Invalid Keypurpose");
        km_error = KM_ERROR_UNSUPPORTED_PURPOSE;
        goto error;
    }

    switch (cipherType) {
    case kSSS_CipherType_RSA:
    case kSSS_CipherType_RSA_CRT:
        operation->op_type = kOperation_SSS_KM_Asymm;
        km_error = utils_->UpdateRsaOperationDescription(
            &params, sw_enforced, hw_enforced, p_keyObject, purpose, &algorithm, operation);
        if (km_error != KM_ERROR_OK)
            goto error;
        // ALOGI("UpdateRsaOperationDescription: %d", km_error);
        break;

    case kSSS_CipherType_EC_NIST_P:
        operation->op_type = kOperation_SSS_KM_Asymm;
        if (mode == kMode_SSS_Encrypt || mode == kMode_SSS_Decrypt) {
            ALOGE("ECC key unsupported purpose");
            km_error = KM_ERROR_UNSUPPORTED_PURPOSE;
            goto error;
        }
        if (!params.GetTagValue(TAG_DIGEST, &digest)) {
            km_error = KM_ERROR_UNSUPPORTED_DIGEST;
            goto error;
        }
        // ALOGI("tag digest set as %d", digest);
        if (digest == KM_DIGEST_SHA1)
            algorithm = kAlgorithm_SSS_SHA1;
        else if (digest == KM_DIGEST_SHA_2_224)
            algorithm = kAlgorithm_SSS_SHA224;
        else if (digest == KM_DIGEST_SHA_2_256)
            algorithm = kAlgorithm_SSS_SHA256;
        else if (digest == KM_DIGEST_SHA_2_384)
            algorithm = kAlgorithm_SSS_SHA384;
        else if (digest == KM_DIGEST_SHA_2_512)
            algorithm = kAlgorithm_SSS_SHA512;
        else {
            ALOGE("Keysize not supported");
            algorithm = kAlgorithm_SSS_SHA256;
        }
        operation->op_handle.op_asymm.digest = digest;
        operation->op_handle.op_asymm.padding = KM_PAD_NONE;
        break;

    case kSSS_CipherType_AES:
        operation->op_type = kOperation_SSS_KM_Symm;
        if (mode == kMode_SSS_Sign || mode == kMode_SSS_Verify) {
            ALOGE("AES sign verify not supported");
            km_error = KM_ERROR_UNSUPPORTED_PURPOSE;
            goto error;
        }
        km_error = utils_->UpdateAesOperationDescription(&params, sw_enforced, hw_enforced, purpose,
                                                         &algorithm, out_params, operation);
        if (km_error != KM_ERROR_OK) {
            goto error;
        }
        break;

    case kSSS_CipherType_HMAC:
        // ALOGI("Hmac CipherType");
        operation->op_type = kOperation_SSS_KM_Mac;
        if (mode == kMode_SSS_Encrypt || mode == kMode_SSS_Decrypt) {
            ALOGE("Encryption Decryption operations not supported with HMAC");
            km_error = KM_ERROR_UNSUPPORTED_PURPOSE;
            goto error;
        }
        if (mode == kMode_SSS_Sign) {
            mode = kMode_SSS_Mac;
        } else if (mode == kMode_SSS_Verify) {
            mode = kMode_SSS_Mac_Validate;
        }
        // mode = kMode_SSS_Mac;
        km_error = utils_->UpdateHmacOperationDescription(&params, sw_enforced, hw_enforced,
                                                          purpose, &algorithm, operation);
        // ALOGD("UpdateHmacOperationDescription : %d", km_error);
        if (km_error != KM_ERROR_OK) {
            goto error;
        }

        break;

    default:
        ALOGE("Unsupported KeyType");
        km_error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        goto error;
    }
    /*ALOGI("ALGO IS : %d", algorithm);
    ALOGI("MODE IS : %d", mode);
    ALOGI("Keyobject pointer %p", p_keyObject);
    ALOGI("Object ID 0x%x", p_keyObject->keyId);*/

    if (cipherType == kSSS_CipherType_AES) {
        switch (operation->op_handle.op_symm.block_mode) {
        case KM_MODE_ECB:
        case KM_MODE_CBC:
        case KM_MODE_CTR:
            status = sss_symmetric_context_init(&operation->op_handle.op_symm.symm_ctx,
                                                &p_boot_ctx->session, p_keyObject, algorithm, mode);
            ALOGI("sss_symmetric_context_init : 0x%x", status);
            if (status != kStatus_SSS_Success) {
                km_error = KM_ERROR_OPERATION_CANCELLED;
                goto error;
            }
            status = sss_cipher_init(&operation->op_handle.op_symm.symm_ctx,
                                     operation->op_handle.op_symm.iv,
                                     operation->op_handle.op_symm.ivLen);
            ALOGI("sss_cipher_init : %x", status);
            if (status != kStatus_SSS_Success) {
                km_error = KM_ERROR_OPERATION_CANCELLED;
                goto error;
            } else {
                memcpy(operation_handle, &operation, sizeof(operation));
            }
            break;
        case KM_MODE_GCM:
            status = sss_aead_context_init(&operation->op_handle.op_symm.aead_ctx,
                                           &p_boot_ctx->session, p_keyObject, algorithm, mode);
            ALOGI("sss_aead_context_init : 0x%x", status);
            if (status != kStatus_SSS_Success) {
                km_error = KM_ERROR_OPERATION_CANCELLED;
                goto error;
            }
            status = sss_aead_init(&operation->op_handle.op_symm.aead_ctx,
                                   operation->op_handle.op_symm.iv,
                                   operation->op_handle.op_symm.ivLen, 8, 8, 8);
            ALOGI("sss_aead_init : 0x%x", status);
            if (status != kStatus_SSS_Success) {
                km_error = KM_ERROR_OPERATION_CANCELLED;
                goto error;
            } else {
                memcpy(operation_handle, &operation, sizeof(operation));
                /*data is not precessed yet so AAD is allowed*/
                operation->op_handle.op_symm.data_started = false;
            }
            break;
        }
    }

    else if (cipherType == kSSS_CipherType_HMAC) {
        status = sss_mac_context_init(&operation->op_handle.op_mac.mac_ctx, &p_boot_ctx->session,
                                      p_keyObject, algorithm, mode);
        ALOGI("sss_mac_context_init : 0x%x", status);
        if (status != kStatus_SSS_Success) {
            km_error = KM_ERROR_OPERATION_CANCELLED;
            goto error;
        }
        status = sss_mac_init(&operation->op_handle.op_mac.mac_ctx);
        ALOGI("sss_mac_init : 0x%x", status);
        if (status != kStatus_SSS_Success) {
            km_error = KM_ERROR_OPERATION_CANCELLED;
            goto error;
        } else {
            memcpy(operation_handle, &operation, sizeof(operation));
        }
    }

    else {
        status = sss_asymmetric_context_init(&operation->op_handle.op_asymm.asymm_ctx,
                                             &p_boot_ctx->session, p_keyObject, algorithm, mode);
        ALOGI("sss_asymmetric_context_init : 0x%x", status);
        if (status != kStatus_SSS_Success) {
            km_error = KM_ERROR_OPERATION_CANCELLED;
            goto error;
        } else {
            memcpy(operation_handle, &operation, sizeof(operation));
        }
    }
    params.Clear();
    return KM_ERROR_OK;
error:
    if (operation) {
        free(operation);
    }
    if (p_keyObject) {
        free(p_keyObject);
    }
    return km_error;
}

/* static */
keymaster_error_t Se050KeymasterDevice::update(
    const keymaster2_device_t* dev, keymaster_operation_handle_t operation_handle,
    const keymaster_key_param_set_t* in_params, const keymaster_blob_t* input,
    size_t* input_consumed, keymaster_key_param_set_t* out_params, keymaster_blob_t* output) {

    ALOGI("%s function called ", __func__);
    if (!dev || !input)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!convert_device(dev)->configured())
        return KM_ERROR_KEYMASTER_NOT_CONFIGURED;

    if (!input_consumed)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    if (out_params) {
        out_params->params = nullptr;
        out_params->length = 0;
    }
    if (output) {
        output->data = nullptr;
        output->data_length = 0;
    }
    if (!output)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    UpdateOperationRequest request;
    sss_km_operation_t** ppOperation = nullptr;
    keymaster_error_t km_error = KM_ERROR_OK;
    sss_status_t status;
    sss_km_symmetric_context_t* symmCtx = nullptr;
    sss_km_mac_context_t* macCtx = nullptr;
    keymaster_blob_t aad;
    sss_km_asymmetric_context_t* asymmCtx = nullptr;
    uint8_t srcData[2048];
    size_t srcDataLen = input->data_length;
    ALOGI("Input data Len %zu", input->data_length);
    uint8_t encBuf[512];
    size_t encBufLen = sizeof(encBuf);
    uint8_t* tmp;
    size_t parsedKeyByteLen = 0;
    uint8_t* rsaN = nullptr;
    memset(encBuf, 0x00, encBufLen);
    if (input->data) {
        request.input.Reinitialize(input->data, input->data_length);
    } else {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (in_params) {
        request.additional_params.Reinitialize(*in_params);
    }

    ppOperation = (sss_km_operation_t**)(&operation_handle);
    if (!(*ppOperation)) {
        km_error = KM_ERROR_INVALID_OPERATION_HANDLE;
        goto error;
    }
    // asymmCtx = (sss_km_asymmetric_context_t*)malloc(sizeof(sss_km_asymmetric_context_t));
    if ((*ppOperation)->op_type == kOperation_SSS_KM_Asymm) {
        ALOGI("Asymmetric operation");
        asymmCtx = (sss_km_asymmetric_context_t*)&(*ppOperation)->op_handle.op_asymm;
        if ((asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_RSA) ||
            (asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_RSA_CRT)) {
            km_error = utils_->RsaOperationParsePubKey(asymmCtx->asymm_ctx.keyObject, &rsaN,
                                                       &parsedKeyByteLen);
            if (km_error != KM_ERROR_OK) {
                goto error;
            }
            parsedKeyByteLen = parsedKeyByteLen * 8;
            if (!asymmCtx->update_rsa_buf.reserve(parsedKeyByteLen)) {
                km_error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                goto error;
            }
            if (!asymmCtx->update_rsa_buf.write(request.input.peek_read(),
                                                request.input.available_read())) {
                ALOGE("Input too long: cannot operate on %zu bytes of data with %zu-byte key",
                      request.input.available_read() + asymmCtx->update_rsa_buf.available_read(),
                      parsedKeyByteLen);
                km_error = KM_ERROR_INVALID_INPUT_LENGTH;
                goto error;
            }
        }
        if (asymmCtx->asymm_ctx.keyObject->cipherType == kSSS_CipherType_EC_NIST_P) {
            km_error =
                utils_->EcOperationParsePubKey(asymmCtx->asymm_ctx.keyObject, &parsedKeyByteLen);
            if (km_error != KM_ERROR_OK)
                goto error;
            if (!asymmCtx->update_ec_buf.reserve(((parsedKeyByteLen) + 7) / 8)) {
                km_error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                goto error;
            }

            if (!asymmCtx->update_ec_buf.write(request.input.peek_read(),
                                               std::min(asymmCtx->update_ec_buf.available_write(),
                                                        request.input.available_read()))) {
                ALOGE("Input too long: cannot operate on %zu bytes of data with %zu-byte key",
                      request.input.available_read() + asymmCtx->update_ec_buf.available_read(),
                      parsedKeyByteLen);
                km_error = KM_ERROR_INVALID_INPUT_LENGTH;
                goto error;
            }
        }

        *input_consumed = request.input.available_read();
        ALOGI("input data consumed :%zu", *input_consumed);

        km_error = KM_ERROR_OK;
    } else if ((*ppOperation)->op_type == kOperation_SSS_KM_Mac) {
        ALOGI("Mac operation");
        if (srcDataLen > sizeof(srcData)) {
            km_error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
            goto error;
        }
        memcpy(&srcData[0], input->data, srcDataLen);
        macCtx = &((*ppOperation)->op_handle.op_mac);
        status = sss_mac_update(&(macCtx->mac_ctx), srcData, srcDataLen);
        ALOGI("sss_cipher_update : %x", status);
        // ALOGI("encBufLen = %zu", encBufLen);
        if (status != kStatus_SSS_Success) {
            km_error = KM_ERROR_OPERATION_CANCELLED;
            goto error;
        }
        *input_consumed = srcDataLen;
    } else if ((*ppOperation)->op_type == kOperation_SSS_KM_Symm) {
        ALOGI("Symmetric operation");
        if (srcDataLen > sizeof(srcData)) {
            km_error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
            goto error;
        }
        memcpy(&srcData[0], input->data, srcDataLen);
        symmCtx = &((*ppOperation)->op_handle.op_symm);
        if (symmCtx->block_mode == KM_MODE_GCM) {
            if (request.additional_params.GetTagValue(TAG_ASSOCIATED_DATA, &aad)) {
                /*if Process of data has already began no more AAD is allowed*/
                if (symmCtx->data_started) {
                    km_error = KM_ERROR_INVALID_TAG;
                    goto error;
                }
                status = sss_aead_update_aad(&(symmCtx->aead_ctx), aad.data, aad.data_length);
                ALOGI("sss_aead_update_aad : %x", status);
                if (status != kStatus_SSS_Success) {
                    km_error = KM_ERROR_OPERATION_CANCELLED;
                    goto error;
                }
            }
            if (srcDataLen > 0)
                /*data process started no more AAD is allowed*/
                symmCtx->data_started = true;
            // encBufLen = srcDataLen;
            status = sss_aead_update(&(symmCtx->aead_ctx), srcData, srcDataLen, encBuf, &encBufLen);
            ALOGI("sss_aead_update : %x", status);
            ALOGI("encBufLen = %zu", encBufLen);
            if (status != kStatus_SSS_Success) {
                km_error = KM_ERROR_OPERATION_CANCELLED;
                goto error;
            }
            if (symmCtx->aead_ctx.mode == kMode_SSS_Decrypt) {
                if (encBufLen > 0) {
                    size_t i = 0;
                    while ((encBuf[encBufLen - 1 - i] == 0) && i < encBufLen) {
                        i++;
                    }
                    encBufLen = encBufLen - i;
                }
            }
        } else {
            status =
                sss_cipher_update(&(symmCtx->symm_ctx), srcData, srcDataLen, encBuf, &encBufLen);
            ALOGI("sss_cipher_update : %x", status);
            // ALOGI("encBufLen = %zu", encBufLen);
            if (status != kStatus_SSS_Success) {
                km_error = KM_ERROR_OPERATION_CANCELLED;
                goto error;
            }
        }
        output->data_length = encBufLen;
        tmp =
            /*reinterpret_cast<uint8_t*>*/ (uint8_t*)(malloc(encBufLen));
        if (!tmp) {
            km_error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
            goto error;
        }
        if (encBufLen > 0) {
            memcpy(tmp, encBuf, encBufLen);
        }
        output->data = tmp;
        *input_consumed = srcDataLen;
    } else {
        ALOGE("Unsuported Cypher type");
        km_error = KM_ERROR_INVALID_OPERATION_HANDLE;
        goto error;
    }

    memmove(&operation_handle, ppOperation, sizeof(*ppOperation));
    goto exit;
error:
    if ((*ppOperation)) {
        if ((*ppOperation)->op_type == kOperation_SSS_KM_Asymm) {
            free((*ppOperation)->op_handle.op_asymm.asymm_ctx.keyObject);
            sss_asymmetric_context_free(&((*ppOperation)->op_handle.op_asymm.asymm_ctx));
            free((*ppOperation));
        } else if ((*ppOperation)->op_type == kOperation_SSS_KM_Mac) {
            free((*ppOperation)->op_handle.op_mac.mac_ctx.keyObject);
            sss_mac_context_free(&((*ppOperation)->op_handle.op_mac.mac_ctx));
            free((*ppOperation));
        } else if ((*ppOperation)->op_type == kOperation_SSS_KM_Symm) {
            if ((*ppOperation)->op_handle.op_symm.symm_ctx.keyObject) {
                free((*ppOperation)->op_handle.op_symm.symm_ctx.keyObject);
                sss_symmetric_context_free(&((*ppOperation)->op_handle.op_symm.symm_ctx));
            }
            if ((*ppOperation)->op_handle.op_symm.aead_ctx.keyObject) {
                free((*ppOperation)->op_handle.op_symm.aead_ctx.keyObject);
                sss_aead_context_free(&((*ppOperation)->op_handle.op_symm.aead_ctx));
            }
            free((*ppOperation));
        }
    }
exit:
    if (rsaN) {
        free(rsaN);  // As we are allocating  memory for modulas in sss layer free the memory after
                     // use*/
    }
    out_params = nullptr;
    in_params = nullptr;
    return km_error;
}

struct KeyParamSetContents_Delete {
    void operator()(keymaster_key_param_set_t* p) { keymaster_free_param_set(p); }
};

/* static */
keymaster_error_t Se050KeymasterDevice::finish(const keymaster2_device_t* dev,
                                               keymaster_operation_handle_t operation_handle,
                                               const keymaster_key_param_set_t* params,
                                               const keymaster_blob_t* input,
                                               const keymaster_blob_t* signature,
                                               keymaster_key_param_set_t* out_params,
                                               keymaster_blob_t* output) {

    keymaster_error_t km_error = KM_ERROR_OK;
    ALOGI("%s function called ", __func__);
    if (!dev || !operation_handle)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!convert_device(dev)->configured())
        return KM_ERROR_KEYMASTER_NOT_CONFIGURED;

    AuthorizationSet finish_params;
    if (params) {
        finish_params = AuthorizationSet(*params);
    }
    sss_km_operation_t** poperation = nullptr;
    uint8_t signature1[512] = {0};
    size_t signaturelen = sizeof(signature1);
    sss_mode_t mode = kMode_SSS_Sign;
    uint8_t* tmp;
    // sss_km_asymmetric_context_t* asymmCtx = nullptr;
    sss_km_symmetric_context_t* symmCtx = nullptr;

    if (input->data_length > 2048) {
        km_error = KM_ERROR_INVALID_INPUT_LENGTH;
        goto cleanup;
    }
    poperation = (sss_km_operation_t**)(&operation_handle);
    if (!(*poperation)) {
        km_error = KM_ERROR_INVALID_OPERATION_HANDLE;
        goto cleanup;
    }
    if (input->data == nullptr) {
        ALOGI("data is empty");
    }

    if ((*poperation)->op_type == kOperation_SSS_KM_Asymm) {
        ALOGI("Asymmetric Operation found");
        mode = (*poperation)->op_handle.op_asymm.asymm_ctx.mode;
        km_error = utils_->process_asymmetric_operation(*poperation, input, signature, signature1,
                                                        &signaturelen);
    } else if ((*poperation)->op_type == kOperation_SSS_KM_Symm) {
        ALOGI("Symmetric Operation found");
        symmCtx = &((*poperation)->op_handle.op_symm);
        if (symmCtx->block_mode == KM_MODE_GCM) {
            mode = symmCtx->aead_ctx.mode;
            // memcpy(&signature1[0], output->data, output->data_length);
            // signaturelen = output->data_length;
        } else {
            mode = symmCtx->symm_ctx.mode;
        }

        km_error = utils_->process_symmetric_operation(*poperation, &finish_params, input,
                                                       signature1, &signaturelen);
    } else if ((*poperation)->op_type == kOperation_SSS_KM_Mac) {
        ALOGI("Mac Operation found");
        mode = (*poperation)->op_handle.op_mac.mac_ctx.mode;
        // algorithm = (*poperation)->op_handle.op_mac.mac_ctx.algorithm;
        km_error =
            utils_->process_mac_operation(*poperation, input, signature, signature1, &signaturelen);
    } else {
        km_error = KM_ERROR_INVALID_OPERATION_HANDLE;
        goto cleanup;
    }

    if (km_error != KM_ERROR_OK)
        goto cleanup;

    if (mode != kMode_SSS_Verify && mode != kMode_SSS_Mac_Validate) {
        // ALOGI("final signaturelen : %zu", signaturelen);
        output->data_length = signaturelen;
        tmp =
            /*reinterpret_cast<uint8_t*>*/ (uint8_t*)(malloc(/*output->data_length*/ signaturelen));
        if (!tmp) {
            km_error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
            goto cleanup;
        }
        memcpy(tmp, &signature1, signaturelen);
        output->data = tmp;
        km_error = KM_ERROR_OK;
    }
    out_params = nullptr;
    params = nullptr;

cleanup:
    return km_error;
}

/* static */
keymaster_error_t Se050KeymasterDevice::abort(const keymaster2_device_t* dev,
                                              keymaster_operation_handle_t operation_handle) {
    ALOGI("%s function called ", __func__);

    if (!dev)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!convert_device(dev)->configured())
        return KM_ERROR_KEYMASTER_NOT_CONFIGURED;
    size_t buffer_size = 0;
    sss_km_operation_t** poperation = (sss_km_operation_t**)(&operation_handle);

    if (!(*poperation))
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    if (!(*poperation)->op_handle.op_asymm.asymm_ctx.keyObject &&
        !(*poperation)->op_handle.op_symm.symm_ctx.keyObject)
        return KM_ERROR_INVALID_OPERATION_HANDLE;

    if ((*poperation)->op_type == kOperation_SSS_KM_Asymm) {
        if (((*poperation)->op_handle.op_asymm.asymm_ctx.keyObject->cipherType ==
             kSSS_CipherType_RSA) ||
            ((*poperation)->op_handle.op_asymm.asymm_ctx.keyObject->cipherType ==
             kSSS_CipherType_RSA_CRT)) {
            buffer_size = (*poperation)->op_handle.op_asymm.update_rsa_buf.available_read();
            if (buffer_size) {
                (*poperation)->op_handle.op_asymm.update_rsa_buf.Clear();
            }
        } else if ((*poperation)->op_handle.op_asymm.asymm_ctx.keyObject->cipherType ==
                   kSSS_CipherType_EC_NIST_P) {
            buffer_size = (*poperation)->op_handle.op_asymm.update_ec_buf.available_read();
            if (buffer_size) {
                (*poperation)->op_handle.op_asymm.update_ec_buf.Clear();
            }
        }

        free((*poperation)->op_handle.op_asymm.asymm_ctx.keyObject);
        sss_asymmetric_context_free(&((*poperation)->op_handle.op_asymm.asymm_ctx));
        free((*poperation));
    } else if ((*poperation)->op_type == kOperation_SSS_KM_Symm) {
        free((*poperation)->op_handle.op_symm.symm_ctx.keyObject);
        sss_symmetric_context_free(&((*poperation)->op_handle.op_symm.symm_ctx));
        free((*poperation));
    } else if ((*poperation)->op_type == kOperation_SSS_KM_Mac) {
        free((*poperation)->op_handle.op_mac.mac_ctx.keyObject);
        sss_mac_context_free(&((*poperation)->op_handle.op_mac.mac_ctx));
        free((*poperation));
    }

    return KM_ERROR_OK;
}

/* static */
void Se050KeymasterDevice::StoreDefaultNewKeyParams(keymaster_algorithm_t algorithm,
                                                    AuthorizationSet* auth_set) {
    ALOGI("StoreDefaultNewKeyParams function called ");
    auth_set->push_back(TAG_PURPOSE, KM_PURPOSE_SIGN);
    auth_set->push_back(TAG_PURPOSE, KM_PURPOSE_VERIFY);
    auth_set->push_back(TAG_ALL_USERS);
    auth_set->push_back(TAG_NO_AUTH_REQUIRED);

    // All digests.
    auth_set->push_back(TAG_DIGEST, KM_DIGEST_NONE);
    auth_set->push_back(TAG_DIGEST, KM_DIGEST_MD5);
    auth_set->push_back(TAG_DIGEST, KM_DIGEST_SHA1);
    auth_set->push_back(TAG_DIGEST, KM_DIGEST_SHA_2_224);
    auth_set->push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
    auth_set->push_back(TAG_DIGEST, KM_DIGEST_SHA_2_384);
    auth_set->push_back(TAG_DIGEST, KM_DIGEST_SHA_2_512);

    if (algorithm == KM_ALGORITHM_RSA) {
        auth_set->push_back(TAG_PURPOSE, KM_PURPOSE_ENCRYPT);
        auth_set->push_back(TAG_PURPOSE, KM_PURPOSE_DECRYPT);
        auth_set->push_back(TAG_PADDING, KM_PAD_NONE);
        auth_set->push_back(TAG_PADDING, KM_PAD_RSA_PKCS1_1_5_SIGN);
        auth_set->push_back(TAG_PADDING, KM_PAD_RSA_PKCS1_1_5_ENCRYPT);
        auth_set->push_back(TAG_PADDING, KM_PAD_RSA_PSS);
        auth_set->push_back(TAG_PADDING, KM_PAD_RSA_OAEP);
    }
}
}  // namespace keymaster
