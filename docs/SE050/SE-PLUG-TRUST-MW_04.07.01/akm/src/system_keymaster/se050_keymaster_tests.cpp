/*
 * Copyright (C) 2014 The Android Open Source Project
 * Copyright 2019 NXP
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

#include <dirent.h>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

#include <keymaster/keymaster_context.h>

#include "android_keymaster_test_utils.h"
#include "attestation_record.h"

#include "openssl_err.h"
#include "openssl_utils.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <keymaster/keymaster_context.h>

#include "hardware/keymaster_defs.h"
#include "keymaster/authorization_set.h"
#include "keymaster/se050_keymaster_device.h"
#include <keymaster/keymaster_configuration.h>

#include "../../fsl_sss_ftr.h"
#include "keymaster/se050_keymaster_testutils.h"

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#define TEST_FOLDER "/data/vendor/secure_iot"
#endif

#define GTEST_COUT std::cerr << "[ WARNING  ] "

using std::copy_if;
using std::find_if;
using std::is_permutation;
using std::ostream;
using std::string;
using std::vector;

std::ostream& operator<<(std::ostream& os, const keymaster_key_param_t& param) {
    os << "Tag: " << keymaster::StringifyTag(param.tag);
    switch (keymaster_tag_get_type(param.tag)) {
    case KM_INVALID:
        os << " Invalid";
        break;
    case KM_UINT_REP:
        os << " (Rep)";
    /* Falls through */
    case KM_UINT:
        os << " Int: " << param.integer;
        break;
    case KM_ENUM_REP:
        os << " (Rep)";
    /* Falls through */
    case KM_ENUM:
        os << " Enum: " << param.enumerated;
        break;
    case KM_ULONG_REP:
        os << " (Rep)";
    /* Falls through */
    case KM_ULONG:
        os << " Long: " << param.long_integer;
        break;
    case KM_DATE:
        os << " Date: " << param.date_time;
        break;
    case KM_BOOL:
        os << " Bool: " << param.boolean;
        break;
    case KM_BIGNUM:
        os << " Bignum: ";
        if (!param.blob.data)
            os << "(null)";
        else
            for (size_t i = 0; i < param.blob.data_length; ++i)
                os << std::hex << std::setw(2) << static_cast<int>(param.blob.data[i]) << std::dec;
        break;
    case KM_BYTES:
        os << " Bytes: ";
        if (!param.blob.data)
            os << "(null)";
        else
            for (size_t i = 0; i < param.blob.data_length; ++i)
                os << std::hex << std::setw(2) << static_cast<int>(param.blob.data[i]) << std::dec;
        break;
    }
    return os;
}

bool operator==(const keymaster_key_param_t& a, const keymaster_key_param_t& b) {
    if (a.tag != b.tag) {
        return false;
    }

    switch (keymaster_tag_get_type(a.tag)) {
    case KM_INVALID:
        return true;
    case KM_UINT_REP:
    case KM_UINT:
        return a.integer == b.integer;
    case KM_ENUM_REP:
    case KM_ENUM:
        return a.enumerated == b.enumerated;
    case KM_ULONG:
    case KM_ULONG_REP:
        return a.long_integer == b.long_integer;
    case KM_DATE:
        return a.date_time == b.date_time;
    case KM_BOOL:
        return a.boolean == b.boolean;
    case KM_BIGNUM:
    case KM_BYTES:
        if ((a.blob.data == NULL || b.blob.data == NULL) && a.blob.data != b.blob.data)
            return false;
        return a.blob.data_length == b.blob.data_length &&
               (memcmp(a.blob.data, b.blob.data, a.blob.data_length) == 0);
    }

    return false;
}

namespace keymaster {

bool operator==(const AuthorizationSet& a, const AuthorizationSet& b) {
    if (a.size() != b.size())
        return false;

    for (size_t i = 0; i < a.size(); ++i)
        if (!(a[i] == b[i]))
            return false;
    return true;
}

bool operator!=(const AuthorizationSet& a, const AuthorizationSet& b) {
    return !(a == b);
}

std::ostream& operator<<(std::ostream& os, const AuthorizationSet& set) {
    if (set.size() == 0)
        os << "(Empty)" << std::endl;
    else {
        os << "\n";
        for (size_t i = 0; i < set.size(); ++i)
            os << set[i] << std::endl;
    }
    return os;
}

namespace test {

X509* parse_cert_blob(const keymaster_blob_t& blob) {
    const uint8_t* p = blob.data;
    return d2i_X509(nullptr, &p, blob.data_length);
}

bool verify_chain(const keymaster_cert_chain_t& chain) {
    for (size_t i = 0; i < chain.entry_count - 1; ++i) {
        keymaster_blob_t& key_cert_blob = chain.entries[i];
        keymaster_blob_t& signing_cert_blob = chain.entries[i + 1];

        X509_Ptr key_cert(parse_cert_blob(key_cert_blob));
        X509_Ptr signing_cert(parse_cert_blob(signing_cert_blob));
        EXPECT_TRUE(!!key_cert.get() && !!signing_cert.get());
        if (!key_cert.get() || !signing_cert.get())
            return false;

        EVP_PKEY_Ptr signing_pubkey(X509_get_pubkey(signing_cert.get()));
        EXPECT_TRUE(!!signing_pubkey.get());
        if (!signing_pubkey.get())
            return false;

        EXPECT_EQ(1, X509_verify(key_cert.get(), signing_pubkey.get()))
            << "Verification of certificate " << i << " failed";
    }

    return true;
}

// Extract attestation record from cert. Returned object is still part of cert; don't free it
// separately.
ASN1_OCTET_STRING* get_attestation_record(X509* certificate) {
    ASN1_OBJECT_Ptr oid(OBJ_txt2obj(kAttestionRecordOid, 1 /* dotted string format */));
    EXPECT_TRUE(!!oid.get());
    if (!oid.get())
        return nullptr;

    int location = X509_get_ext_by_OBJ(certificate, oid.get(), -1 /* search from beginning */);
    EXPECT_NE(-1, location);
    if (location == -1)
        return nullptr;

    X509_EXTENSION* attest_rec_ext = X509_get_ext(certificate, location);
    EXPECT_TRUE(!!attest_rec_ext);
    if (!attest_rec_ext)
        return nullptr;

    ASN1_OCTET_STRING* attest_rec = X509_EXTENSION_get_data(attest_rec_ext);
    EXPECT_TRUE(!!attest_rec);
    return attest_rec;
}

bool verify_attestation_record(uint8_t* challenge, size_t len,
                               AuthorizationSet expected_sw_enforced,
                               AuthorizationSet expected_tee_enforced,
                               uint32_t expected_keymaster_version,
                               keymaster_security_level_t expected_keymaster_security_level,
                               const keymaster_blob_t& attestation_cert) {

    X509_Ptr cert(parse_cert_blob(attestation_cert));
    EXPECT_TRUE(!!cert.get());
    if (!cert.get())
        return false;

    ASN1_OCTET_STRING* attest_rec = get_attestation_record(cert.get());
    EXPECT_TRUE(!!attest_rec);
    if (!attest_rec)
        return false;

    AuthorizationSet att_sw_enforced;
    AuthorizationSet att_tee_enforced;
    uint32_t att_attestation_version;
    uint32_t att_keymaster_version;
    keymaster_security_level_t att_attestation_security_level;
    keymaster_security_level_t att_keymaster_security_level;
    keymaster_blob_t att_challenge = {};
    keymaster_blob_t att_unique_id = {};

    EXPECT_EQ(KM_ERROR_OK, parse_attestation_record(
                               attest_rec->data, attest_rec->length, &att_attestation_version,
                               &att_attestation_security_level, &att_keymaster_version,
                               &att_keymaster_security_level, &att_challenge, &att_sw_enforced,
                               &att_tee_enforced, &att_unique_id));

    EXPECT_EQ(2U, att_attestation_version);
    EXPECT_EQ(KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT, att_attestation_security_level);
    EXPECT_EQ(expected_keymaster_version, att_keymaster_version);
    EXPECT_EQ(expected_keymaster_security_level, att_keymaster_security_level);

    EXPECT_EQ(len, att_challenge.data_length);
    if (!att_challenge.data) {
        return false;
    }
    EXPECT_EQ(0, memcmp(challenge, att_challenge.data, len));

    // Add TAG_USER_ID to the relevant attestation list, because user IDs are not included in
    // attestations, since they're meaningless off-device.
    uint32_t user_id;
    if (expected_sw_enforced.GetTagValue(TAG_USER_ID, &user_id))
        att_sw_enforced.push_back(TAG_USER_ID, user_id);
    if (expected_tee_enforced.GetTagValue(TAG_USER_ID, &user_id))
        att_tee_enforced.push_back(TAG_USER_ID, user_id);

    // Add TAG_INCLUDE_UNIQUE_ID to the relevant attestation list, because that tag is not included
    // in the attestation.
    if (expected_sw_enforced.GetTagValue(TAG_INCLUDE_UNIQUE_ID))
        att_sw_enforced.push_back(TAG_INCLUDE_UNIQUE_ID);
    if (expected_tee_enforced.GetTagValue(TAG_INCLUDE_UNIQUE_ID))
        att_tee_enforced.push_back(TAG_INCLUDE_UNIQUE_ID);

    att_sw_enforced.Sort();
    expected_sw_enforced.Sort();
    EXPECT_EQ(expected_sw_enforced, att_sw_enforced);

    att_tee_enforced.Sort();
    expected_tee_enforced.Sort();
    EXPECT_EQ(expected_tee_enforced, att_tee_enforced);

    delete[] att_challenge.data;
    delete[] att_unique_id.data;

    return true;
}

std::ostream& operator<<(std::ostream& os, const InstanceCreatorPtr& instance_creator) {
    return os << instance_creator->name();
}

class KeymasterHALTest : public ::testing::Test {
  private:
    void mbedtls_keymaster_reset() {
        DIR* theFolder = opendir(TEST_FOLDER);
        struct dirent* next_file;
        char filepath[256];

        while ((next_file = readdir(theFolder)) != NULL) {
            // build the path for each file in the folder
            sprintf(filepath, "%s/%s", TEST_FOLDER, next_file->d_name);
            if (!strncmp("sss_", next_file->d_name, 4))
                if (!remove(filepath))
                    continue;
        }
        closedir(theFolder);
    }

  protected:
    Se050KeymasterDevice* mydevice = NULL;
    keymaster2_device_t* newdev2 = NULL;
    KeymasterHALTest() {}

    virtual ~KeymasterHALTest() {}

    virtual void SetUp() {
        mydevice = new Se050KeymasterDevice();
        newdev2 = mydevice->keymaster2_device();
    }

    virtual void TearDown() {
#if SSS_HAVE_APPLET_SE05X_IOT
        newdev2->delete_key(newdev2, &myBlob_);
        newdev2->delete_all_keys(newdev2);
#elif SSS_HAVE_HOSTCRYPTO_MBEDTLS
        mbedtls_keymaster_reset();
#endif
        if (mydevice)
            delete mydevice;
    }
    keymaster_key_blob_t myBlob_;
    keymaster_operation_handle_t op_handle_;
};

class KeymasterUpgradeKeyTest : public ::testing::Test {
  private:
    void mbedtls_keymaster_reset() {
        DIR* theFolder = opendir(TEST_FOLDER);
        struct dirent* next_file;
        char filepath[256];

        while ((next_file = readdir(theFolder)) != NULL) {
            // build the path for each file in the folder
            sprintf(filepath, "%s/%s", TEST_FOLDER, next_file->d_name);
            if (!strncmp("sss_", next_file->d_name, 4))
                if (!remove(filepath))
                    continue;
        }
        closedir(theFolder);
    }

  protected:
    Se050KeymasterDevice* mydevice = NULL;
    keymaster2_device_t* newdev2 = NULL;
    SoftKeymasterContext* context;
    KeymasterUpgradeKeyTest() {}

    virtual ~KeymasterUpgradeKeyTest() {}

    virtual void SetUp() {
        context = new SoftKeymasterContext();
        mydevice = new Se050KeymasterDevice(context);
        newdev2 = mydevice->keymaster2_device();
    }

    virtual void TearDown() {
#if SSS_HAVE_APPLET_SE05X_IOT
        newdev2->delete_key(newdev2, &myBlob_);
        newdev2->delete_all_keys(newdev2);
#elif SSS_HAVE_HOSTCRYPTO_MBEDTLS
        mbedtls_keymaster_reset();
#endif
        if (mydevice)
            delete mydevice;
    }
    keymaster_key_blob_t myBlob_;
    keymaster_operation_handle_t op_handle_;
};

class keymasterInjectTest : public ::testing::Test {
  private:
    void mbedtls_keymaster_reset() {
        DIR* theFolder = opendir(TEST_FOLDER);
        struct dirent* next_file;
        char filepath[256];

        while ((next_file = readdir(theFolder)) != NULL) {
            // build the path for each file in the folder
            sprintf(filepath, "%s/%s", TEST_FOLDER, next_file->d_name);
            if (!strncmp("sss_", next_file->d_name, 4))
                if (!remove(filepath))
                    continue;
        }
        closedir(theFolder);
    }

  protected:
    Se050KeymasterDevice* mydevice = NULL;
    keymaster2_device_t* newdev2 = NULL;
    keymasterInjectTest() {}

    virtual ~keymasterInjectTest() {}

    virtual void SetUp() {
        mydevice = new Se050KeymasterDevice();
        newdev2 = mydevice->keymaster2_device();
    }

    virtual void TearDown() {
#if SSS_HAVE_APPLET_SE05X_IOT
        // newdev2->delete_key(newdev2, &myBlob_);
        // newdev2->delete_all_keys(newdev2);
#elif SSS_HAVE_HOSTCRYPTO_MBEDTLS
        mbedtls_keymaster_reset();
#endif
        if (mydevice)
            delete mydevice;
    }
    keymaster_key_blob_t myBlob_;
    keymaster_operation_handle_t op_handle_;
};

typedef KeymasterHALTest Se050KeyGeneration;

/*
 *Generate ECC 224-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyGeneration, EC224) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x23, 0x10, 0x24, 0x20};  //{0x32,0x09,0x42,0x02};
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(224)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
}

/*
 *Generate ECC 256-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyGeneration, EC256) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x32, 0x09, 0x42, 0x02};  //{0x32,0x09,0x42,0x02};
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
}

/*
 *Generate ECC 384-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyGeneration, EC384) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x82, 0x39, 0x42, 0x02};  // 0x82394202;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(384)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
}

/*
 *Generate ECC 521-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyGeneration, EC521) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x82, 0x00, 0x42, 0x02};  // 0x82394202;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(521)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
}

/*
 *Generate RSA 1024-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyGeneration, RSA1024) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x32, 0x01, 0x14, 0x02};  // 0x32011402;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(1024, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    }
}

/*
 *Generate RSA 2048-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyGeneration, RSA2048) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x32, 0x89, 0x23, 0x02};  //(uint8_t)0x32892302;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
}

/*
 *Generate RSA 3072-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyGeneration, RSA3072) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x32, 0x89, 0x23, 0x02};  //(uint8_t)0x32892302;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(3072, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
}

/*
 *Generate RSA 4096-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyGeneration, RSA4096) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x10, 0x49, 0x42, 0x02};  //(uint8_t)0x10494202;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(4096, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    }
}

typedef KeymasterHALTest Se050KeyCharacteristics;
/*
 *use get_key_characteristics to retrieve key characterisitcs of generated key.
 * */
TEST_F(Se050KeyCharacteristics, getKeyCharacteristics) {
    keymaster_key_characteristics_t generatedKeyCharc;
    keymaster_key_characteristics_t retrievedKeyCharc;

    const uint8_t id[] = {0x10, 0x67, 0x42, 0x35};
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &generatedKeyCharc));
    AuthorizationSet gen_sw(generatedKeyCharc.sw_enforced);
    AuthorizationSet gen_hw(generatedKeyCharc.hw_enforced);
    ASSERT_EQ(KM_ERROR_OK, newdev2->get_key_characteristics(newdev2, &myBlob_, NULL /*client id*/,
                                                            NULL /*app data*/, &retrievedKeyCharc));
    AuthorizationSet retrieve_sw(retrievedKeyCharc.sw_enforced);
    AuthorizationSet retrieve_hw(retrievedKeyCharc.hw_enforced);
    EXPECT_EQ(gen_sw, retrieve_sw);
}

typedef KeymasterHALTest Se050KeyExport;
/*
 *Generate ECC 224-bit keypair in SE050
 *Get public key from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyExport, EC224) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x73, 0x48, 0x38, 0x41};  //(uint8_t) {0x73,0x48,0x38,0x41};

    keymaster_key_format_t export_format = KM_KEY_FORMAT_X509;
    keymaster_blob_t *client_id = nullptr, export_data, *app_data = nullptr;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(224)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_OK, newdev2->export_key(newdev2, export_format, &myBlob_, client_id,
                                               app_data, &export_data));
}

/*
 *Generate ECC 256-bit keypair in SE050
 *Get public key from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyExport, EC256) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x73, 0x48, 0x38, 0x41};  //(uint8_t) {0x73,0x48,0x38,0x41};

    keymaster_key_format_t export_format = KM_KEY_FORMAT_X509;
    keymaster_blob_t *client_id = nullptr, export_data, *app_data = nullptr;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_OK, newdev2->export_key(newdev2, export_format, &myBlob_, client_id,
                                               app_data, &export_data));
}

/*
 *Generate ECC 384-bit keypair in SE050
 *Get public key from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyExport, EC384) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x00, 0x11, 0x25, 0x48};  // (uint8_t) 0x00112548;

    keymaster_key_format_t export_format = KM_KEY_FORMAT_X509;
    keymaster_blob_t *client_id = nullptr, export_data, *app_data = nullptr;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(384)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_OK, newdev2->export_key(newdev2, export_format, &myBlob_, client_id,
                                               app_data, &export_data));
}

/*
 *Generate ECC 521-bit keypair in SE050
 *Get public key from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyExport, EC521) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x99, 0x11, 0x25, 0x48};  // (uint8_t) 0x00112548;

    keymaster_key_format_t export_format = KM_KEY_FORMAT_X509;
    keymaster_blob_t *client_id = nullptr, export_data, *app_data = nullptr;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(521)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_OK, newdev2->export_key(newdev2, export_format, &myBlob_, client_id,
                                               app_data, &export_data));
}

/*
 *Generate RSA 1024-bit keypair in SE050
 *Get public key from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyExport, RSA1024) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x01, 0x10, 0x41, 0x42};  // (uint8_t) 0x01104142;

    keymaster_key_format_t export_format = KM_KEY_FORMAT_X509;
    keymaster_blob_t *client_id = nullptr, export_data, *app_data = nullptr;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(1024, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        ASSERT_EQ(KM_ERROR_OK, newdev2->export_key(newdev2, export_format, &myBlob_, client_id,
                                                   app_data, &export_data));
    }
}

/*
 *Generate RSA 2048-bit keypair in SE050
 *Get public key from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyExport, RSA2048) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x01, 0x10, 0x42, 0x41};  // (uint8_t) 0x01104142;

    keymaster_key_format_t export_format = KM_KEY_FORMAT_X509;
    keymaster_blob_t *client_id = nullptr, export_data, *app_data = nullptr;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_OK, newdev2->export_key(newdev2, export_format, &myBlob_, client_id,
                                               app_data, &export_data));
}

/*
 *Generate RSA 3072-bit keypair in SE050
 *Get public key from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyExport, RSA3072) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x01, 0x10, 0x42, 0x41};  // (uint8_t) 0x01104142;

    keymaster_key_format_t export_format = KM_KEY_FORMAT_X509;
    keymaster_blob_t *client_id = nullptr, export_data, *app_data = nullptr;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(3072, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_OK, newdev2->export_key(newdev2, export_format, &myBlob_, client_id,
                                               app_data, &export_data));
}

/*
 *Generate RSA 4096-bit keypair in SE050
 *Get public key from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyExport, RSA4096) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x41, 0x42, 0x01, 0x10};  // (uint8_t) 0x01104142;

    keymaster_key_format_t export_format = KM_KEY_FORMAT_X509;
    keymaster_blob_t *client_id = nullptr, export_data, *app_data = nullptr;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(4096, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        ASSERT_EQ(KM_ERROR_OK, newdev2->export_key(newdev2, export_format, &myBlob_, client_id,
                                                   app_data, &export_data));
    }
}

typedef KeymasterHALTest Se050KeyDelete;
/*
 *Generate ECC 224-bit keypair in SE050
 *Delete keyobject from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyDelete, EC224) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x43, 0x89, 0x22};  // (uint8_t) {0x38,0x43,0x89,0x22};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(224)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_OK, newdev2->delete_key(newdev2, &myBlob_));
}

/*
 *Generate ECC 256-bit keypair in SE050
 *Delete keyobject from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyDelete, EC256) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x43, 0x89, 0x22};  // (uint8_t) {0x38,0x43,0x89,0x22};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_OK, newdev2->delete_key(newdev2, &myBlob_));
}

/*
 *Generate ECC 384-bit keypair in SE050
 *Delete keyobject from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyDelete, EC384) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x58, 0x89, 0x22};  // (uint8_t) {0x38,0x58,0x89,0x22};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(384)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_OK, newdev2->delete_key(newdev2, &myBlob_));
}

/*
 *Generate ECC 521-bit keypair in SE050
 *Delete keyobject from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyDelete, EC521) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x08, 0x85, 0x23};  // (uint8_t) {0x38,0x58,0x89,0x22};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(521)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_OK, newdev2->delete_key(newdev2, &myBlob_));
}

/*
 *Generate RSA 1024-bit keypair in SE050
 *Delete keyobject from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyDelete, RSA1024) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x43, 0x99, 0x22};  // (uint8_t) {0x38,0x43,0x99,0x22};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(1024, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        ASSERT_EQ(KM_ERROR_OK, newdev2->delete_key(newdev2, &myBlob_));
    }
}

/*
 *Generate RSA 2048-bit keypair in SE050
 *Delete keyobject from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyDelete, RSA2048) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x43, 0x89, 0x67};  // (uint8_t) {0x38,0x43,0x89,0x22};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_OK, newdev2->delete_key(newdev2, &myBlob_));
}

/*
 *Generate RSA 3072-bit keypair in SE050
 *Delete keyobject from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyDelete, RSA3072) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x43, 0x89, 0x67};  // (uint8_t) {0x38,0x43,0x89,0x22};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(3072, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_OK, newdev2->delete_key(newdev2, &myBlob_));
}

/*
 *Generate RSA 4096-bit keypair in SE050
 *Delete keyobject from SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyDelete, RSA4096) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x43, 0x89, 0x43};  // (uint8_t) {0x38,0x43,0x89,0x43};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(4096, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        ASSERT_EQ(KM_ERROR_OK, newdev2->delete_key(newdev2, &myBlob_));
    }
}

typedef KeymasterHALTest Se050KeyImport;
/*
 *Inject ECC 224-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyImport, EC224) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = ECC_PAIR_224_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id[] = {0x73, 0x48, 0x34, 0x80};  // (uint8_t) {0x73,0x48,0x34,0x80};

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(224)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
}

/*
 *Inject ECC 256-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyImport, EC256) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = ECC_PAIR_256_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id[] = {0x73, 0x48, 0x34, 0x80};  // (uint8_t) {0x73,0x48,0x34,0x80};

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
}

/*
 *Inject ECC 384-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyImport, EC384) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = ECC_PAIR_384_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id[] = {0x73, 0x48, 0x43, 0x89};  //(uint8_t) 0x73484389;

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(384)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
}

/*
 *Inject ECC 521-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyImport, EC521) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = ECC_PAIR_521_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id[] = {0x73, 0x48, 0x43, 0x89};  //(uint8_t) 0x73484389;

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(521)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
}

/*
 *Inject RSA 1024-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyImport, RSA1024) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = RSA_PAIR_1024_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id[] = {0x73, 0x91, 0x84, 0x80};

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(1024, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
    } else {
        ASSERT_EQ(KM_ERROR_OK,
                  newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
    }
}

/*
 *Inject RSA 2048-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyImport, RSA2048) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = RSA_PAIR_2048_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id[] = {0x24, 0x83, 0x48, 0x72};

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
}

/*
 *Inject RSA 3072-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyImport, RSA3072) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = RSA_PAIR_3072_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id[] = {0x24, 0x38, 0x44, 0x72};

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(3072, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
}

/*
 *Inject RSA 4096-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyImport, RSA4096) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = RSA_PAIR_4096_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    //  keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();
    const uint8_t id[] = {0x43, 0x23, 0x48, 0x80};

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(4096, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
}

/*
 *Inject AES 128-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyImport, AES128) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_RAW;
    const uint8_t set_data[] = AES_128_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id[] = {0x90, 0x21, 0x34, 0x90};

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .AesEncryptionKey(128)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
}

/*
 *Inject AES GCM 128-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyImport, AES128_GCM) {
#if SSS_HAVE_SE05X_VER_GTE_07_02
    keymaster_key_format_t key_format = KM_KEY_FORMAT_RAW;

    const uint8_t set_data[] = AES_128_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id[] = {0x90, 0x21, 0x34, 0x90};

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .AesEncryptionKey(128)
                                .Authorization(TAG_BLOCK_MODE, KM_MODE_GCM)
                                .Authorization(TAG_PADDING, KM_PAD_NONE)
                                .Authorization(TAG_CALLER_NONCE)
                                .Authorization(TAG_MAC_LENGTH, 128)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
#else
    GTEST_COUT << " AES GCM feature is not supported for SE050 " << std::endl;
#endif
}

/*
 *Inject HMAC 256-bit keypair in SE050
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyImport, HMAC256) {
    // sss_status_t status;
    /* clang-format off */
    const uint8_t id[] = {0xaf, 0xb4, 0x5c, 0xc0};
    const uint8_t key[32] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33 };

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&key[0];
    key_data.data_length = sizeof(key);
    keymaster_key_characteristics_t myChar;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .HmacKey(256)
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_MIN_MAC_LENGTH, 128)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
}
/*
 * Following Test cases are commented because currently we do not have the
 * support to create a certificate. Refer to
 * https://source.android.com/security/keystore/attestation for how attestation is to be done.
 * */

#if 0
TEST_F(Se050Test, sign_EC256){
  keymaster_key_characteristics_t myKeyCharac;

  const uint8_t id[]={0x32, 0x09, 0x99, 0x02};
  const uint8_t data_to_be_signed[32] = "Random Data to be signed";
  const uint8_t application_id[32] = "Unique Application ID";
  keymaster_cert_chain_t signature;



  AuthorizationSet
params(AuthorizationSetBuilder().Authorization(TAG_INCLUDE_UNIQUE_ID).Authorization(TAG_UNIQUE_ID,
id, sizeof(id)).EcdsaSigningKey(256).Digest(KM_DIGEST_NONE).build()); ASSERT_EQ(KM_ERROR_OK,
ConfigureDevice(newdev2)); ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_,
&myKeyCharac));

  AuthorizationSet attest_params(AuthorizationSetBuilder().Authorization(TAG_ATTESTATION_CHALLENGE,
data_to_be_signed, sizeof(data_to_be_signed)).Authorization(TAG_ATTESTATION_APPLICATION_ID,
application_id, sizeof(application_id)).Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
  ASSERT_EQ(KM_ERROR_OK, newdev2->attest_key(newdev2, &myBlob_, &attest_params, &signature));

}

TEST_F(Se050Test, sign_EC384){
  keymaster_key_characteristics_t myKeyCharac;

  const uint8_t id[]={0x44, 0x59, 0x55, 0x60};
  const uint8_t data_to_be_signed[32] = "Random Data to be signed";
  const uint8_t application_id[32] = "Unique Application ID";
  keymaster_cert_chain_t signature;



  AuthorizationSet
params(AuthorizationSetBuilder().Authorization(TAG_INCLUDE_UNIQUE_ID).Authorization(TAG_UNIQUE_ID,
id, sizeof(id)).EcdsaSigningKey(384).Digest(KM_DIGEST_NONE).build()); ASSERT_EQ(KM_ERROR_OK,
ConfigureDevice(newdev2)); ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_,
&myKeyCharac));

  AuthorizationSet attest_params(AuthorizationSetBuilder().Authorization(TAG_ATTESTATION_CHALLENGE,
data_to_be_signed, sizeof(data_to_be_signed)).Authorization(TAG_ATTESTATION_APPLICATION_ID,
application_id, sizeof(application_id)).Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
  ASSERT_EQ(KM_ERROR_OK, newdev2->attest_key(newdev2, &myBlob_, &attest_params, &signature));

}

TEST_F(Se050Test, sign_EC521){
  keymaster_key_characteristics_t myKeyCharac;

  const uint8_t id[]={0x00, 0x55, 0x55, 0x60};
  const uint8_t data_to_be_signed[32] = "Random Data to be signed";
  const uint8_t application_id[32] = "Unique Application ID";
  keymaster_cert_chain_t signature;



  AuthorizationSet
params(AuthorizationSetBuilder().Authorization(TAG_INCLUDE_UNIQUE_ID).Authorization(TAG_UNIQUE_ID,
id, sizeof(id)).EcdsaSigningKey(521).Digest(KM_DIGEST_NONE).build()); ASSERT_EQ(KM_ERROR_OK,
ConfigureDevice(newdev2)); ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_,
&myKeyCharac));

  AuthorizationSet attest_params(AuthorizationSetBuilder().Authorization(TAG_ATTESTATION_CHALLENGE,
data_to_be_signed, sizeof(data_to_be_signed)).Authorization(TAG_ATTESTATION_APPLICATION_ID,
application_id, sizeof(application_id)).Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
  ASSERT_EQ(KM_ERROR_OK, newdev2->attest_key(newdev2, &myBlob_, &attest_params, &signature));

}
TEST_F(Se050Test, sign_RSA1024){
  keymaster_key_characteristics_t myKeyCharac;

  const uint8_t id[]={0x32, 0x09, 0x99, 0x02};
  const uint8_t data_to_be_signed[32] = "1234567890123456789012345678";
  const uint8_t application_id[32] = "Unique Application ID";
  keymaster_cert_chain_t signature;



  AuthorizationSet
params(AuthorizationSetBuilder().Authorization(TAG_INCLUDE_UNIQUE_ID).Authorization(TAG_UNIQUE_ID,
id, sizeof(id)).RsaSigningKey(1024, 65537).Digest(KM_DIGEST_NONE).build()); ASSERT_EQ(KM_ERROR_OK,
ConfigureDevice(newdev2)); ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_,
&myKeyCharac));

  AuthorizationSet attest_params(AuthorizationSetBuilder().Authorization(TAG_ATTESTATION_CHALLENGE,
data_to_be_signed, sizeof(data_to_be_signed)).Authorization(TAG_ATTESTATION_APPLICATION_ID,
application_id, sizeof(application_id)).Authorization(TAG_DIGEST, KM_DIGEST_NONE));
  ASSERT_EQ(KM_ERROR_OK, newdev2->attest_key(newdev2, &myBlob_, &attest_params, &signature));

}

TEST_F(Se050Test, sign_RSA2048){
  keymaster_key_characteristics_t myKeyCharac;

  const uint8_t id[]={0x32, 0x71, 0x99, 0x00};
  const uint8_t data_to_be_signed[32] = "1234567890123456789012345678";
  const uint8_t application_id[32] = "Unique Application ID";
  keymaster_cert_chain_t signature;



  AuthorizationSet
params(AuthorizationSetBuilder().Authorization(TAG_INCLUDE_UNIQUE_ID).Authorization(TAG_UNIQUE_ID,
id, sizeof(id)).RsaSigningKey(2048, 65537).Digest(KM_DIGEST_NONE).build()); ASSERT_EQ(KM_ERROR_OK,
ConfigureDevice(newdev2)); ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_,
&myKeyCharac));

  AuthorizationSet attest_params(AuthorizationSetBuilder().Authorization(TAG_ATTESTATION_CHALLENGE,
data_to_be_signed, sizeof(data_to_be_signed)).Authorization(TAG_ATTESTATION_APPLICATION_ID,
application_id, sizeof(application_id)).Authorization(TAG_DIGEST, KM_DIGEST_NONE));
  ASSERT_EQ(KM_ERROR_OK, newdev2->attest_key(newdev2, &myBlob_, &attest_params, &signature));

}
#endif

typedef KeymasterUpgradeKeyTest Se050KeyUpgrade;
/*
 *Inject RSA 2048 -bit keypair in SE050
 *Upgrade it with new params and new keypair (RSA-1024)
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050KeyUpgrade, AesVersionUpgrade) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_RAW;
    const uint8_t set_data[] = AES_128_TEST_KEY;
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_purpose_t myPurpose_decrypt = KM_PURPOSE_DECRYPT;
    keymaster_key_param_set_t out_params = {nullptr, 0}, tmp_params = {nullptr, 0};
    keymaster_operation_handle_t op_handle_enc, op_handle_dec;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    // keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();
    const uint8_t id[] = {0x90, 0x21, 0x34, 0x90};
    const uint8_t data_to_be_enc[] = {"Hello World!000"};
    keymaster_blob_t input, signature, encryptedBlob = {nullptr, 0};
    keymaster_blob_t outBlob, decryptedBlob = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_enc;
    input.data_length = sizeof(data_to_be_enc);
    std::string to_be_enc = (char*)input.data;
    keymaster_key_blob_t upgradedBlob;
    keymaster_blob_t client_id_ = {.data = reinterpret_cast<const uint8_t*>("app_id"),
                                   .data_length = 6};
    keymaster_key_characteristics_t myChar;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .AesEncryptionKey(128)
                                .Authorization(TAG_BLOCK_MODE, KM_MODE_ECB)
                                .Authorization(TAG_PADDING, KM_PAD_NONE)
                                .Authorization(TAG_APPLICATION_ID, client_id_.data, client_id_.data_length)
                                .build());
    AuthorizationSet upgrade_params(AuthorizationSetBuilder()
                                .Authorization(TAG_APPLICATION_ID, client_id_.data, client_id_.data_length)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    context->SetSystemVersion(1, 1);

    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &params, &out_params,
                                          &op_handle_enc));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_enc, &tmp_params, &input, &signature,
                                           &out_params, &encryptedBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_decrypt, &myBlob_, &params, &out_params,
                                          &op_handle_dec));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_dec, &tmp_params, &encryptedBlob,
                                           &outBlob, &out_params, &decryptedBlob));
    std::string decrypted;
    if (decryptedBlob.data) {
        decrypted = (char*)decryptedBlob.data;
    } else {
        decrypted = "";
    }
    ASSERT_EQ(to_be_enc, decrypted);

    context->SetSystemVersion(1, 2);

    ASSERT_EQ(KM_ERROR_KEY_REQUIRES_UPGRADE, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &params, &out_params,
                                          &op_handle_enc));
    ASSERT_EQ(KM_ERROR_OK, newdev2->upgrade_key(newdev2, &myBlob_, &upgrade_params, &upgradedBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_decrypt, &upgradedBlob, &params, &out_params,
                                          &op_handle_dec));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_dec, &tmp_params, &encryptedBlob,
                                           &outBlob, &out_params, &decryptedBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_decrypt, &upgradedBlob, &params, &out_params,
                                          &op_handle_dec));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_dec, &tmp_params, &encryptedBlob,
                                           &outBlob, &out_params, &decryptedBlob));
    if (decryptedBlob.data) {
        decrypted = (char*)decryptedBlob.data;
    } else {
        decrypted = "";
    }
    ASSERT_EQ(to_be_enc, decrypted);

    context->SetSystemVersion(1, 1);
    ASSERT_EQ(KM_ERROR_INVALID_KEY_BLOB, newdev2->begin(newdev2, myPurpose_encrypt, &upgradedBlob, &params, &out_params,
                                          &op_handle_enc));
}

typedef KeymasterHALTest Se050SignOperation;

/*
 *Generate ECC 384-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, EC224_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x02, 0x02, 0x23, 0x02};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(224)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    //  keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, data_to_be_signed, sizeof(data_to_be_signed))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->begin(newdev2, myPurpose, &myBlob_, &attest_params, &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Generate ECC 256-bit keypair in SE050
 *Sign some random data with SHA256
 *32-bit Keyid should be unique (required for SE050)
 *VTS expects to calculate the hash first and then sign but we
 *have called sign API directly and it works because
 *of a hack to truncate the data to 32bytes.
 *
 *Artifact #artf638850
 * */
TEST_F(Se050SignOperation, EC256_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x02, 0x32, 0x32, 0x02};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params, tmp_params;

    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    //  keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, data_to_be_signed, sizeof(data_to_be_signed))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->begin(newdev2, myPurpose, &myBlob_, &attest_params, &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Generate ECC 384-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, EC384_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x02, 0x02, 0x23, 0x02};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params, tmp_params;

    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(384)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    //  keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, data_to_be_signed, sizeof(data_to_be_signed))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->begin(newdev2, myPurpose, &myBlob_, &attest_params, &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Generate ECC 521-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, EC521_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x02, 0x02, 0x02, 0x02};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params, tmp_params;

    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(521)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    //  keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, data_to_be_signed, sizeof(data_to_be_signed))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->begin(newdev2, myPurpose, &myBlob_, &attest_params, &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Generate ECC 224-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, EC224_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x75, 0x67, 0x95, 0x67};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    const uint8_t data_to_be_updated[] = "Random Data to be updated";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params, tmp_params;

    keymaster_blob_t outBlob, updateoutBlob = {nullptr, 0};
    keymaster_blob_t input1, input2;
    input1.data = data_to_be_signed;
    input1.data_length = sizeof(data_to_be_signed);
    input2.data = data_to_be_updated;
    input2.data_length = sizeof(data_to_be_updated);
    size_t input_consumed = 0;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(224)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    //  keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, input1.data, input1.data_length)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->begin(newdev2, myPurpose, &myBlob_, &attest_params, &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input1,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input2,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &updateoutBlob,
                                           &signature, &out_params, &outBlob));
}

/*
 *Generate ECC 256-bit keypair in SE050
 *Sign some random data with SHA256
 *32-bit Keyid should be unique (required for SE050)
 *VTS expects to calculate the hash first and then sign but we
 *have called sign API directly and it works because
 *of a hack to truncate the data to 32bytes.
 *
 *Artifact #artf638850
 * */
TEST_F(Se050SignOperation, EC256_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x20, 0x23, 0x33, 0x20};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params, tmp_params;

    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    //  keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, input.data, input.data_length)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->begin(newdev2, myPurpose, &myBlob_, &attest_params, &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input, &input_consumed,
                                           &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Generate ECC 384-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, EC384_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x20, 0x20, 0x32, 0x20};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params, tmp_params;

    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(384)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    //  keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, input.data, input.data_length)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->begin(newdev2, myPurpose, &myBlob_, &attest_params, &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input, &input_consumed,
                                           &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}


/*
 *Generate ECC 521-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, EC521_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x20, 0x20, 0x20, 0x20};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params, tmp_params;

    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(521)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    //  keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, input.data, input.data_length)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->begin(newdev2, myPurpose, &myBlob_, &attest_params, &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input, &input_consumed,
                                           &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}


/*
 *Generate RSA 1024-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, RSA1024_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x19, 0x02, 0x11};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params;//, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(1024, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        AuthorizationSet attest_params(AuthorizationSetBuilder()
                                           .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                           .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input,
                                               &signature, &out_params, &outBlob));
    }
}

/*
 *Generate RSA 2048-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, RSA2048_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x09, 0x07, 0x11};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params;//, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Generate RSA 3072-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, RSA3072_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x33, 0x00, 0x07, 0x11};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params;//, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(3072, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Generate RSA 4096-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, RSA4096_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x32, 0x20, 0x79, 0x19};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params;//, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(4096, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        AuthorizationSet attest_params(AuthorizationSetBuilder()
                                           .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                           .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input,
                                               &signature, &out_params, &outBlob));
    }
}

/*
 *Generate RSA 1024-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, RSA1024_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0xab, 0xcd, 0xef, 0x10};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    const uint8_t* data_to_be_update = (uint8_t*)"RANDOM DATA TO BE UPDATED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params;//, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t updateoutBlob = {nullptr, 0};
    keymaster_blob_t input1 = {nullptr, 0};
    keymaster_blob_t input2 = {nullptr, 0};
    input1.data = data_to_be_signed;
    input1.data_length = sizeof(data_to_be_signed);
    input2.data = data_to_be_update;
    input2.data_length = sizeof(data_to_be_update);
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(1024, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        AuthorizationSet attest_params(AuthorizationSetBuilder()
                                           .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                           .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input1,
                                               &input_consumed, &out_params, &updateoutBlob));
        ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input2,
                                               &input_consumed, &out_params, &updateoutBlob));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &updateoutBlob,
                                               &signature, &out_params, &outBlob));
    }
}

/*
 *Generate RSA 2048-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, RSA2048_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x95, 0x67, 0x95, 0x67};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params;//, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Generate RSA 3072-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, RSA3072_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0xab, 0xcd, 0xde, 0xf0};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params;//, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(3072, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Generate RSA 4096-bit keypair in SE050
 *Perform sign operation on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, RSA4096_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0xaa, 0xcd, 0xde, 0x0d};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params;//, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(4096, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        AuthorizationSet attest_params(AuthorizationSetBuilder()
                                           .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                           .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                               &input_consumed, &out_params, &outBlob));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input,
                                               &signature, &out_params, &outBlob));
    }
}

/*
 *Generate HMAC 256-bit keypair in SE050
 *Perform sign operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, HMAC_begin_finish)
{
    const uint8_t id[] = {0xff, 0x44, 0xcc, 0xc4};
    const uint8_t srcData[] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33 };
    const uint8_t key[32] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33 };

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&key;
    key_data.data_length = sizeof(key);
    keymaster_key_characteristics_t myChar;
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_blob_t input ;
    input.data = (const uint8_t*)&srcData;
    input.data_length = sizeof(srcData);
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t signature = {nullptr, 0};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .HmacKey(256)
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_MIN_MAC_LENGTH, 256)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_MIN_MAC_LENGTH, 160)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                       .Authorization(TAG_MAC_LENGTH, 256));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Generate HMAC 256-bit keypair in SE050
 *Perform sign operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050SignOperation, HMAC_begin_update_finish)
{
    const uint8_t id[] = {0xaf, 0xb4, 0x5c, 0xc4};
    const uint8_t srcData[] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33 };
    const uint8_t key[32] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33 };

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&key;
    key_data.data_length = sizeof(key);
    keymaster_key_characteristics_t myChar;
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_blob_t input ;
    input.data = (const uint8_t*)&srcData;
    input.data_length = sizeof(srcData);
    size_t input_consumed = 0;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t signature = {nullptr, 0};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .HmacKey(256)
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_MIN_MAC_LENGTH, 256)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_MIN_MAC_LENGTH, 160)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                       .Authorization(TAG_MAC_LENGTH, 256));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input,
                                           &input_consumed, &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}

typedef KeymasterHALTest Se050VerifyOperation;

/*
 *Generate ECC 384-bit keypair in SE050
 *Perform sign and verify operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, EC224_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x88, 0x9f, 0x8a, 0x01};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(224)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, data_to_be_signed, sizeof(data_to_be_signed))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &outBlob,
                                           &out_params, &outBlob));
}

/*
 *Generate ECC 256-bit keypair in SE050
 *Perform sign and verify operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, EC256_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x29, 0x38, 0x01};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, data_to_be_signed, sizeof(data_to_be_signed))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &outBlob,
                                           &out_params, &outBlob));
}


/*
 *Generate ECC 384-bit keypair in SE050
 *Perform sign and verify operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, EC384_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x88, 0x99, 0x38, 0x01};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(384)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, data_to_be_signed, sizeof(data_to_be_signed))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &outBlob,
                                           &out_params, &outBlob));
}

/*
 *Generate ECC 521-bit keypair in SE050
 *Perform sign and verify operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, EC521_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x88, 0x99, 0x00, 0x11};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(521)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, data_to_be_signed, sizeof(data_to_be_signed))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &outBlob,
                                           &out_params, &outBlob));
}

/*
 *Generate ECC 224-bit keypair in SE050
 *Perform sign and verify operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, EC224_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x08, 0x09, 0x01, 0x01};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    const uint8_t data_to_be_update[] = "Random Data to be updated";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob, updateoutBlob = {nullptr, 0};
    keymaster_blob_t input1, input2;
    input1.data = data_to_be_signed;
    input1.data_length = sizeof(data_to_be_signed);
    input2.data = data_to_be_update;
    input2.data_length = sizeof(data_to_be_update);
    size_t input_consumed = 0;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(224)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, input1.data, input1.data_length)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input1,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input2,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &updateoutBlob,
                                           &signature, &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input1,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input2,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &updateoutBlob,
                                           &outBlob, &out_params, &outBlob));
}

/*
 *Generate ECC 256-bit keypair in SE050
 *Perform sign and verify operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, EC256_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x83, 0x92, 0x83, 0x10};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob, updateoutBlob;
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, input.data, input.data_length)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &outBlob,
                                           &out_params, &outBlob));
}

/*
 *Generate ECC 384-bit keypair in SE050
 *Perform sign and verify operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, EC384_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x00, 0x00, 0x33, 0x11};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob, updateoutBlob;
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(384)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, input.data, input.data_length)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &outBlob,
                                           &out_params, &outBlob));
}

/*
 *Generate ECC 521-bit keypair in SE050
 *Perform sign and verify operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, EC521_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x99, 0x55, 0x77, 0x66};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob, updateoutBlob;
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(521)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, input.data, input.data_length)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &outBlob,
                                           &out_params, &outBlob));
}

/*
 *Generate RSA 1024-bit keypair in SE050
 *Perform sign and verify operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, RSA1024_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x29, 0x38, 0x01};
    //  const uint8_t* data_to_be_signed = (uint8_t*) "RANDOM DATA TO BE SIGNED";
    const uint8_t data_to_be_signed2[] = "RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_signed2;
    input.data_length = sizeof(data_to_be_signed2);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(1024, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        AuthorizationSet attest_params(
            AuthorizationSetBuilder()
                .Authorization(TAG_ATTESTATION_CHALLENGE, input.data, input.data_length)
                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input,
                                               &signature, &out_params, &outBlob));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input,
                                               &outBlob, &out_params, &outBlob));
    }
}

/*
 *Generate RSA 2048-bit keypair in SE050
 *Perform sign and verfiy operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, RSA2048_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x08, 0x09, 0x25, 0x01};
    //  const uint8_t* data_to_be_signed = (uint8_t*) "RANDOM DATA TO BE SIGNED";
    const uint8_t data_to_be_signed2[] = "RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_signed2;
    input.data_length = sizeof(data_to_be_signed2);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, input.data, input.data_length)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
            .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &outBlob,
                                           &out_params, &outBlob));
}

/*
 *Generate RSA 3072-bit keypair in SE050
 *Perform sign and verfiy operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, RSA3072_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x68, 0x09, 0x28, 0x01};
    //  const uint8_t* data_to_be_signed = (uint8_t*) "RANDOM DATA TO BE SIGNED";
    const uint8_t data_to_be_signed2[] = "RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_signed2;
    input.data_length = sizeof(data_to_be_signed2);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(3072, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, input.data, input.data_length)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
            .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &outBlob,
                                           &out_params, &outBlob));
}

/*
 *Generate RSA 4096-bit keypair in SE050
 *Perform sign and verfiy operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, RSA4096_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x66, 0x99, 0x75, 0x01};
    //  const uint8_t* data_to_be_signed = (uint8_t*) "RANDOM DATA TO BE SIGNED";
    const uint8_t data_to_be_signed2[] = "RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_signed2;
    input.data_length = sizeof(data_to_be_signed2);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(4096, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        AuthorizationSet attest_params(
            AuthorizationSetBuilder()
                .Authorization(TAG_ATTESTATION_CHALLENGE, input.data, input.data_length)
                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input,
                                               &signature, &out_params, &outBlob));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input,
                                               &outBlob, &out_params, &outBlob));
    }
}

/*
 *Generate RSA 1024-bit keypair in SE050
 *Perform sign and verify operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, RSA1024_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x83, 0x92, 0x83, 0x10};
    //  const uint8_t* data_to_be_signed = (uint8_t*) "RANDOM DATA TO BE SIGNED";
    const uint8_t* data_to_be_signed2 = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    const uint8_t* data_to_be_update = (uint8_t*)"RANDOM DATA TO BE UPDATE";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob, updateoutBlob = {nullptr, 0};
    keymaster_blob_t input1, input2;
    input1.data = data_to_be_signed2;
    input1.data_length = sizeof(data_to_be_signed2);
    input2.data = data_to_be_update;
    input2.data_length = sizeof(data_to_be_update);
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(1024, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        AuthorizationSet attest_params(
            AuthorizationSetBuilder()
                // .Authorization(TAG_ATTESTATION_CHALLENGE, input1.data, input1.data_length)
                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input1,
                                               &input_consumed, &out_params, &updateoutBlob));
        ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input2,
                                               &input_consumed, &out_params, &updateoutBlob));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &updateoutBlob,
                                               &signature, &out_params, &outBlob));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input1,
                                               &input_consumed, &out_params, &updateoutBlob));
        ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input2,
                                               &input_consumed, &out_params, &updateoutBlob));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr,
                                               &updateoutBlob, &outBlob, &out_params, &outBlob));
    }
}

/*
 *Generate RSA 2048-bit keypair in SE050
 *Perform sign and verfiy operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, RSA2048_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0xaa, 0xbb, 0xdc, 0xc0};
    //  const uint8_t* data_to_be_signed = (uint8_t*) "RANDOM DATA TO BE SIGNED";
    const uint8_t* data_to_be_signed2 = (uint8_t*)"RANDOMDATATOBESIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob, updateoutBlob;
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed2;
    input.data_length = sizeof(data_to_be_signed2);
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            //        .Authorization(TAG_ATTESTATION_CHALLENGE, input.data, input.data_length)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
            .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &outBlob,
                                           &out_params, &outBlob));
}

/*
 *Generate RSA 3072-bit keypair in SE050
 *Perform sign and verfiy operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, RSA3072_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0xab, 0xba, 0xcd, 0xdc};
    //  const uint8_t* data_to_be_signed = (uint8_t*) "RANDOM DATA TO BE SIGNED";
    const uint8_t* data_to_be_signed2 = (uint8_t*)"RANDOMDATATOBESIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob, updateoutBlob;
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed2;
    input.data_length = sizeof(data_to_be_signed2);
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(3072, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            //        .Authorization(TAG_ATTESTATION_CHALLENGE, input.data, input.data_length)
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
            .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &outBlob,
                                           &out_params, &outBlob));
}

/*
 *Generate RSA 4096-bit keypair in SE050
 *Perform sign and verfiy operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, RSA4096_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0xaa, 0xde, 0xde, 0x0d};
    //  const uint8_t* data_to_be_signed = (uint8_t*) "RANDOM DATA TO BE SIGNED";
    const uint8_t* data_to_be_signed2 = (uint8_t*)"RANDOMDATATOBESIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob, updateoutBlob;
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed2;
    input.data_length = sizeof(data_to_be_signed2);
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(4096, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        AuthorizationSet attest_params(
            AuthorizationSetBuilder()
                //        .Authorization(TAG_ATTESTATION_CHALLENGE, input.data, input.data_length)
                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                               &input_consumed, &out_params, &outBlob));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input,
                                               &signature, &out_params, &outBlob));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                               &input_consumed, &out_params, &updateoutBlob));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input,
                                               &outBlob, &out_params, &outBlob));
    }
}

/*
 *Generate HMAC 256-bit keypair in SE050
 *Perform sign and verfiy operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, HMAC_begin_finish)
{
    const uint8_t id[] = {0x1f, 0xb2, 0xcb, 0xc4};
    const uint8_t srcData[] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33 };
    const uint8_t key[32] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33 };

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&key;
    key_data.data_length = sizeof(key);
    keymaster_key_characteristics_t myChar;
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t input ;
    input.data = (const uint8_t*)&srcData;
    input.data_length = sizeof(srcData);
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t signature = {nullptr, 0};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .HmacKey(256)
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_MIN_MAC_LENGTH, 256)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_MIN_MAC_LENGTH, 160)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                       .Authorization(TAG_MAC_LENGTH, 256));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));


    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &outBlob,
                                           &out_params, &outBlob));
}

/*
 *Generate HMAC 256-bit keypair in SE050
 *Perform sign and verfiy operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050VerifyOperation, HMAC_begin_update_finish)
{
    const uint8_t id[] = {0xaf, 0xb4, 0x5c, 0xc4};
    const uint8_t srcData[] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33 };
    const uint8_t key[32] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33,
                              0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x31, 0x32, 0x33 };

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&key;
    key_data.data_length = sizeof(key);
    keymaster_key_characteristics_t myChar;
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t input , dummy_blob={nullptr , 0};
    input.data = (const uint8_t*)&srcData;
    input.data_length = sizeof(srcData);
    size_t input_consumed = 0;
    keymaster_blob_t outBlob,updateoutBlob;
    keymaster_blob_t signature = {nullptr, 0};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .HmacKey(256)
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_MIN_MAC_LENGTH, 256)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_MIN_MAC_LENGTH, 160)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                       .Authorization(TAG_MAC_LENGTH, 256));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &dummy_blob, &signature,
                                           &out_params, &outBlob));


    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, nullptr, &input,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &dummy_blob, &outBlob,
                                           &out_params, &outBlob));
}

typedef KeymasterHALTest Se050EncyptOperation;
/*
 *Import RSA 1024-bit keypair in SE050
 *Perform encryption operation on some random data
 *PADDING: OAEP
 *DIGEST: SHA1
 *(Currently only OAEP-SHA1 is supported)
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050EncyptOperation, RSA1024_begin_finish) {
    // keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x29, 0x38, 0x01};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaEncryptionKey(1024, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    // ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = RSA_PAIR_1024_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    keymaster_key_characteristics_t myChar;
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
    } else {
        ASSERT_EQ(KM_ERROR_OK,
                  newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input,
                                               &signature, &out_params, &outBlob));
    }
}

/*
 *Import RSA 2048-bit keypair in SE050
 *Perform encryption operation on some random data
 *(Currently only OAEP-SHA1 is supported)
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050EncyptOperation, RSA2048_begin_finish) {
    // keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x11, 0x22, 0x33, 0x44};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaEncryptionKey(2048, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    // ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = RSA_PAIR_2048_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    keymaster_key_characteristics_t myChar;
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Import RSA 3072-bit keypair in SE050
 *Perform encryption operation on some random data
 *(Currently only OAEP-SHA1 is supported)
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050EncyptOperation, RSA3072_begin_finish) {
    // keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0xbb, 0xaa, 0xcd, 0xee};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaEncryptionKey(3072, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    // ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = RSA_PAIR_3072_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    keymaster_key_characteristics_t myChar;
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Import RSA 1024-bit keypair in SE050
 *Perform encryption operation on some random data
 *PADDING: OAEP
 *DIGEST: SHA1
 *(Currently only OAEP-SHA1 is supported)
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050EncyptOperation, RSA1024_begin_update_finish) {
    // keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x3f, 0x2a, 0x85, 0x10};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_blob_t outBlob, updateoutBlob;
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaEncryptionKey(1024, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    // ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = RSA_PAIR_1024_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    keymaster_key_characteristics_t myChar;
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
    } else {
        ASSERT_EQ(KM_ERROR_OK,
                  newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input,
                                               &input_consumed, &out_params, &updateoutBlob));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input,
                                               &signature, &out_params, &outBlob));
    }
}

/*
 *Import RSA 2048-bit keypair in SE050
 *Perform encryption operation on some random data
 *(Currently only OAEP-SHA1 is supported)
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050EncyptOperation, RSA2048_begin_update_finish) {
    // keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x11, 0x22, 0x33, 0x44};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaEncryptionKey(2048, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    // ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = RSA_PAIR_2048_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    keymaster_key_characteristics_t myChar;
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input,
                                           &input_consumed, &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Import RSA 3072-bit keypair in SE050
 *Perform encryption operation on some random data
 *(Currently only OAEP-SHA1 is supported)
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050EncyptOperation, RSA3072_begin_update_finish) {
    // keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x1a, 0x2b, 0x3c, 0x4d};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaEncryptionKey(3072, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    // ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = RSA_PAIR_3072_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    keymaster_key_characteristics_t myChar;
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input,
                                           &input_consumed, &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}

/*
 *Import AES 128-bit key in SE050
 *Perform encryption operation on some random data
 *BLOCK_MODE: ECB
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050EncyptOperation, AES128_ECB) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_RAW;
    const uint8_t set_data[] = AES_128_TEST_KEY;
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_operation_handle_t op_handle_enc;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    // keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();
    const uint8_t id[] = {0x90, 0x21, 0x34, 0x90};
    const uint8_t data_to_be_enc[] = {"RANDOM DATA TO "};
    keymaster_blob_t input, signature, encryptedBlob;
    input.data = (const uint8_t*)&data_to_be_enc;
    input.data_length = sizeof(data_to_be_enc);

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .AesEncryptionKey(128)
                                .Authorization(TAG_BLOCK_MODE, KM_MODE_ECB)
                                .Authorization(TAG_PADDING, KM_PAD_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &params, &out_params,
                                          &op_handle_enc));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_enc, &tmp_params, &input, &signature,
                                           &out_params, &encryptedBlob));
}

/*
 *Import AES 128-bit key in SE050
 *Perform encryption operation on some random data
 *BLOCK_MODE: GCM
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050EncyptOperation, AES128_GCM) {

#if SSS_HAVE_SE05X_VER_GTE_07_02
    keymaster_key_format_t key_format = KM_KEY_FORMAT_RAW;
    const uint8_t set_data[] = AES_128_TEST_KEY ;
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params;
    keymaster_operation_handle_t op_handle_enc;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    // keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();
    const uint8_t id[] = {0x90, 0x21, 0x34, 0x2F};
    const uint8_t data_to_be_enc[] = {"RANDOM DATA TO "};
    const uint8_t aad[] = {"1234567890123456"};
    keymaster_blob_t input, signature, encryptedBlob;
    input.data = (const uint8_t*)&data_to_be_enc;
    input.data_length = sizeof(data_to_be_enc);

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .AesEncryptionKey(128)
                                .Authorization(TAG_BLOCK_MODE, KM_MODE_GCM)
                                .Authorization(TAG_PADDING, KM_PAD_NONE)
                                .Authorization(TAG_MAC_LENGTH, 128)
                                .build());

    AuthorizationSet tmp_params(AuthorizationSetBuilder()
                                .Authorization(TAG_ASSOCIATED_DATA, aad, sizeof(aad))
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));

    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &params, &out_params,
                                          &op_handle_enc));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_enc, &tmp_params, &input, &signature,
                                           &out_params, &encryptedBlob));
#else
    GTEST_COUT << " AES GCM feature is not supported for SE050 " << std::endl;
#endif
}

typedef KeymasterHALTest Se050DecyptOperation;
/*
 *Import RSA 1024-bit keypair in SE050
 *Perform encryption and decryption operations on some random data
 *Check that the decrypted data matches the input to encrypt
 *(Currently only OAEP-SHA1 is supported)
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050DecyptOperation, RSA1024_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x29, 0x38, 0x01};
    const uint8_t data_to_be_signed[] = {"RANDOM DATA TO BE SIGNED"};
    // const uint8_t empty[] = {""};
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_purpose_t myPurpose_decrypt = KM_PURPOSE_DECRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_operation_handle_t op_handle_ = 0, op_handle_decrypt = 0;
    keymaster_blob_t outBlob, encryptedBlob, decryptedBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    std::string to_be_encrypted = (char*)input.data;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaEncryptionKey(1024, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        AuthorizationSet attest_params(AuthorizationSetBuilder()
                                           .Authorization(TAG_ATTESTATION_CHALLENGE,
                                                          (const uint8_t*)&data_to_be_signed,
                                                          sizeof(data_to_be_signed))
                                           .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                           .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input,
                                               &signature, &out_params, &encryptedBlob));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_decrypt, &myBlob_, &attest_params,
                                              &out_params, &op_handle_decrypt));
        ASSERT_EQ(KM_ERROR_OK,
                  newdev2->finish(newdev2, op_handle_decrypt, &tmp_params, &encryptedBlob, &outBlob,
                                  &out_params, &decryptedBlob));
        std::string decrypted;
        if (decryptedBlob.data) {
            decrypted = (char*)decryptedBlob.data;
        } else {
            decrypted = "";
            // decryptedBlob.data = (const uint8_t*)&empty;
            // decryptedBlob.data_length = sizeof(empty);
        }
        ASSERT_EQ(to_be_encrypted, decrypted);
    }
}

/*
 *Import RSA 2048-bit keypair in SE050
 *Perform encryption and decryption operations on some random data
 *Check that the decrypted data matches the input to encrypt
 *(Currently only OAEP-SHA1 is supported)
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050DecyptOperation, RSA2048_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x22, 0x33, 0x44, 0x55};
    const uint8_t data_to_be_signed[] = {"RANDOM DATA TO BE SIGNED"};
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_purpose_t myPurpose_decrypt = KM_PURPOSE_DECRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_operation_handle_t op_handle_, op_handle_decrypt;
    keymaster_blob_t outBlob, encryptedBlob = {nullptr, 0};
    keymaster_blob_t decryptedBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    std::string to_be_encrypted = (char*)input.data;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaEncryptionKey(2048, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_ATTESTATION_CHALLENGE,
                                                      (const uint8_t*)&data_to_be_signed,
                                                      sizeof(data_to_be_signed))
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &encryptedBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_decrypt, &myBlob_, &attest_params,
                                          &out_params, &op_handle_decrypt));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_decrypt, &tmp_params, &encryptedBlob,
                                           &outBlob, &out_params, &decryptedBlob));
    std::string decrypted;
    if (decryptedBlob.data) {
        decrypted = (char*)decryptedBlob.data;
    } else {
        decrypted = "";
    }
    ASSERT_EQ(to_be_encrypted, decrypted);
}

/*
 *Import RSA 3072-bit keypair in SE050
 *Perform encryption and decryption operations on some random data
 *Check that the decrypted data matches the input to encrypt
 *(Currently only OAEP-SHA1 is supported)
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050DecyptOperation, RSA3072_begin_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0xa2, 0xb3, 0xc4, 0xd5};
    const uint8_t data_to_be_signed[] = {"RANDOM DATA TO BE SIGNED"};
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_purpose_t myPurpose_decrypt = KM_PURPOSE_DECRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_operation_handle_t op_handle_, op_handle_decrypt;
    keymaster_blob_t outBlob, encryptedBlob = {nullptr, 0};
    keymaster_blob_t decryptedBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    std::string to_be_encrypted = (char*)input.data;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaEncryptionKey(3072, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_ATTESTATION_CHALLENGE,
                                                      (const uint8_t*)&data_to_be_signed,
                                                      sizeof(data_to_be_signed))
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &encryptedBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_decrypt, &myBlob_, &attest_params,
                                          &out_params, &op_handle_decrypt));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_decrypt, &tmp_params, &encryptedBlob,
                                           &outBlob, &out_params, &decryptedBlob));
    std::string decrypted;
    if (decryptedBlob.data) {
        decrypted = (char*)decryptedBlob.data;
    } else {
        decrypted = "";
    }
    ASSERT_EQ(to_be_encrypted, decrypted);
}

/*
 *Import RSA 1024-bit keypair in SE050
 *Perform encryption and decryption operations on some random data
 *Check that the decrypted data matches the input to encrypt
 *(Currently only OAEP-SHA1 is supported)
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050DecyptOperation, RSA1024_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x29, 0x38, 0x01};
    const uint8_t data_to_be_signed[] = {"RANDOM DATA TO BE SIGNED"};
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_purpose_t myPurpose_decrypt = KM_PURPOSE_DECRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_operation_handle_t op_handle_, op_handle_decrypt;
    keymaster_blob_t outBlob, encryptedBlob = {nullptr, 0};
    keymaster_blob_t updateoutBlob, decryptedBlob = {nullptr, 0};
    keymaster_blob_t dummy_blob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    std::string to_be_encrypted = (char*)input.data;
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaEncryptionKey(1024, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    if (SSS_HAVE_FIPS) {
        GTEST_COUT << " Not supported for FIPS checking Integrity " << std::endl;
        ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    } else {
        ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
        AuthorizationSet attest_params(AuthorizationSetBuilder()
                                           .Authorization(TAG_ATTESTATION_CHALLENGE,
                                                          (const uint8_t*)&data_to_be_signed,
                                                          sizeof(data_to_be_signed))
                                           .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                           .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &attest_params,
                                              &out_params, &op_handle_));
        ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input,
                                               &input_consumed, &out_params, &updateoutBlob));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input,
                                               &signature, &out_params, &encryptedBlob));

        ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_decrypt, &myBlob_, &attest_params,
                                              &out_params, &op_handle_decrypt));
        ASSERT_EQ(KM_ERROR_OK,
                  newdev2->update(newdev2, op_handle_decrypt, &tmp_params, &encryptedBlob,
                                  &input_consumed, &out_params, &updateoutBlob));
        ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_decrypt, &tmp_params, &dummy_blob,
                                               &outBlob, &out_params, &decryptedBlob));
        std::string decrypted;
        if (decryptedBlob.data) {
            decrypted = (char*)decryptedBlob.data;
        } else {
            decrypted = "";
        }
        ASSERT_EQ(to_be_encrypted, decrypted);
    }
}

/*
 *Import RSA 2048-bit keypair in SE050
 *Perform encryption and decryption operations on some random data
 *Check that the decrypted data matches the input to encrypt
 *(Currently only OAEP-SHA1 is supported)
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050DecyptOperation, RSA2048_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0xa0, 0x30, 0x4b, 0x50};
    const uint8_t data_to_be_signed[] = {"RANDOM DATA TO BE SIGNED"};
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_purpose_t myPurpose_decrypt = KM_PURPOSE_DECRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_operation_handle_t op_handle_, op_handle_decrypt;
    keymaster_blob_t outBlob, encryptedBlob = {nullptr, 0};
    keymaster_blob_t updateoutBlob, decryptedBlob = {nullptr, 0};
    keymaster_blob_t dummy_blob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    std::string to_be_encrypted = (char*)input.data;
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaEncryptionKey(2048, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_ATTESTATION_CHALLENGE,
                                                      (const uint8_t*)&data_to_be_signed,
                                                      sizeof(data_to_be_signed))
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &encryptedBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_decrypt, &myBlob_, &attest_params,
                                          &out_params, &op_handle_decrypt));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_decrypt, &tmp_params, &encryptedBlob,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_decrypt, &tmp_params, &dummy_blob,
                                           &outBlob, &out_params, &decryptedBlob));
    std::string decrypted;
    if (decryptedBlob.data) {
        decrypted = (char*)decryptedBlob.data;
    } else {
        decrypted = "";
    }
    ASSERT_EQ(to_be_encrypted, decrypted);
}

/*
 *Import RSA 3072-bit keypair in SE050
 *Perform encryption and decryption operations on some random data
 *Check that the decrypted data matches the input to encrypt
 *(Currently only OAEP-SHA1 is supported)
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050DecyptOperation, RSA3072_begin_update_finish) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0xa0, 0xb0, 0x4b, 0x5f};
    const uint8_t data_to_be_signed[] = {"RANDOM DATA TO BE SIGNED"};
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_purpose_t myPurpose_decrypt = KM_PURPOSE_DECRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_operation_handle_t op_handle_, op_handle_decrypt;
    keymaster_blob_t outBlob, encryptedBlob = {nullptr, 0};
    keymaster_blob_t updateoutBlob, decryptedBlob = {nullptr, 0};
    keymaster_blob_t dummy_blob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    std::string to_be_encrypted = (char*)input.data;
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaEncryptionKey(3072, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_ATTESTATION_CHALLENGE,
                                                      (const uint8_t*)&data_to_be_signed,
                                                      sizeof(data_to_be_signed))
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &encryptedBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_decrypt, &myBlob_, &attest_params,
                                          &out_params, &op_handle_decrypt));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_decrypt, &tmp_params, &encryptedBlob,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_decrypt, &tmp_params, &dummy_blob,
                                           &outBlob, &out_params, &decryptedBlob));
    std::string decrypted;
    if (decryptedBlob.data) {
        decrypted = (char*)decryptedBlob.data;
    } else {
        decrypted = "";
    }
    ASSERT_EQ(to_be_encrypted, decrypted);
}

/*
 *Import AES 128-bit key in SE050
 *Perform encryption and decryption operations on some random data
 *BLOCK_MODE: ECB
 *Check that decrypted data matches the input to encrypt
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050DecyptOperation, AES128_ECB) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_RAW;
    const uint8_t set_data[] = AES_128_TEST_KEY;
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_purpose_t myPurpose_decrypt = KM_PURPOSE_DECRYPT;
    keymaster_key_param_set_t out_params = {nullptr, 0}, tmp_params = {nullptr, 0};
    keymaster_operation_handle_t op_handle_enc, op_handle_dec;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    // keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();
    const uint8_t id[] = {0x90, 0x21, 0x34, 0x90};
    const uint8_t data_to_be_enc[] = {"Hello World!000"};
    keymaster_blob_t input, signature, encryptedBlob = {nullptr, 0};
    keymaster_blob_t outBlob, decryptedBlob = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_enc;
    input.data_length = sizeof(data_to_be_enc);
    std::string to_be_enc = (char*)input.data;

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .AesEncryptionKey(128)
                                .Authorization(TAG_BLOCK_MODE, KM_MODE_ECB)
                                .Authorization(TAG_PADDING, KM_PAD_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &params, &out_params,
                                          &op_handle_enc));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_enc, &tmp_params, &input, &signature,
                                           &out_params, &encryptedBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_decrypt, &myBlob_, &params, &out_params,
                                          &op_handle_dec));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_dec, &tmp_params, &encryptedBlob,
                                           &outBlob, &out_params, &decryptedBlob));
    std::string decrypted;
    if (decryptedBlob.data) {
        decrypted = (char*)decryptedBlob.data;
    } else {
        decrypted = "";
    }
    ASSERT_EQ(to_be_enc, decrypted);
}

TEST_F(Se050DecyptOperation, AES128_CBC) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_RAW;
    const uint8_t set_data[] = AES_128_TEST_KEY;
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_purpose_t myPurpose_decrypt = KM_PURPOSE_DECRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_operation_handle_t op_handle_enc, op_handle_dec;
    keymaster_blob_t key_data;
    keymaster_blob_t nonce;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    // keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();
    const uint8_t id[] = {0x90, 0x21, 0x34, 0x90};
    const uint8_t data_to_be_enc[] = {"Hello World!000"};
    const uint8_t nonce_value[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    keymaster_blob_t input, signature, encryptedBlob = {nullptr, 0};
    keymaster_blob_t outBlob, decryptedBlob = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_enc;
    input.data_length = sizeof(data_to_be_enc);
    std::string to_be_enc = (char*)input.data;
    nonce.data = (const uint8_t*)&nonce_value;
    nonce.data_length = sizeof(nonce_value);

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .AesEncryptionKey(128)
                                .Authorization(TAG_BLOCK_MODE, KM_MODE_CBC)
                                .Authorization(TAG_PADDING, KM_PAD_NONE)
                                .Authorization(TAG_CALLER_NONCE)
                                .Authorization(TAG_NONCE, nonce_value, sizeof(nonce_value))
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &params, &out_params,
                                          &op_handle_enc));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_enc, &tmp_params, &input, &signature,
                                           &out_params, &encryptedBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_decrypt, &myBlob_, &params, &out_params,
                                          &op_handle_dec));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_dec, &tmp_params, &encryptedBlob,
                                           &outBlob, &out_params, &decryptedBlob));
    std::string decrypted;
    if (decryptedBlob.data) {
        decrypted = (char*)decryptedBlob.data;
    } else {
        decrypted = "";
    }
    ASSERT_EQ(to_be_enc, decrypted);
}

TEST_F(Se050DecyptOperation, AES128_CTR) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_RAW;
    const uint8_t set_data[] = AES_128_TEST_KEY;
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_purpose_t myPurpose_decrypt = KM_PURPOSE_DECRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_operation_handle_t op_handle_enc, op_handle_dec;
    keymaster_blob_t key_data;
    keymaster_blob_t nonce;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    // keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();
    const uint8_t id[] = {0x90, 0x21, 0x34, 0x90};
    const uint8_t data_to_be_enc[] = {"Hello World!000"};
    // const uint8_t empty[] = {""};
    const uint8_t nonce_value[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    keymaster_blob_t input, signature, encryptedBlob = {nullptr, 0};
    keymaster_blob_t outBlob, decryptedBlob = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_enc;
    input.data_length = sizeof(data_to_be_enc);
    std::string to_be_enc = (char*)input.data;
    nonce.data = (const uint8_t*)&nonce_value;
    nonce.data_length = sizeof(nonce_value);

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .AesEncryptionKey(128)
                                .Authorization(TAG_BLOCK_MODE, KM_MODE_CTR)
                                .Authorization(TAG_PADDING, KM_PAD_NONE)
                                .Authorization(TAG_CALLER_NONCE)
                                .Authorization(TAG_NONCE, nonce_value, sizeof(nonce_value))
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &params, &out_params,
                                          &op_handle_enc));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_enc, &tmp_params, &input, &signature,
                                           &out_params, &encryptedBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_decrypt, &myBlob_, &params, &out_params,
                                          &op_handle_dec));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_dec, &tmp_params, &encryptedBlob,
                                           &outBlob, &out_params, &decryptedBlob));
    std::string decrypted;
    if (decryptedBlob.data) {
        decrypted = (char*)decryptedBlob.data;
    } else {
        decrypted = "";
        // decryptedBlob.data = (const uint8_t*)&empty;
        // decryptedBlob.data_length = sizeof(empty);
    }
    ASSERT_EQ(to_be_enc, decrypted);
}

/*
 *Import AES 128-bit key in SE050
 *Perform encryption and decryption operations on some random data
 *BLOCK_MODE: GCM
 *Check that decrypted data matches the input to encrypt
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050DecyptOperation, AES128_GCM) {

#if SSS_HAVE_SE05X_VER_GTE_07_02
    keymaster_key_format_t key_format = KM_KEY_FORMAT_RAW;
    const uint8_t set_data[] = AES_128_TEST_KEY ;
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_purpose_t myPurpose_decrypt = KM_PURPOSE_DECRYPT;
    keymaster_key_param_set_t out_params;
    keymaster_operation_handle_t op_handle_enc, op_handle_dec;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    // keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();
    const uint8_t id[] = {0xF2, 0x21, 0x34, 0x90};
    uint8_t data_to_be_enc[75] = {0} ;
    const uint8_t aad[] = {"1234567890123456"};
    const uint8_t nonce[] = {
        0xb7, 0x94, 0x37, 0xae, 0x08, 0xff, 0x35, 0x5d, 0x7d, 0x8a, 0x4d, 0x0f,
    };
    for(size_t i = 0; i < 75 ; i++)
    {
        data_to_be_enc[i] = 0x61;
    }
    keymaster_blob_t input, signature, encryptedBlob = {nullptr, 0};
    keymaster_blob_t outBlob, decryptedBlob = {nullptr, 0} ;
    input.data = (const uint8_t*)&data_to_be_enc;
    input.data_length = sizeof(data_to_be_enc);
    //std::string to_be_enc = (char*)input.data;
    std:: string to_be_enc(75, 'a');

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .AesEncryptionKey(128)
                                .Authorization(TAG_BLOCK_MODE, KM_MODE_GCM)
                                .Authorization(TAG_PADDING, KM_PAD_NONE)
                                .Authorization(TAG_CALLER_NONCE)
                                .Authorization(TAG_NONCE, nonce, sizeof(nonce))
                                .Authorization(TAG_MAC_LENGTH, 128)
                                .build());

    AuthorizationSet tmp_params(AuthorizationSetBuilder()
                                .Authorization(TAG_ASSOCIATED_DATA, aad, sizeof(aad))
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));

    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &params, &out_params,
                                          &op_handle_enc));

    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_enc, &tmp_params, &input, &signature,
                                           &out_params, &encryptedBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_decrypt, &myBlob_, &params, &out_params,
                                          &op_handle_dec));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_dec, &tmp_params, &encryptedBlob,
                                           &outBlob, &out_params, &decryptedBlob));
    std::string decrypted;
    if (decryptedBlob.data) {
        decrypted = (char*)decryptedBlob.data;
    } else {
        decrypted = "";
    }
    ASSERT_EQ(to_be_enc, decrypted);
#else
    GTEST_COUT << " AES GCM feature is not supported for SE050 " << std::endl ;
#endif
}

typedef KeymasterHALTest Se050Entropy;

/*
 *Adding entropy to RNG function.
 *Not implemented for SE050 (Artifact #artf635904)
 * */
TEST_F(Se050Entropy, add_rng_entropy) {
    const uint8_t entropy[] = {0x01, 0x10, 0x30, 0x40, 0x11, 0x43, 0x57, 0x92};
    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->add_rng_entropy(newdev2, entropy, sizeof(entropy)));
}

/*
 * Negative Testcases for SE050 Keymaster Device
 */
typedef KeymasterHALTest Se050InvalidInput;

/*
 *Passing unconfigured keymaster2_device_t should fail with correct error code
 * */

TEST_F(Se050InvalidInput, getKeyCharacteristics_unconfigured) {
    keymaster_key_characteristics_t retrievedKeyCharc;
    keymaster_key_blob_t dummy_blob;

    ASSERT_EQ(KM_ERROR_KEYMASTER_NOT_CONFIGURED,
              newdev2->get_key_characteristics(newdev2, &dummy_blob, NULL /*client id*/,
                                               NULL /*app data*/, &retrievedKeyCharc));
}

/*
 *passing invalid keyblob to retrieve key characterisitcs of generated key.
 * */

TEST_F(Se050InvalidInput, getKeyCharacteristics_invalidKeyBlob) {
    keymaster_key_characteristics_t generatedKeyCharc;
    keymaster_key_characteristics_t retrievedKeyCharc;
    keymaster_key_blob_t dummy_blob;

    const uint8_t id[] = {0x1a, 0xb7, 0xc2, 0x35};
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &generatedKeyCharc));
    AuthorizationSet gen_sw(generatedKeyCharc.sw_enforced);
    AuthorizationSet gen_hw(generatedKeyCharc.hw_enforced);
    ASSERT_EQ(KM_ERROR_INVALID_KEY_BLOB,
              newdev2->get_key_characteristics(newdev2, &dummy_blob, NULL /*client id*/,
                                               NULL /*app data*/, &retrievedKeyCharc));
}

/*
 *Passing unconfigured keymaster2_device_t should fail with correct error code
 * */
TEST_F(Se050InvalidInput, generate_EC256_unconfigured) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x32, 0x09, 0x42, 0x02};
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_KEYMASTER_NOT_CONFIGURED,
              newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
}

/*
 *Not specified which type of key is to be generated in params
 *
 * */
TEST_F(Se050InvalidInput, generate_invalid_params) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x32, 0x09, 0x42, 0x02};
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
              newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
}

/*
 *Passing unconfigured keymaster2_device_t should fail with correct error code
 * */
TEST_F(Se050InvalidInput, set_EC256_unconfigured) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = ECC_PAIR_256_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    //  keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();
    const uint8_t id[] = {0x73, 0x48, 0x34, 0x80};

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_KEYMASTER_NOT_CONFIGURED,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
}

/*
 *Not specified which type of key is being imported in params
 * */
TEST_F(Se050InvalidInput, set_EC256_invalid_params) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = ECC_PAIR_256_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    //  keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();
    const uint8_t id[] = {0x73, 0x48, 0x34, 0x80};

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
}

/*
 *Passing unconfigured keymaster2_device_t should fail with correct error code
 * */
TEST_F(Se050InvalidInput, getkey_unconfigured) {
    keymaster_key_characteristics_t myKeyCharac;
    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();

    const uint8_t id[] = {0x73, 0x48, 0x88, 0x55};
    // Se050KeymasterDevice* mydevice2 = new Se050KeymasterDevice();
    // keymaster2_device_t* my_km2_device = mydevice2->keymaster2_device();

    keymaster_key_format_t export_format = KM_KEY_FORMAT_X509;
    keymaster_blob_t *client_id = nullptr, export_data, *app_data = nullptr;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));

    ASSERT_EQ(KM_ERROR_KEYMASTER_NOT_CONFIGURED,
              newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(
        KM_ERROR_KEYMASTER_NOT_CONFIGURED,
        newdev2->export_key(newdev2, export_format, &myBlob_, client_id, app_data, &export_data));
}

/*
 *Passing unconfigured keymaster2_device_t should fail with correct error code
 * */
TEST_F(Se050InvalidInput, sign_EC256_unconfigured) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x32, 0x09, 0x42, 0x02};
    keymaster_cert_chain_t signature;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_KEYMASTER_NOT_CONFIGURED,
              newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params;
    ASSERT_EQ(KM_ERROR_KEYMASTER_NOT_CONFIGURED,
              newdev2->attest_key(newdev2, &myBlob_, &attest_params, &signature));
}

/*
 *TAG_APPLICATION_DATA not passed to attest_params
 * */
TEST_F(Se050InvalidInput, sign_EC256_invalid_params) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x32, 0x00, 0x02, 0x02};
    const uint8_t application_id[] = "Unique ID";
    keymaster_cert_chain_t signature;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .Digest(KM_DIGEST_SHA_2_256)
                                .build());
    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_APPLICATION_ID, application_id, sizeof(application_id))
            .build());
    ASSERT_EQ(KM_ERROR_INVALID_INPUT_LENGTH,
              newdev2->attest_key(newdev2, &myBlob_, &attest_params, &signature));
}

/*
 *Passing unconfigured keymaster2_device_t should fail with correct error code
 * */
TEST_F(Se050InvalidInput, upgradeKey_unconfigured) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    keymaster_key_characteristics_t myKeyCharac;
    keymaster_key_blob_t upgradedBlob;
    const uint8_t id[] = {0x84, 0x92, 0x01, 0x28};
    const uint8_t set_data[] = RSA_PAIR_4096_TEST_KEY;
    const uint8_t new_key[] = RSA_PAIR2_4096_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    // keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(4096, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    AuthorizationSet upgrade_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_APPLICATION_DATA, new_key, sizeof(new_key))
            .build());

    ASSERT_EQ(KM_ERROR_KEYMASTER_NOT_CONFIGURED,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_KEYMASTER_NOT_CONFIGURED,
              newdev2->upgrade_key(newdev2, &myBlob_, &upgrade_params, &upgradedBlob));
}

/*
 *TAG_APPLICATION_DATA not passed to upgrade_params
 * */
TEST_F(Se050InvalidInput, upgradeKey_invalid_params) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    keymaster_key_characteristics_t myKeyCharac;
    keymaster_key_blob_t upgradedBlob;
    const uint8_t id[] = {0x84, 0x92, 0x01, 0x28};
    const uint8_t set_data[] = RSA_PAIR_2048_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    //  keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    AuthorizationSet upgrade_params(AuthorizationSetBuilder().build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_UNEXPECTED_NULL_POINTER,
              newdev2->upgrade_key(newdev2, &myBlob_, &upgrade_params, &upgradedBlob));
}

/*
 *Passing unconfigured keymaster2_device_t should fail with correct error code
 * */
TEST_F(Se050InvalidInput, erasekey_unconfigured) {
    keymaster_key_characteristics_t myKeyCharac;
    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    // Se050KeymasterDevice *mydevice2=new Se050KeymasterDevice();
    // keymaster2_device_t* my_km2_dev = mydevice2->keymaster2_device();

    const uint8_t id[] = {0x38, 0x43, 0x89, 0x22};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    // ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_KEYMASTER_NOT_CONFIGURED,
              newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_KEYMASTER_NOT_CONFIGURED, newdev2->delete_key(newdev2, &myBlob_));
}

/*
 *Passing incorrect keyblob to delete_key should fail (newBlob instead of myBlob_)
 * */
TEST_F(Se050InvalidInput, erasekey_invalid_keyblob) {
    keymaster_key_characteristics_t myKeyCharac;
    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    // keymaster_key_blob_t myBlob_{nullptr,0};
    keymaster_key_blob_t newBlob{nullptr, 0};
    const uint8_t id[] = {0x38, 0x43, 0x00, 0x29};

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_UNEXPECTED_NULL_POINTER, newdev2->delete_key(newdev2, &newBlob));
}

/*
 *Passing unconfigured keymaster2_device_t should fail with correct error code
 * */
TEST_F(Se050InvalidInput, encrypt_RSA2048_begin_finish_unconfigured) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x29, 0x38, 0x01};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    // ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_KEYMASTER_NOT_CONFIGURED,
              newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params;

    ASSERT_EQ(KM_ERROR_KEYMASTER_NOT_CONFIGURED,
              newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params, &out_params,
                             &op_handle_));
    ASSERT_EQ(KM_ERROR_KEYMASTER_NOT_CONFIGURED,
              newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature, &out_params,
                              &outBlob));
}

/*
 *begin should fail because of incorrect purpose passed to the API
 *finish should fail because context has not been initialized in begin
 * */
TEST_F(Se050InvalidInput, encrypt_RSA2048_begin_finish_invalid_operation) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x29, 0x32, 0x01};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_DERIVE_KEY;  // KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_operation_handle_t op_handle_ = 0;  //, op_handle_;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params;

    ASSERT_EQ(KM_ERROR_UNSUPPORTED_PURPOSE,
              newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params, &out_params,
                             &op_handle_));
    ASSERT_EQ(KM_ERROR_UNEXPECTED_NULL_POINTER,
              newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature, &out_params,
                              &outBlob));
}

/*
 * Passing incorrect blob to begin and finish should fail in expected way
 * */
TEST_F(Se050InvalidInput, encrypt_RSA2048_begin_finish_invalid_blob) {
    keymaster_key_characteristics_t myKeyCharac;
    // keymaster_key_blob_t myBlob_{nullptr,0};
    keymaster_key_blob_t newBlob{nullptr, 0};
    const uint8_t id[] = {0x38, 0x29, 0x38, 0x01};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_operation_handle_t op_handle_ = 0;  //, op_handle_;
    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params;

    ASSERT_EQ(KM_ERROR_UNEXPECTED_NULL_POINTER,
              newdev2->begin(newdev2, myPurpose_sign, &newBlob, &attest_params, &out_params,
                             &op_handle_));
    ASSERT_EQ(KM_ERROR_UNEXPECTED_NULL_POINTER,
              newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature, &out_params,
                              &outBlob));
}

/*
 * Passing incorrect blob to finish should fail in expected way
 * */
TEST_F(Se050InvalidInput, verify_RSA2048_begin_finish_invalid_params) {
    keymaster_key_characteristics_t myKeyCharac;
    // keymaster_key_blob_t myBlob_{nullptr,0};
    const uint8_t id[] = {0x38, 0x67, 0x48, 0x01};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params;
    keymaster_blob_t outBlob{nullptr, 0};
    keymaster_blob_t invalid_verify_blob{nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, nullptr, &input, &signature,
                                           &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_UNEXPECTED_NULL_POINTER,
              newdev2->finish(newdev2, op_handle_, nullptr, &input, &invalid_verify_blob,
                              &out_params, &outBlob));
}

/*
 * Try to update the input data bigger than keysize should fail with invalid input length
 * */
TEST_F(Se050InvalidInput, update_biggerDatathanKeysize) {
    keymaster_key_characteristics_t myKeyCharac;
    // keymaster_key_blob_t myBlob_{nullptr,0};
    const uint8_t id[] = {0x08, 0x76, 0x84, 0x10};
    const uint8_t data_to_be_signed[] = "RANDOM DATA TO BE SIGNED";
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_operation_handle_t op_handle_ = 0;
    keymaster_blob_t outBlob{nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed) + 2048;
    size_t input_consumed = 0;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, data_to_be_signed, sizeof(data_to_be_signed))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
            .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_INVALID_INPUT_LENGTH,
              newdev2->update(newdev2, op_handle_, &tmp_params, &input, &input_consumed,
                              &out_params, &outBlob));
}

TEST_F(Se050InvalidInput, add_rng_entropy_large) {
    // std::string entropy(2 * 2048, 'a');
    // const uint8_t entropy[] = {0x01, 0x10, 0x30, 0x40, 0x11, 0x43, 0x57, 0x92};
    const char entropy[4096] = "a";
    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_INVALID_INPUT_LENGTH,
              newdev2->add_rng_entropy(newdev2, (const uint8_t*)&entropy, sizeof(entropy)));
}

TEST_F(Se050InvalidInput, RSA_operations_wrong_params) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x38, 0x29, 0x38, 0x01};
    const uint8_t pkcs1_long_data[300] = "RANDOM DATA TO BE SIGNED";
    const uint8_t oaep_long_data[300] = "RANDOM DATA TO BE ENCRYPTED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_key_param_set_t out_params, tmp_params;

    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t pkcs1_long_data_blob, oaep_long_data_blob;
    pkcs1_long_data_blob.data = (const uint8_t*)&pkcs1_long_data;
    pkcs1_long_data_blob.data_length = sizeof(pkcs1_long_data);
    oaep_long_data_blob.data = (const uint8_t*)&oaep_long_data;
    oaep_long_data_blob.data_length = sizeof(oaep_long_data);
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .EncryptionKey()
                                .Authorization(TAG_DIGEST, KM_DIGEST_NONE)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PKCS1_1_5_SIGN)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet encrypt_params(AuthorizationSetBuilder()
                                        .Authorization(TAG_DIGEST, KM_DIGEST_NONE)
                                        .Authorization(TAG_PADDING, KM_PAD_RSA_PKCS1_1_5_ENCRYPT));

    AuthorizationSet encrypt_params2(AuthorizationSetBuilder()
                                         .Authorization(TAG_DIGEST, KM_DIGEST_SHA1)
                                         .Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

    AuthorizationSet encrypt_params3(
        AuthorizationSetBuilder().Authorization(TAG_PADDING, KM_PAD_RSA_OAEP));

    AuthorizationSet sign_params(AuthorizationSetBuilder()
                                     .Authorization(TAG_DIGEST, KM_DIGEST_NONE)
                                     .Authorization(TAG_PADDING, KM_PAD_RSA_PKCS1_1_5_SIGN));

    AuthorizationSet sign_params2(AuthorizationSetBuilder()
                                      .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                      .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    AuthorizationSet sign_params3(AuthorizationSetBuilder()
                                      .Authorization(TAG_DIGEST, KM_DIGEST_NONE)
                                      .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    AuthorizationSet sign_params4(AuthorizationSetBuilder()
                                      .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_512)
                                      .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    EXPECT_EQ(KM_ERROR_UNSUPPORTED_PADDING_MODE,
              newdev2->begin(newdev2, KM_PURPOSE_SIGN, &myBlob_, &encrypt_params, &out_params,
                             &op_handle_));
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_PADDING_MODE,
              newdev2->begin(newdev2, KM_PURPOSE_SIGN, &myBlob_, &encrypt_params2, &out_params,
                             &op_handle_));
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_PADDING_MODE,
              newdev2->begin(newdev2, KM_PURPOSE_ENCRYPT, &myBlob_, &sign_params, &out_params,
                             &op_handle_));
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_PADDING_MODE,
              newdev2->begin(newdev2, KM_PURPOSE_ENCRYPT, &myBlob_, &sign_params2, &out_params,
                             &op_handle_));
    EXPECT_EQ(KM_ERROR_INCOMPATIBLE_DIGEST,
              newdev2->begin(newdev2, KM_PURPOSE_ENCRYPT, &myBlob_, &encrypt_params3, &out_params,
                             &op_handle_));
    EXPECT_EQ(KM_ERROR_INCOMPATIBLE_DIGEST, newdev2->begin(newdev2, KM_PURPOSE_SIGN, &myBlob_,
                                                           &sign_params3, &out_params, &op_handle_));
    EXPECT_EQ(KM_ERROR_INCOMPATIBLE_DIGEST, newdev2->begin(newdev2, KM_PURPOSE_SIGN, &myBlob_,
                                                           &sign_params4, &out_params, &op_handle_));

    EXPECT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, KM_PURPOSE_SIGN, &myBlob_, &sign_params,
                                          &out_params, &op_handle_));
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH,
              newdev2->finish(newdev2, op_handle_, &tmp_params, &pkcs1_long_data_blob, &signature,
                              &out_params, &outBlob));

    EXPECT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, KM_PURPOSE_ENCRYPT, &myBlob_, &encrypt_params,
                                          &out_params, &op_handle_));
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH,
              newdev2->finish(newdev2, op_handle_, &tmp_params, &pkcs1_long_data_blob, &signature,
                              &out_params, &outBlob));

    EXPECT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, KM_PURPOSE_ENCRYPT, &myBlob_, &encrypt_params2,
                                          &out_params, &op_handle_));
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH,
              newdev2->finish(newdev2, op_handle_, &tmp_params, &oaep_long_data_blob, &signature,
                              &out_params, &outBlob));
}

TEST_F(Se050InvalidInput, EccEncryption) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x02, 0x32, 0x32, 0x02};
    keymaster_key_param_set_t out_params;


    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder().Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));

    EXPECT_EQ(KM_ERROR_UNSUPPORTED_PURPOSE,
              newdev2->begin(newdev2, KM_PURPOSE_ENCRYPT, &myBlob_, &attest_params, &out_params,
                             &op_handle_));

    EXPECT_EQ(KM_ERROR_UNSUPPORTED_PURPOSE,
              newdev2->begin(newdev2, KM_PURPOSE_DECRYPT, &myBlob_, &attest_params, &out_params,
                             &op_handle_));
}

TEST_F(Se050InvalidInput, AES_operations_invalid_params) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_RAW;
    const uint8_t set_data[] = AES_128_TEST_KEY;
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_operation_handle_t op_handle_enc;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    // keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();
    const uint8_t id[] = {0x90, 0x21, 0x34, 0x90};
    const uint8_t data_to_be_enc[] = {"RANDOM DATA TO BE ENCRYPTED"};
    keymaster_blob_t input, signature, encryptedBlob;
    input.data = (const uint8_t*)&data_to_be_enc;
    input.data_length = sizeof(data_to_be_enc);

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .AesEncryptionKey(128)
                                .Authorization(TAG_BLOCK_MODE, KM_MODE_ECB)
                                .Authorization(TAG_PADDING, KM_PAD_NONE)
                                .build());

    AuthorizationSet op_params(AuthorizationSetBuilder()
                                   .Authorization(TAG_BLOCK_MODE, KM_MODE_CTR)
                                   .Authorization(TAG_PADDING, KM_PAD_PKCS7)
                                   .build());

    AuthorizationSet op_params1(AuthorizationSetBuilder()
                                    .Authorization(TAG_BLOCK_MODE, KM_MODE_ECB)
                                    .Authorization(TAG_PADDING, KM_PAD_NONE)
                                    .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    EXPECT_EQ(KM_ERROR_INCOMPATIBLE_PADDING_MODE,
              newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &op_params, &out_params,
                             &op_handle_enc));
    EXPECT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &op_params1,
                                          &out_params, &op_handle_enc));
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH,
              newdev2->finish(newdev2, op_handle_enc, &tmp_params, &input, &signature, &out_params,
                              &encryptedBlob));
}

TEST_F(Se050InvalidInput, AES_GCM_invalidtag) {

#if SSS_HAVE_SE05X_VER_GTE_07_02
    keymaster_key_format_t key_format = KM_KEY_FORMAT_RAW;
    const uint8_t set_data[] = AES_128_TEST_KEY;
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params;
    keymaster_operation_handle_t op_handle_enc;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    // keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();
    const uint8_t id[] = {0x90, 0xFF, 0xE1, 0x90};
    const uint8_t data_to_be_enc[] = {"RANDOM DATA TO BE ENCRYPTED"};
    keymaster_blob_t input = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_enc;
    input.data_length = sizeof(data_to_be_enc);

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .AesEncryptionKey(128)
                                .Authorization(TAG_BLOCK_MODE, KM_MODE_GCM)
                                .Authorization(TAG_PADDING, KM_PAD_NONE)
                                .Authorization(TAG_MAC_LENGTH, 128)
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));

    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    AuthorizationSet op_params(AuthorizationSetBuilder()
                                .Authorization(TAG_BLOCK_MODE, KM_MODE_GCM)
                                .Authorization(TAG_PADDING, KM_PAD_NONE)
                                .Authorization(TAG_MAC_LENGTH, 96)
                                .build());
    EXPECT_EQ(KM_ERROR_INVALID_MAC_LENGTH,
              newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &op_params, &out_params,
                             &op_handle_enc));
#else
    GTEST_COUT << " AES GCM feature is not supported for SE050 " << std::endl;
#endif

}

TEST_F(Se050InvalidInput, AES_GCM_aadOutofOrder) {

#if SSS_HAVE_SE05X_VER_GTE_07_02
    keymaster_key_format_t key_format = KM_KEY_FORMAT_RAW;
    const uint8_t set_data[] = AES_128_TEST_KEY;
    keymaster_purpose_t myPurpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_key_param_set_t out_params;
    keymaster_operation_handle_t op_handle_enc;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    // keymaster2_device_t* my_km2_device = mydevice->keymaster2_device();
    const uint8_t id[] = {0x90, 0xFF, 0xE1, 0xE1};
    const uint8_t data_to_be_enc[] = {"RANDOM DATA TO BE ENCRYPTED"};
    const uint8_t aad[] = {"1234567890123456"};
    keymaster_blob_t input, outBlob, dummyBlob_ = {nullptr, 0};
    input.data = (const uint8_t*)&data_to_be_enc;
    input.data_length = sizeof(data_to_be_enc);
    size_t input_consumed = 0 ;

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .AesEncryptionKey(128)
                                .Authorization(TAG_BLOCK_MODE, KM_MODE_GCM)
                                .Authorization(TAG_PADDING, KM_PAD_NONE)
                                .Authorization(TAG_MAC_LENGTH, 128)
                                .build());

    AuthorizationSet tmp_params(AuthorizationSetBuilder()
                                .Authorization(TAG_ASSOCIATED_DATA, aad, sizeof(aad))
                                .build());

    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));

    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_encrypt, &myBlob_, &params, &out_params,
                                          &op_handle_enc));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_enc, &tmp_params, &dummyBlob_/*input*/,
                                           &input_consumed, &out_params, &outBlob));
    EXPECT_EQ(0U, input_consumed);
    EXPECT_EQ(0U, outBlob.data_length);

    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_enc, &tmp_params, &input,
                                           &input_consumed, &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_INVALID_TAG, newdev2->update(newdev2, op_handle_enc, &tmp_params, &dummyBlob_/*input*/,
                                           &input_consumed, &out_params, &outBlob));
#else
    GTEST_COUT << " AES GCM feature is not supported for SE050 "<< std::endl;
#endif

}

TEST_F(Se050InvalidInput, attestKey_AES) {
    keymaster_key_characteristics_t myKeyCharac;

    uint8_t attestation_challenge[10] = {0x00};
    const uint8_t application_id[32] = "Unique Application ID";
    keymaster_cert_chain_t cert_chain = {nullptr, 0};

    AuthorizationSet params(AuthorizationSetBuilder().AesEncryptionKey(128).build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, attestation_challenge,
                           sizeof(attestation_challenge))
            .Authorization(TAG_ATTESTATION_APPLICATION_ID, application_id, sizeof(application_id))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
    EXPECT_EQ(KM_ERROR_INCOMPATIBLE_ALGORITHM,
              newdev2->attest_key(newdev2, &myBlob_, &attest_params, &cert_chain));
}

TEST_F(Se050InvalidInput, attestKey_HMAC) {
    keymaster_key_characteristics_t myKeyCharac;

    uint8_t attestation_challenge[10] = {0x00};
    const uint8_t application_id[32] = "Unique Application ID";
    keymaster_cert_chain_t cert_chain;

    AuthorizationSet params(AuthorizationSetBuilder()
                                .HmacKey(128)
                                .Digest(KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_MIN_MAC_LENGTH, 128)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, attestation_challenge,
                           sizeof(attestation_challenge))
            .Authorization(TAG_ATTESTATION_APPLICATION_ID, application_id, sizeof(application_id))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
    EXPECT_EQ(KM_ERROR_INCOMPATIBLE_ALGORITHM,
              newdev2->attest_key(newdev2, &myBlob_, &attest_params, &cert_chain));
}

typedef keymasterInjectTest Se050InjectKey;

TEST_F(Se050InjectKey, injectECC256) {
    // inject key
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = ECC_PAIR_256_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id[] = {0x7c, 0x00, 0x00, 0x01};  // (uint8_t) {0x73,0x48,0x34,0x80};

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
}

TEST_F(Se050InjectKey, sign_EC256_begin_update_finish_injected_key) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x20, 0x23, 0x33, 0x20};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params, tmp_params;

    keymaster_blob_t outBlob = {nullptr, 0};
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = TP_DUMMY_EC256_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, data_to_be_signed, sizeof(data_to_be_signed))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->begin(newdev2, myPurpose, &myBlob_, &attest_params, &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input, &input_consumed,
                                           &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));
}

TEST_F(Se050InjectKey, verify_EC256_begin_update_finish_injected_key) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x83, 0x92, 0x83, 0x10};
    const uint8_t data_to_be_signed[] = "Random Data to be signed";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_blob_t outBlob, updateoutBlob;
    keymaster_blob_t input = {nullptr, 0};
    input.data = data_to_be_signed;
    input.data_length = sizeof(data_to_be_signed);
    size_t input_consumed = 0;

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = TP_DUMMY_EC256_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    // ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, data_to_be_signed, sizeof(data_to_be_signed))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input,
                                           &input_consumed, &out_params, &outBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &signature,
                                           &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &input, &outBlob,
                                           &out_params, &outBlob));
}

TEST_F(Se050InjectKey, injectRSA2048) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = RSA_PAIR_2048_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id[] = {0x7c, 0x00, 0x00, 0x02};

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));
}

TEST_F(Se050InjectKey, Bosch_NonReadable_Key_RSA4096) {
    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = TP_DUMMY_RSA4096_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id[] = {0x00, 0x00, 0x00, 0x05};

    keymaster_key_format_t export_format = KM_KEY_FORMAT_X509;
    keymaster_blob_t *client_id = nullptr, export_data, *app_data = nullptr;

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(4096, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myChar));

    ASSERT_EQ(KM_ERROR_OK, newdev2->export_key(newdev2, export_format, &myBlob_, client_id, app_data,
                                               &export_data));
}


TEST_F(Se050InjectKey, sign_RSA2048_begin_update_finish_injected_key) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0xab, 0xcd, 0xef, 0x10};
    const uint8_t* data_to_be_signed = (uint8_t*)"RANDOM DATA TO BE SIGNED";
    const uint8_t* data_to_be_update = (uint8_t*)"RANDOM DATA TO BE UPDATED";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_blob_t outBlob, updateoutBlob = {nullptr, 0};
    keymaster_blob_t input1, input2;
    input1.data = data_to_be_signed;
    input1.data_length = sizeof(data_to_be_signed);
    input2.data = data_to_be_update;
    input2.data_length = sizeof(data_to_be_update);
    size_t input_consumed = 0;

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = TP_DUMMY_RSA2048_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input1,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input2,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &updateoutBlob,
                                           &signature, &out_params, &outBlob));
}

/*
 *Generate RSA 1024-bit keypair in SE050
 *Perform sign and verify operations on some random data
 *32-bit Keyid should be unique (required for SE050)
 * */
TEST_F(Se050InjectKey, verify_RSA2048_begin_update_finish_injected_key) {
    keymaster_key_characteristics_t myKeyCharac;

    const uint8_t id[] = {0x83, 0x92, 0x83, 0x10};
    //  const uint8_t* data_to_be_signed = (uint8_t*) "RANDOM DATA TO BE SIGNED";
    const uint8_t data_to_be_signed2[] = "RANDOM DATA TO BE SIGNED";
    const uint8_t data_to_be_update[] = "RANDOM DATA TO BE UPDATE";
    keymaster_blob_t signature = {nullptr, 0};
    keymaster_purpose_t myPurpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t myPurpose_verify = KM_PURPOSE_VERIFY;
    keymaster_key_param_set_t out_params, tmp_params;
    keymaster_blob_t outBlob, updateoutBlob = {nullptr, 0};
    keymaster_blob_t input1, input2;
    input1.data = (const uint8_t*)&data_to_be_signed2;
    input1.data_length = sizeof(data_to_be_signed2);
    input2.data = (const uint8_t*)&data_to_be_update;
    input2.data_length = sizeof(data_to_be_update);
    size_t input_consumed = 0;

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = TP_DUMMY_RSA2048_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);

    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .RsaSigningKey(2048, 65537)
                                .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                .Authorization(TAG_PADDING, KM_PAD_RSA_PSS)
                                .build());

    // keymaster2_device_t* newdev2 = mydevice->keymaster2_device();
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(AuthorizationSetBuilder()
                                       .Authorization(TAG_ATTESTATION_CHALLENGE, data_to_be_signed2,
                                                      sizeof(data_to_be_signed2))
                                       .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
                                       .Authorization(TAG_PADDING, KM_PAD_RSA_PSS));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_sign, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input1,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input2,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &updateoutBlob,
                                           &signature, &out_params, &outBlob));

    ASSERT_EQ(KM_ERROR_OK, newdev2->begin(newdev2, myPurpose_verify, &myBlob_, &attest_params,
                                          &out_params, &op_handle_));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input1,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->update(newdev2, op_handle_, &tmp_params, &input2,
                                           &input_consumed, &out_params, &updateoutBlob));
    ASSERT_EQ(KM_ERROR_OK, newdev2->finish(newdev2, op_handle_, &tmp_params, &updateoutBlob,
                                           &outBlob, &out_params, &outBlob));
}

TEST_F(Se050InjectKey, deleteAllInjected) {
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->delete_all_keys(newdev2));
}

typedef KeymasterHALTest Se050AttestTest;

TEST_F(Se050AttestTest, attest_EC256) {

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = ECC_PAIR_256_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id[] = {0x7c, 0x00, 0x00, 0x05};  // (uint8_t) {0x73,0x48,0x34,0x80};
    uint8_t attestation_challenge[10] =  "challenge";
    size_t len = sizeof(attestation_challenge);
    const uint8_t application_id[32] = "attest_app_id";
    keymaster_cert_chain_t cert_chain;

    keymaster_key_characteristics_t myChar , myKeyCharac;
    AuthorizationSet params1(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params1, key_format, &key_data, &myBlob_, &myChar));

    AuthorizationSet params(
        AuthorizationSetBuilder()
        .Authorization(TAG_NO_AUTH_REQUIRED)
        .EcdsaSigningKey(256)
        .Digest(KM_DIGEST_SHA_2_256)
        .Authorization(TAG_INCLUDE_UNIQUE_ID)
        .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));
    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
        .Authorization(TAG_ATTESTATION_CHALLENGE, attestation_challenge,
            sizeof(attestation_challenge))
        .Authorization(TAG_ATTESTATION_APPLICATION_ID, application_id, sizeof(application_id)));
    ASSERT_EQ(KM_ERROR_OK, newdev2->attest_key(newdev2, &myBlob_, &attest_params, &cert_chain));
    EXPECT_GE(cert_chain.entry_count, 2U);
    EXPECT_TRUE(verify_chain(cert_chain));
    AuthorizationSet sw_enforced(myKeyCharac.sw_enforced);
    AuthorizationSet hw_enforced(myKeyCharac.hw_enforced);
    EXPECT_TRUE(verify_attestation_record(attestation_challenge, len, sw_enforced, hw_enforced, 3,
                                          KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT, cert_chain.entries[0]));

    keymaster_free_cert_chain(&cert_chain);
}

TEST_F(Se050AttestTest, attest_RSA4096) {

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = RSA_PAIR_4096_TEST_KEY;
    const uint8_t set_data1[] = RSA_PAIR2_4096_TEST_KEY;
    keymaster_blob_t key_data, key_data1;
    key_data1.data = (const uint8_t*)&set_data1;
    key_data1.data_length = sizeof(set_data1);
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id1[] = {0x7c, 0x00, 0x00, 0x04};

    keymaster_key_characteristics_t myKeyCharac;
    uint8_t attestation_challenge[10] = "challenge";
    size_t len = sizeof(attestation_challenge);
    const uint8_t application_id[32] = "attest_app_id";
    keymaster_cert_chain_t cert_chain;

    keymaster_key_characteristics_t myChar;
    AuthorizationSet params1(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id1, sizeof(id1))
                                .RsaSigningKey(4096, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .Digest(KM_DIGEST_SHA_2_256)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params1, key_format, &key_data1, &myBlob_, &myChar));

    AuthorizationSet params(AuthorizationSetBuilder()
                                .RsaSigningKey(4096, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .Digest(KM_DIGEST_SHA_2_256)
                                .build());
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params, key_format, &key_data, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
            .Authorization(TAG_ATTESTATION_CHALLENGE, attestation_challenge,
                           sizeof(attestation_challenge))
            .Authorization(TAG_ATTESTATION_APPLICATION_ID, application_id, sizeof(application_id))
            .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)
            .Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA));
    ASSERT_EQ(KM_ERROR_OK, newdev2->attest_key(newdev2, &myBlob_, &attest_params, &cert_chain));
    EXPECT_GE(cert_chain.entry_count, 2U);
    EXPECT_TRUE(verify_chain(cert_chain));
    AuthorizationSet sw_enforced(myKeyCharac.sw_enforced);
    AuthorizationSet hw_enforced(myKeyCharac.hw_enforced);
    EXPECT_TRUE(verify_attestation_record(attestation_challenge, len, sw_enforced, hw_enforced, 3,
                                          KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT, cert_chain.entries[0]));

    keymaster_free_cert_chain(&cert_chain);
}


TEST_F(Se050AttestTest, RsaAttestationRequiresAppId) {

    keymaster_key_format_t key_format = KM_KEY_FORMAT_PKCS8;
    const uint8_t set_data[] = RSA_PAIR2_4096_TEST_KEY;
    keymaster_blob_t key_data;
    key_data.data = (const uint8_t*)&set_data;
    key_data.data_length = sizeof(set_data);
    const uint8_t id1[] = {0x7c, 0x09, 0x00, 0x04};

    uint8_t attestation_challenge[10] = "challenge";
    keymaster_key_characteristics_t myChar;
    keymaster_cert_chain_t cert_chain;
    AuthorizationSet params1(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id1, sizeof(id1))
                                .RsaSigningKey(4096, 65537)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK,
              newdev2->import_key(newdev2, &params1, key_format, &key_data, &myBlob_, &myChar));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
        .Authorization(TAG_ATTESTATION_CHALLENGE, attestation_challenge,
            sizeof(attestation_challenge)));

    ASSERT_EQ(KM_ERROR_ATTESTATION_APPLICATION_ID_MISSING,
        newdev2->attest_key(newdev2, &myBlob_, &attest_params, &cert_chain));
}


TEST_F(Se050AttestTest, EcAttestationRequiresAttestationAppId) {
    keymaster_key_characteristics_t myKeyCharac;
    uint8_t attestation_challenge[10] = "challenge";
    const uint8_t id[] = {0x7c, 0x00, 0x42, 0x02};  //{0x32,0x09,0x42,0x02};
    keymaster_cert_chain_t cert_chain;
    AuthorizationSet params(AuthorizationSetBuilder()
                                .Authorization(TAG_INCLUDE_UNIQUE_ID)
                                .Authorization(TAG_UNIQUE_ID, id, sizeof(id))
                                .EcdsaSigningKey(256)
                                .Digest(KM_DIGEST_NONE)
                                .build());
    ASSERT_EQ(KM_ERROR_OK, ConfigureDevice(newdev2));
    ASSERT_EQ(KM_ERROR_OK, newdev2->generate_key(newdev2, &params, &myBlob_, &myKeyCharac));

    AuthorizationSet attest_params(
        AuthorizationSetBuilder()
        .Authorization(TAG_ATTESTATION_CHALLENGE, attestation_challenge,
            sizeof(attestation_challenge)));

    ASSERT_EQ(KM_ERROR_ATTESTATION_APPLICATION_ID_MISSING,
        newdev2->attest_key(newdev2, &myBlob_, &attest_params, &cert_chain));
}


}  // namespace test
}  // namespace keymaster
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    return result;
}
