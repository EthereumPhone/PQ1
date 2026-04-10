/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef SYSTEM_KEYMASTER_SE050_KEYMASTER_ATTESTATION_RECORD_H_
#define SYSTEM_KEYMASTER_SE050_KEYMASTER_ATTESTATION_RECORD_H_

#include <keymaster/authorization_set.h>
#include <keymaster/keymaster_context.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace keymaster {

const size_t kMaximumAttestationChallengeLength = 128;

keymaster_error_t get_certificate_blob(X509* certificate, keymaster_blob_t* blob);
keymaster_error_t add_key_usage_extension(const AuthorizationSet& tee_enforced,
                                          const AuthorizationSet& sw_enforced, X509* certificate);
bool copy_attestation_chain(keymaster_algorithm_t sign_algorithm, uint8_t* root_ca_cert,
                            size_t root_ca_cert_size, keymaster_cert_chain_t* chain,
                            keymaster_error_t* error);
bool add_public_key(EVP_PKEY* key, X509* certificate, keymaster_error_t* error);
bool add_attestation_extension(const AuthorizationSet& attest_params,
                               const AuthorizationSet& tee_enforced,
                               const AuthorizationSet& sw_enforced, X509* certificate,
                               keymaster_error_t* error);
}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_SE050_KEYMASTER_ATTESTATION_RECORD_H_