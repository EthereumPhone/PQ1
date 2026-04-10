/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <bootutil/sign_key.h>

#include <mcuboot_config.h>

#if defined( MCUBOOT_SIGN_RSA )

extern const unsigned char rsa_pub_key[];
extern const unsigned int rsa_pub_key_len;

const struct bootutil_key bootutil_keys[] =
{
    {
        .key = rsa_pub_key,
        .len = &rsa_pub_key_len,
    }
};
const int bootutil_key_cnt = 1;

#elif defined( MCUBOOT_SIGN_EC256 )

extern const unsigned char ecdsa_pub_key[];
extern const unsigned int ecdsa_pub_key_len;

const struct bootutil_key bootutil_keys[] =
{
    {
        .key = ecdsa_pub_key,
        .len = &ecdsa_pub_key_len,
    }
};
const int bootutil_key_cnt = 1;

#elif defined( CONFIG_BOOT_SIGNATURE_TYPE_ROM )
/* Don't need to define keys for HAB method */
#else /* if defined( MCUBOOT_SIGN_RSA ) || defined( MCUBOOT_SIGN_EC256 ) */
#error "Please define a signature type used to sign the MCUBoot images."
#endif /* if defined( MCUBOOT_SIGN_RSA ) || defined( MCUBOOT_SIGN_EC256 ) */


#if defined( MCUBOOT_ENCRYPT_RSA )
extern const unsigned char enc_priv_key[];
extern const unsigned int enc_priv_key_len;

const struct bootutil_key bootutil_enc_key =
{
    .key = enc_priv_key,
    .len = &enc_priv_key_len,
};
#elif defined( MCUBOOT_ENCRYPT_KW )
#error "Encrypted images with AES-KW is not implemented yet."
#endif /* if defined( MCUBOOT_ENCRYPT_RSA ) */
