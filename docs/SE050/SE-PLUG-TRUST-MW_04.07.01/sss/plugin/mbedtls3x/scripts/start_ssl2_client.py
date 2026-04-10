#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

import os
import sys
from util import *

server_address = "localhost"

keyTypeMap = {
    'prime192v1':'secp192r1',
    'secp224r1':'secp224r1',
    'prime256v1':'secp256r1',
    'secp384r1':'secp384r1',
    'secp521r1':'secp521r1',
    'brainpoolP256r1':'brainpoolP256r1',
    'brainpoolP384r1':'brainpoolP384r1',
    'brainpoolP512r1':'brainpoolP512r1',
    # 'secp192k1':'secp192k1',
    # 'secp224k1':'secp224k1',
    'secp256k1':'secp256k1',
    'rsa1024':'',
    'rsa2048':'',
    'rsa3072':'',
    'rsa4096':'',
}

def printUsage():
    print('Invalid input argument')
    print('Run as -  start_ssl2_server.py  <keyType> <cipher_suite>')
    print('supported key types -')
    print(ecc_types_cryptography_44)
    print(rsa_types)
    print('Example invocation - start_ssl2_client.py prime256v1 TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA')
    print('Example invocation - start_ssl2_client.py rsa2048 TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256')
    print('Example invocation - start_ssl2_client.py rsa2048 TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256')
    sys.exit()


if len(sys.argv) != 3:
    printUsage()
else:
    cur_dir = os.path.abspath(os.path.dirname(__file__))
    keytype = sys.argv[1]
    cipher_suite = sys.argv[2];
    if isValidKeyType(keytype) != True:
        printUsage()
    mbedtls_keyType = keyTypeMap[keytype]
    curves = ""
    if isValidECKeyType(keytype) == True:
        curves = "curves=" + mbedtls_keyType

    tls_rootCA = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca.cer')
    tls_client_cert = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client.cer')
    tls_client_ref_key = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client_key_ref.pem')

    mbedtls_client = os.path.join(cur_dir, '..', '..', '..', '..', 'tools', 'mbedtls_3x_client')
    run("%s server_name=%s exchanges=1 force_version=tls12 debug_level=1 ca_file=%s auth_mode=required key_file=%s crt_file=%s force_ciphersuite=%s"
        %(mbedtls_client, server_address, tls_rootCA, tls_client_ref_key, tls_client_cert, cipher_suite))
