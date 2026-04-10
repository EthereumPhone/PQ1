#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

import os
import sys
from util import *

def printUsage():
    print('Invalid input argument')
    print('Run as -  start_ssl2_server.py  <keyType> ')
    print('supported key types -')
    print(ecc_types_cryptography_44)
    print(rsa_types)
    print('Example invocation - start_ssl2_server.py prime256v1')
    sys.exit()

if len(sys.argv) != 2:
    printUsage()
else:
    cur_dir = os.path.abspath(os.path.dirname(__file__))
    keytype = sys.argv[1]
    if isValidKeyType(keytype) != True:
        printUsage()
    tls_rootCA = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca.cer')
    tls_server_key = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_server_key.pem')
    tls_server_cer = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_server.cer')
    mbedtls_server = os.path.join(cur_dir, '..', '..', '..', '..', 'tools', 'mbedtls_ex_orig_ssl_server2')
    run("%s exchanges=1 force_version=tls12 debug_level=1 ca_file=%s auth_mode=required key_file=%s crt_file=%s"
        %(mbedtls_server, tls_rootCA, tls_server_key, tls_server_cer))
