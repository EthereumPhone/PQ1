#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

import sys
from util import *
import test_mbedtls_alt_rsa

def printUsage():
    print('Invalid input argument')
    print('Run as -  test_mbedtls_alt_ssl_rsa.py  <rs_type|all> <jrcpv2|vcom> <ip_address|port_name>  <se050> <auth_type> <auth_key>')
    print(f"supported Key Types : {rsa_types}")
    print(f"supported auth types : {auth_types}")
    print(f"connection data : COM10, None, 127.0.0.1:8050")
    print(f"supported connection types: {connection_types}")
    print('Example invocation - test_mbedtls_alt_ssl_rsa.py all jrcpv2 127.0.0.1:8050 se050 PlatformSCP "<path_to_scp_keys>"')
    print('Example invocation - test_mbedtls_alt_ssl_rsa.py all vcom COM10 se050 PlatformSCP "<path_to_scp_keys>"')
    print('Example invocation - test_mbedtls_alt_ssl_rsa.py all vcom COM10 se050 None')
    print('Example invocation - test_mbedtls_alt_ssl_rsa.py all vcom COM10 se050 ECKey')
    print('Example invocation - create_and_provision_rsa_keys.py all t1oi2c none se050 PlatformSCP "<path_to_scp_keys>"')
    sys.exit()

if len(sys.argv) < 5:
    printUsage()

if len(sys.argv) > 5 and sys.argv[5] == "PlatformSCP":
    if len(sys.argv) < 7:
        printUsage()

if test_mbedtls_alt_rsa.doTest(sys.argv, "ssl2", __file__) != 0:
        printUsage()

