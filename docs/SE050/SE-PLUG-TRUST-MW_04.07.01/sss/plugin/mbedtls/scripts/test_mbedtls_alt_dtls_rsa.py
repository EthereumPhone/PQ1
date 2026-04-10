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
    print('Run as -  test_mbedtls_alt_dtls_rsa.py  <rsa_type|all> <jrcpv2|vcom> <ip_address|port_name> <auth_type> <auth_key>')
    print('supported rsa_type -')
    print(rsa_types)
    print('supported auth types -')
    print(auth_types)
    print('Example invocation - test_mbedtls_alt_dtls_rsa.py all jrcpv2 127.0.0.1:8050')
    sys.exit()


if len(sys.argv) < 4:
    printUsage()
else:
    if test_mbedtls_alt_rsa.doTest(sys.argv, "dtls", __file__) != 0:
        printUsage()
