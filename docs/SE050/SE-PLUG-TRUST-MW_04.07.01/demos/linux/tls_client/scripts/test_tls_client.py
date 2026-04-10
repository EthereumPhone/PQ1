#
# Copyright 2019,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

import subprocess
import sys
import logging
import time
log = logging.getLogger(__name__)


def do_tls_client_test(ip_address, cipher):
    log.info("Starting tlsServer with cipher: %s" % cipher)
    server_cmd = "./tlsServer.sh %s" % (cipher,)
    tls_server = subprocess.Popen(server_cmd, shell=True,)
    log.info("Waiting for 2 seconds to initialize server")
    time.sleep(2)
    log.info("Starting tlsSeClient with ip_address: %s, cipher: %s" % (ip_address, cipher))
    tls_se_client = subprocess.Popen("./tlsSeClient_3_0.sh %s %s" % (ip_address, cipher),
                                      shell=True,)
    log.info("Waiting for 10 seconds to waiting for the client to complete")
    time.sleep(10)
    subprocess.Popen("pkill -9 openssl", shell=True,)


def do_tls_extended_client_test(ip_address, cipher):
    log.info("Starting tlsServer with cipher: %s" % cipher)
    server_cmd = "./tlsServer.sh %s" % cipher
    tls_server = subprocess.Popen(server_cmd, shell=True,)
    log.info("Waiting for 2 seconds to initialize server")
    time.sleep(2)
    if cipher in ["ECDHE", "ECDH", "both", "max"]:
        key_type = "EC"
    else:
        key_type = "RSA"
    log.info("Starting tlsExtendedSeClient with ip_address: %s" % (ip_address,))
    tls_se_ext_client = subprocess.Popen("./tlsExtendedSeClient.sh %s %s" % (ip_address, key_type,),  shell=True,)
    log.info("Waiting for 10 seconds to waiting for the client to complete")
    time.sleep(10)
    subprocess.Popen("pkill -9 openssl", shell=True,)


def usage():
    log.info("Please provide as first argument:  CONNECTION_PARAMETER. Default: \"None\"")
    log.info("Please provide as second argument:  cipher type. [ECDHE|ECDH|both|max|RSA]")
    log.info("Usage Example:")
    log.info("               python %s 127.0.0.1 ECDHE" % (__file__,))
    log.info("               python %s 127.0.0.1 RSA" % (__file__,))


if __name__ == '__main__':
    logging.basicConfig(format='%(message)s', level=logging.DEBUG)
    if len(sys.argv) > 2:
        ip_address = sys.argv[1]
        cipher = sys.argv[2]
        do_tls_client_test(ip_address, cipher)
        log.info("Waiting for 10 seconds to tls_client test to complete")
        time.sleep(10)
        do_tls_extended_client_test(ip_address, cipher)
    else:
        usage()

