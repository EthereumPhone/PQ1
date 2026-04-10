#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

# Create Keys for MbedTLS ALT testing
#
# Preconditions
# - Openssl installed
#

import os
import sys
import logging
import re
import shlex
import subprocess
import os.path
from util import *
import sss.sss_api as apis

KeyLenMap = {
    'rsa1024': 1024,
    'rsa2048': 2048,
    'rsa3072': 3072,
    'rsa4096': 4096,
}

CLIENT_CERT_KEY_ID = 0x20181002
CLIENT_KEY_PAIR_ID = 0x20181001
ROOT_CA_PUB_KEY_ID = 0x7DCCBB22


def run(cmd_str, ignore_result=0, exp_retcode=0):
    print("Running command: %s" %cmd_str)
    if 'nt' in os.name:
        cmd = cmd_str
    else:
        cmd = shlex.split(cmd_str)

    pipes = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    std_out, std_err = pipes.communicate()
    std_out = std_out.strip()
    std_err = std_err.strip()
    print(std_err)
    if not ignore_result:
        if pipes.returncode != exp_retcode:
            print("Command execution failed.")
        else:
            print("Command execution was successful.")
    assert pipes.returncode == exp_retcode


def printUsage():
    print('Invalid input argument')
    print('Run as -  create_and_provision_rsa_keys.py  <keyType> <connection_type> <connection_string> <iot_se (optional. Default - se05x)> <auth (optional. Default - None)> <auth_key>')
    print(f"supported Key Types : {rsa_types}")
    print(f"supported auth types : {auth_types}")
    print(f"connection data : COM10, None, 127.0.0.1:8050")
    print(f"supported connection types: {connection_types}")
    print('Example invocation - create_and_provision_rsa_keys.py rsa2048 jrcpv2 127.0.0.1:8050')
    print('Example invocation - create_and_provision_rsa_keys.py rsa2048 jrcpv2 127.0.0.1:8050 se05x PlatformSCP "<path_to_scp_keys>"')
    print('Example invocation - create_and_provision_rsa_keys.py rsa2048 vcom COM1')
    print('Example invocation - create_and_provision_rsa_keys.py rsa2048 vcom COM1 se05x PlatformSCP "<path_to_scp_keys>"')
    print('Example invocation - create_and_provision_rsa_keys.py rsa2048 vcom COM1 se05x ECKey')
    print('Example invocation - create_and_provision_rsa_keys.py rsa2048 vcom COM1')
    print('Example invocation - create_and_provision_rsa_keys.py rsa2048 t1oi2c none se05x PlatformSCP "<path_to_scp_keys>"')
    sys.exit()


print (len(sys.argv))
if len(sys.argv) < 4:
    printUsage()

cur_dir = os.path.abspath(os.path.dirname(__file__))

keytype = sys.argv[1]
if isValidRSAKeyType(keytype) != True:
    printUsage()

connection_type = sys.argv[2];
connection_string = sys.argv[3];

iot_se = 'se05x'
if len(sys.argv) > 4:
    iot_se = sys.argv[4]

auth_type = "None"
if len(sys.argv) > 5:
    auth_type = sys.argv[5]

auth_key  = "None"
if len(sys.argv) > 6:
    auth_key = sys.argv[6]

if auth_type == "PlatformSCP" and len(sys.argv) < 7:
    printUsage()

if os.path.isdir(os.path.join(cur_dir, '..', 'keys', keytype)) == False:
    os.mkdir(os.path.join(cur_dir, '..', 'keys', keytype))

KEY_TYPE_FILE_NAME = keytype + '.pem'
KEY_TYPE_FILE = os.path.join(cur_dir, '..', 'keys', keytype, KEY_TYPE_FILE_NAME)

ROOT_CA_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca.pem')
ROOT_CA_CER = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca.cer')
ROOT_CA_SRL = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca.srl')
ROOT_CA_KEY_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca_key.pem')
ROOT_CA_KEY_PUBLIC_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca_pub_key.pem')
ROOT_CA_KEY_DER = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca_key.der')

CLIENT_KEY_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client_key.pem')
CLIENT_KEY_PUBLIC_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client_key_pub.pem')
CLIENT_CER = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client.cer')
CLIENT_CSR = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client_key.csr')
CLIENT_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client.pem')
CLIENT_KEY_REF_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client_key_ref.pem')

SERVER_KEY_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_server_key.pem')
SERVER_CERTIFICATE = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_server.cer')
SERVER_CSR = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_server_key.csr')
SERVER_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_server.pem')
SERVER_CER = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_server.cer')

if sys.platform.startswith("win"):
    openssl = os.path.join(cur_dir, '..', '..', '..', '..', 'ext', 'openssl', 'bin', 'openssl.exe')
    openssl_config_file = os.path.join(cur_dir, '..', '..', '..', '..', 'ext', 'openssl', 'ssl', 'openssl.cnf')
    os.environ['OPENSSL_CONF'] = openssl_config_file
else:
    openssl = 'openssl'

SUBJECT = "/C=AB/ST=XY/L=LH/O=NXP-Demo-CA/OU=Demo-Unit/CN=localhost"
KEY_LEN = KeyLenMap[keytype]


cmd_str = "\"%s\" genrsa -out \"%s\" \"%s\" " % (openssl, ROOT_CA_KEY_PEM, KEY_LEN)
run(cmd_str)

cmd_str = "\"%s\" req -x509 -new -nodes -key \"%s\" -sha256 -days 1000 -out \"%s\" -subj \"%s\"" % (openssl, ROOT_CA_KEY_PEM, ROOT_CA_PEM, SUBJECT)
run(cmd_str)

cmd_str = "\"%s\" x509 -outform der -in \"%s\" -out \"%s\" " % (openssl, ROOT_CA_PEM, ROOT_CA_CER)
run(cmd_str)

cmd_str = "\"%s\" x509 -pubkey -noout -in \"%s\" -out \"%s\"" % (openssl, ROOT_CA_PEM, ROOT_CA_KEY_PUBLIC_PEM)
run(cmd_str)



cmd_str = "\"%s\" genrsa -out \"%s\" \"%s\"" % (openssl, CLIENT_KEY_PEM, KEY_LEN)
run(cmd_str)

cmd_str = "\"%s\" req -new -key \"%s\" -out \"%s\" -subj \"%s\" " % (openssl, CLIENT_KEY_PEM, CLIENT_CSR, SUBJECT)
run(cmd_str)

cmd_str = "\"%s\" x509 -req -in \"%s\" -CA \"%s\" -CAkey \"%s\" -CAcreateserial -out \"%s\" -days 1000 -sha256" % (openssl, CLIENT_CSR, ROOT_CA_PEM, ROOT_CA_KEY_PEM, CLIENT_PEM)
run(cmd_str)

cmd_str = "\"%s\" x509 -outform der -in \"%s\" -out \"%s\"" % (openssl, CLIENT_PEM, CLIENT_CER)
run(cmd_str)


cmd_str = "\"%s\" genrsa -out \"%s\" \"%s\"" % (openssl, SERVER_KEY_PEM, KEY_LEN)
run(cmd_str)

cmd_str = "\"%s\" req -new -key \"%s\" -out \"%s\" -subj \"%s\" " % (openssl, SERVER_KEY_PEM, SERVER_CSR, SUBJECT)
run(cmd_str)

cmd_str = "\"%s\" x509 -req -in \"%s\" -CA \"%s\" -CAkey \"%s\" -CAcreateserial -out \"%s\" -days 1000 -sha256" % (openssl, SERVER_CSR, ROOT_CA_PEM, ROOT_CA_KEY_PEM, SERVER_PEM)
run(cmd_str)

cmd_str = "\"%s\" x509 -outform der -in \"%s\" -out \"%s\"" % (openssl, SERVER_PEM, SERVER_CER)
run(cmd_str)


#Provision the keys

session_close(None)
session = session_open(iot_se, connection_string, connection_type, auth_type, auth_key)
if session is None:
    print("Error in session_open")
    sys.exit()

reset(session)

# Inject client certificate to the Secure Element
status = set_cert(session, CLIENT_CERT_KEY_ID, CLIENT_PEM)
if status != apis.kStatus_SSS_Success:
    print("Error in set_cert")

# Inject root ca public key to the Secure Element
status = set_rsa_pub(session, ROOT_CA_PUB_KEY_ID, ROOT_CA_KEY_PUBLIC_PEM)
if status != apis.kStatus_SSS_Success:
    print("Error in set_rsa_pub")

# Inject client rsa pair key to the Secure Element
status = set_rsa_pair(session, CLIENT_KEY_PAIR_ID, CLIENT_KEY_PEM)
if status != apis.kStatus_SSS_Success:
    print("Error in set_rsa_pair")

# Create ecc ref key
status = refpem_rsa(session, CLIENT_KEY_PAIR_ID, CLIENT_KEY_REF_PEM)
if status != apis.kStatus_SSS_Success:
    print("Error in refpem_ecc_pair")

session_close(None)
