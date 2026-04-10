#
# Copyright 2019,2025 NXP
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

PycliKeyTypeMap = {
    'prime192v1':'NIST_P192',
    'secp224r1':'NIST_P224',
    'prime256v1':'NIST_P256',
    'secp384r1':'NIST_P384',
    'secp521r1':'NIST_P521',
    'brainpoolP256r1':'Brainpool256',
    'brainpoolP384r1':'Brainpool384',
    'brainpoolP512r1':'Brainpool512',
    'secp192k1':'Secp192k1',
    'secp224k1':'Secp224k1',
    'secp256k1':'Secp256k1',
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
    if not ignore_result:
        if pipes.returncode != exp_retcode:
            print("Command execution failed.")
        else:
            print("Command execution was successful.")
    assert pipes.returncode == exp_retcode


def printUsage():
    print('Invalid input argument')
    print('Run as -  create_and_provision_ecc_keys.py  <keyType> <connection_type> <connection_string> <iot_se (optional. Default - se05x)> <auth (optional. Default - None)> <auth_key>')
    print(f"supported Key Types : {ecc_types_cryptography_44}")
    print(f"supported auth types : {auth_types}")
    print(f"connection data : COM10, None, 127.0.0.1:8050")
    print(f"supported connection types: {connection_types}")
    print('Example invocation - create_and_provision_ecc_keys.py prime256v1 jrcpv2 127.0.0.1:8050')
    print('Example invocation - create_and_provision_ecc_keys.py prime256v1 vcom COM10 se05x None')
    print('Example invocation - create_and_provision_ecc_keys.py prime256v1 vcom COM10 se05x PlatformSCP "<path_to_scp_keys>"')
    print('Example invocation - create_and_provision_ecc_keys.py prime256v1 t1oi2c none se05x PlatformSCP "<path_to_scp_keys>"')
    print('Example invocation - create_and_provision_ecc_keys.py prime256v1 t1oi2c none se05x AESKey')
    sys.exit()


print (len(sys.argv))
if len(sys.argv) < 4:
    printUsage()

cur_dir = os.path.abspath(os.path.dirname(__file__))

keytype = sys.argv[1]
if isValidECKeyType(keytype) != True:
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

ROOT_CA_CER = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca.cer')
ROOT_CA_SRL = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca.srl')
ROOT_CA_KEY_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca_key.pem')
ROOT_CA_KEY_PUBLIC_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca_pub_key.pem')
ROOT_CA_KEY_DER = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca_key.der')

CLIENT_KEY_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client_key.pem')
CLIENT_KEY_REF_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client_key_ref.pem')
CLIENT_KEY_PUBLIC_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client_key_pub.pem')
CLIENT_CER = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client.cer')

SERVER_KEY_PEM = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_server_key.pem')
SERVER_CSR = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_server.csr')
SERVER_CERTIFICATE = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_server.cer')

openssl_config_file = os.path.join(cur_dir, '..', '..', '..', '..', 'ext', 'openssl', 'ssl', 'openssl.cnf')
if sys.platform.startswith("win"):
    openssl = os.path.join(cur_dir, '..', '..', '..', '..', 'ext', 'openssl', 'bin', 'openssl.exe')
    os.environ['OPENSSL_CONF'] = openssl_config_file
else:
    openssl = 'openssl'

SUBJECT = "/C=AB/ST=XY/L=LH/O=NXP-Demo-CA/OU=Demo-Unit/CN=localhost"


cmd_str = "\"%s\" ecparam -name \"%s\" -out \"%s\"" % (openssl, keytype, KEY_TYPE_FILE)
run(cmd_str)

cmd_str = "\"%s\" ecparam -in \"%s\" -genkey -noout -out \"%s\"" % (openssl, KEY_TYPE_FILE, ROOT_CA_KEY_PEM)
run(cmd_str)

cmd_str = "\"%s\" ec -in \"%s\" -text -noout" % (openssl, ROOT_CA_KEY_PEM)
run(cmd_str)

cmd_str = "\"%s\" ec -in \"%s\" -outform DER -out \"%s\"" % (openssl, ROOT_CA_KEY_PEM, ROOT_CA_KEY_DER)
run(cmd_str)

cmd_str = "\"%s\" ec -in \"%s\" -pubout -out \"%s\"" % (openssl, ROOT_CA_KEY_PEM, ROOT_CA_KEY_PUBLIC_PEM)
run(cmd_str)

#create CA certificates
cmd_str = "\"%s\" req -x509 -new -nodes -key \"%s\" -subj \"%s\" -days 2800 -out \"%s\" -config \"%s\"" % (openssl, ROOT_CA_KEY_PEM, SUBJECT, ROOT_CA_CER, openssl_config_file)
run(cmd_str)

cmd_str = "\"%s\" x509 -in \"%s\" -text -noout" % (openssl, ROOT_CA_CER)
run(cmd_str)


#Create client key and extract public part
cmd_str = "\"%s\" ecparam -in \"%s\" -genkey -out \"%s\"" % (openssl, KEY_TYPE_FILE, CLIENT_KEY_PEM)
run(cmd_str)

cmd_str = "\"%s\" ec -in \"%s\" -text -noout" % (openssl, CLIENT_KEY_PEM)
run(cmd_str)

cmd_str = "\"%s\" ec -in \"%s\" -pubout -out \"%s\"" % (openssl, CLIENT_KEY_PEM, CLIENT_KEY_PUBLIC_PEM)
run(cmd_str)

#Now create CSR
cmd_str = "\"%s\" req -new -key \"%s\" -subj \"%s\" -out \"%s\" -config \"%s\"" % (openssl, CLIENT_KEY_PEM, SUBJECT, CLIENT_CER, openssl_config_file)
run(cmd_str)

cmd_str = "\"%s\" req -in \"%s\" -text -config \"%s\"" % (openssl, CLIENT_CER, openssl_config_file)
run(cmd_str)


#Create CA signed client certificate
if os.path.isfile(ROOT_CA_SRL) == True:
    cmd_str = "\"%s\" x509 -req -sha256 -days 2800 -in \"%s\" -CAserial \"%s\" -CA \"%s\" -CAkey \"%s\" -out \"%s\" " % (openssl, CLIENT_CER, ROOT_CA_SRL, ROOT_CA_CER, ROOT_CA_KEY_PEM, CLIENT_CER)
else:
    cmd_str = "\"%s\" x509 -req -sha256 -days 2800 -in \"%s\" -CAserial \"%s\" -CAcreateserial -CA \"%s\" -CAkey \"%s\" -out \"%s\" " % (openssl, CLIENT_CER, ROOT_CA_SRL, ROOT_CA_CER, ROOT_CA_KEY_PEM, CLIENT_CER)
run(cmd_str)

cmd_str = "\"%s\" x509 -in \"%s\" -text -noout" % (openssl, CLIENT_CER)
run(cmd_str)

#Create server key
cmd_str = "\"%s\" ecparam -in \"%s\" -genkey -out \"%s\"" % (openssl, KEY_TYPE_FILE, SERVER_KEY_PEM)
run(cmd_str)

cmd_str = "\"%s\" ec -in \"%s\" -text -noout" % (openssl, SERVER_KEY_PEM)
run(cmd_str)

#Create CSR a new
cmd_str = "\"%s\" req -new -key \"%s\" -subj \"%s\" -out \"%s\" -config \"%s\"" % (openssl, SERVER_KEY_PEM, SUBJECT, SERVER_CSR, openssl_config_file)
run(cmd_str)

cmd_str = "\"%s\" req -in \"%s\" -text -noout -config \"%s\"" % (openssl, SERVER_CSR, openssl_config_file)
run(cmd_str)

#Create a CA signed server certificate
if os.path.isfile(ROOT_CA_SRL) == True:
    cmd_str = "\"%s\" x509 -req -sha256 -days 2800 -in \"%s\" -CAserial \"%s\" -CA \"%s\" -CAkey \"%s\" -out \"%s\" " % (openssl, SERVER_CSR, ROOT_CA_SRL, ROOT_CA_CER, ROOT_CA_KEY_PEM, SERVER_CERTIFICATE)
else:
    cmd_str = "\"%s\" x509 -req -sha256 -days 2800 -in \"%s\" -CAserial \"%s\" -CAcreateserial -CA \"%s\" -CAkey \"%s\" -out \"%s\" " % (openssl, SERVER_CSR, ROOT_CA_SRL, ROOT_CA_CER, ROOT_CA_KEY_PEM, SERVER_CERTIFICATE)
run(cmd_str)

cmd_str = "\"%s\" x509 -in \"%s\" -text -noout" % (openssl, SERVER_CERTIFICATE)
run(cmd_str)


#Provision the keys

session_close(None)
session = session_open(iot_se, connection_string, connection_type, auth_type, auth_key)
if session is None:
    print("Error in session_open")
    sys.exit()

reset(session)

# Inject client certificate to the Secure Element
status = set_cert(session, CLIENT_CERT_KEY_ID, CLIENT_CER)
if status != apis.kStatus_SSS_Success:
    print("Error in set_cert")

# Inject root ca public key to the Secure Element
status = set_ecc_pub(session, ROOT_CA_PUB_KEY_ID, ROOT_CA_KEY_PUBLIC_PEM)
if status != apis.kStatus_SSS_Success:
    print("Error in set_ecc_pub")

# Inject client ecc pair key to the Secure Element
status = set_ecc_pair(session, CLIENT_KEY_PAIR_ID, CLIENT_KEY_PEM)
if status != apis.kStatus_SSS_Success:
    print("Error in set_ecc_pair")

# Create ecc ref key
status = refpem_ecc_pair(session, CLIENT_KEY_PAIR_ID, CLIENT_KEY_REF_PEM)
if status != apis.kStatus_SSS_Success:
    print("Error in refpem_ecc_pair")

session_close(None)