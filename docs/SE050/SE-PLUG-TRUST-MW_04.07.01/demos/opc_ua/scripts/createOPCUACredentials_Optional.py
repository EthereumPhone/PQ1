#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

# Create Keys for OPC UA demo
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


def run(cmd_str, ignore_result=0, exp_retcode=0):
    print("Running command: %s" %cmd_str)
    if 'nt' in os.name:
        cmd=cmd_str
    else:
        cmd=shlex.split(cmd_str)

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


cur_dir = os.path.abspath(os.path.dirname(__file__))

if len(sys.argv) == 2:
    hostname = sys.argv[1]
    EXT_CNF = os.path.join(cur_dir, '..', 'credentials', 'extensions_new.cnf')
    f= open('%s' %EXT_CNF,"w+")
    f.write("basicConstraints=CA:TRUE \n")
    ip_address_match = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", hostname)
    if ip_address_match:
        f.write("subjectAltName=URI:\"urn:open62541:%s\",IP:\"%s\"" % (hostname, hostname))
    else:
        f.write("subjectAltName=URI:\"urn:open62541:%s\",DNS:\"%s\"" % (hostname, hostname))
    f.close()
else:
    EXT_CNF = os.path.join(cur_dir, '..', 'credentials', 'extensions.cnf')


CA_KEY_LEN = 2048
RSA_KEY_LEN = 2048
ROOTCA_CERT_SUB = "/OU=NXP Plug Trust CA/CN=NXP RootCAvRxxx"
CERT_VALIDITY = 4380  # 12 years

ROOT_CA_KEY = os.path.join(cur_dir, '..', 'credentials', 'open62541_rootCA_key_pair.pem')
ROOT_CA_CERT_CER = os.path.join(cur_dir, '..', 'credentials', 'open62541_rootCA_cert.cer')
ROOT_CA_CERT_DER = os.path.join(cur_dir, '..', 'credentials', 'open62541_rootCA_cert.der')
ROOT_CA_CERT_SRL = os.path.join(cur_dir, '..', 'credentials', 'open62541_rootCA_cert.srl')

SERVER_KEY = os.path.join(cur_dir, '..', 'credentials', 'open62541_server_key_pair.pem')
SERVER_CERT_CER = os.path.join(cur_dir, '..', 'credentials', 'open62541_server_cert.cer')
SERVER_CERT_DER = os.path.join(cur_dir, '..', 'credentials', 'open62541_server_cert.der')
SERVER_CERT_CSR = os.path.join(cur_dir, '..', 'credentials', 'open62541_server.csr')
SERVER_CERT_SUB = "/CN=NXP_SE050_OPEN62541_SERVER"

CLIENT_KEY = os.path.join(cur_dir, '..', 'credentials', 'open62541_client_key_pair.pem')
CLIENT_CERT_CER = os.path.join(cur_dir, '..', 'credentials', 'open62541_client_cert.cer')
CLIENT_CERT_DER = os.path.join(cur_dir, '..', 'credentials', 'open62541_client_cert.der')
CLIENT_CERT_CSR = os.path.join(cur_dir, '..', 'credentials', 'open62541_client.csr')
CLIENT_CERT_SUB = "/CN=NXP_SE050_OPEN62541_CLIENT"

CLIENT_CONF = os.path.join(cur_dir, '..', 'credentials', 'client.conf')


if sys.platform.startswith("win"):
    openssl = os.path.join(cur_dir, '..', '..', '..', 'ext', 'openssl', 'bin', 'openssl.exe')
    openssl_config_file = os.path.join(cur_dir, '..', '..', '..', 'ext', 'openssl', 'ssl', 'openssl.cnf')
    os.environ['OPENSSL_CONF'] = openssl_config_file
else:
    openssl = 'openssl'

# Create root CA key pair
cmd_str = "\"%s\" genrsa -out \"%s\" \"%s\"" % (openssl, ROOT_CA_KEY, CA_KEY_LEN)
run(cmd_str)

#Create rootCA certificate
cmd_str = "\"%s\" req -x509 -new -nodes -key \"%s\" -subj \"%s\" -days \"%s\" -out \"%s\"" % (openssl, ROOT_CA_KEY, ROOTCA_CERT_SUB, CERT_VALIDITY, ROOT_CA_CERT_CER)
run(cmd_str)

# Create server key pair
cmd_str = "\"%s\" genrsa -out \"%s\" \"%s\"" % (openssl, SERVER_KEY, RSA_KEY_LEN)
run(cmd_str)

# Create certificate signing request for server
cmd_str = "\"%s\" req -new -key \"%s\" -subj \"%s\" -out \"%s\" " % (openssl, SERVER_KEY, SERVER_CERT_SUB, SERVER_CERT_CSR)
run(cmd_str)

# Sign and create server certificate
cmd_str = "\"%s\" x509 -req -extfile \"%s\" -sha256 -days \"%s\" -in \"%s\" -CAcreateserial -CA \"%s\" -CAkey \"%s\" -out \"%s\" " % (openssl, EXT_CNF, CERT_VALIDITY, SERVER_CERT_CSR, ROOT_CA_CERT_CER, ROOT_CA_KEY, SERVER_CERT_CER)
run(cmd_str)

# Convert root ca certificate to DER format
cmd_str = "\"%s\" x509 -in \"%s\" -outform DER -out \"%s\" " % (openssl, ROOT_CA_CERT_CER, ROOT_CA_CERT_DER)
run(cmd_str)

# Convert server certificate to DER format
cmd_str = "\"%s\" x509 -in \"%s\" -outform DER -out \"%s\" " % (openssl, SERVER_CERT_CER, SERVER_CERT_DER)
run(cmd_str)


# create client certificate (CA signed)

# Create client key pair
#cmd_str = "\"%s\" genrsa -out \"%s\" \"%s\"" % (openssl, CLIENT_KEY, RSA_KEY_LEN)
#run(cmd_str)

# Create certificate signing request for client
#cmd_str = "\"%s\" req -new -key \"%s\" -subj \"%s\" -out \"%s\" " % (openssl, CLIENT_KEY, CLIENT_CERT_SUB, CLIENT_CERT_CSR)
#run(cmd_str)

# Sign and create client certificate
#cmd_str = "\"%s\" x509 -req -extfile \"%s\" -sha256 -days \"%s\" -in \"%s\" -CAcreateserial -CA \"%s\" -CAkey \"%s\" -out \"%s\" " % (openssl, CLIENT_EXT_CNF, CERT_VALIDITY, CLIENT_CERT_CSR, ROOT_CA_CERT_CER, ROOT_CA_KEY, CLIENT_CERT_CER)
#run(cmd_str)

# Convert client certificate to DER format
#cmd_str = "\"%s\" x509 -in \"%s\" -outform DER -out \"%s\" " % (openssl, CLIENT_CERT_CER, CLIENT_CERT_DER)
#run(cmd_str)


# create client certificate (self signed)
cmd_str = "\"%s\" genrsa -out \"%s\" \"%s\"" % (openssl, CLIENT_KEY, RSA_KEY_LEN)
run(cmd_str)

#Create rootCA certificate
cmd_str = "\"%s\" req -x509 -new -nodes -key \"%s\" -subj \"%s\" -days \"%s\" -out \"%s\" -config \"%s\" " % (openssl, CLIENT_KEY, CLIENT_CERT_SUB, CERT_VALIDITY, CLIENT_CERT_CER, CLIENT_CONF)
run(cmd_str)

# Convert client certificate to DER format
cmd_str = "\"%s\" x509 -in \"%s\" -outform DER -out \"%s\" " % (openssl, CLIENT_CERT_CER, CLIENT_CERT_DER)
run(cmd_str)


#os.remove('.rnd')
os.remove(SERVER_CERT_CSR)
os.remove(SERVER_CERT_CER)
#os.remove(CLIENT_CERT_CSR)
os.remove(CLIENT_CERT_CER)
os.remove(ROOT_CA_CERT_CER)
#os.remove(ROOT_CA_CERT_SRL)
if len(sys.argv) == 2:
    os.remove(EXT_CNF)

print("##############################################################")
print("#                                                            #")
print("#     Program Completed Successfully                         #")
print("#                                                            #")
print("##############################################################")
