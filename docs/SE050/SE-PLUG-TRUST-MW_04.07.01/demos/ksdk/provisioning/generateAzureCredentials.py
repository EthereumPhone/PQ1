#
# Copyright 2018 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate
import os
import sys

header_file = os.path.abspath(os.path.dirname(__file__))+os.sep+"azure_credentials.h"

c_header = "/* Copyright 2019, 2020 NXP \n\
 * SPDX-License-Identifier: Apache-2.0\n\
 */\n\n\
#ifndef __AZURE_CREDENTIALS__H__\n\
#define __AZURE_CREDENTIALS__H__\n\n\
"

def writeHFile(o, var_name, binary):
    count = 0
    var_name_string = "const uint8_t %s[] = {"%var_name
    o.write(var_name_string.encode())
    for i in binary:
        if count % 8 == 0:
            o.write(" \\\n".encode())
        elif count % 4 == 0:
            o.write("    ".encode())
        value_to_write = "0x%02X, "%(i,)
        o.write(value_to_write.encode())
        count = count + 1

    o.write("};\n\n".encode())


def main(keypair_file, certificate_file):
    with open(keypair_file, "rb") as infile:
        keypair = infile.read()

    with open(certificate_file, "rb") as infile:
        certificate = infile.read()

    priv_pem_obj = serialization.load_pem_private_key(keypair, None, default_backend())
    cert_pem_obj = load_pem_x509_certificate(certificate, default_backend())
    priv_der = priv_pem_obj.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    cert_der = cert_pem_obj.public_bytes(serialization.Encoding.DER)

    o = open(header_file, "wb")
    o.write(c_header.encode())
    o.write("/* Generated file. Do not modify */\n".encode())
    o.write("/* clang-format off */\n".encode())
    writeHFile(o, "client_key", priv_der)
    writeHFile(o, "client_cer", cert_der)
    o.write("/* clang-format on */\n".encode())
    o.write("#endif // __AZURE_CREDENTIALS__H__\n".encode())
    o.close()



def usage():
    print("Usage:\ngenerateAzureCredentials.py <keypair_file> <certificate_file>")
    sys.exit()

if __name__ == "__main__":
    argc = len(sys.argv)
    argv = sys.argv
    if(argc != 3):
        usage()
    main(argv[1], argv[2])
    print("Generated %s"%header_file)
