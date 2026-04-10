#
# Copyright 2024-2025 NXP
# SPDX-License-Identifier: Apache-2.0
#

"""
Performs Encryption/Decryption
"""
import binascii
import sys

from pkcs11_utils import *

OPENSC_UNSUPPORTED_VERSION = "0.23.0"
OPENSC_ENCRYPT_UNSUPPORTED = "0.20.0"

def read_from_file(filename, binary=False):

    if binary is True:
        with open(filename, 'rb') as f:
            data = f.read()
    else:
        with open(filename, 'rb') as f:
            data = bytes_to_hexstr(f.read())

    logging.info(f"Data read from [{filename}]")
    return data

def bytes_to_hexstr(bt):
    return binascii.hexlify(bt).decode('ascii')

def compare_data(filename, input_file):

    data = read_from_file(filename, binary=True)
    print("se05x decrypted:",data)

    data2 = read_from_file(input_file, binary=True)
    print("input data:",data2)
    log.info("Comparing data")
    if(data == data2):
        log.info("Data is same !!")
    else:
        log.error("comparison failed !!")
        sys.exit()

    log.info("###################################################")

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    opensc_version = get_opensc_version().strip()

    if OPENSC_ENCRYPT_UNSUPPORTED in opensc_version:
            log.info("encryption is not supported for opensc version %s"%(OPENSC_ENCRYPT_UNSUPPORTED))
            return

    log.info("Generating symmetric key: aes:16.. (Generates random data and set key)")
    run("%s --module %s --keygen --key-type aes:16 --label sss:0xEF00000D" % (pkcs11_tool, module_path))
    log.info("###################################################")

    mechanisms = ["aes-ecb", "aes-cbc"]
    for mech in mechanisms:
        log.info("Performing encryption operation")
        run("%s --module %s --encrypt --id EF00000D --mechanism %s --input-file %sdata10.txt --output-file %sencrypted_%s.txt" % (pkcs11_tool, module_path, mech, input_dir, output_dir, mech))
        log.info("###################################################")

        log.info("Performing decryption operation")
        run("%s --module %s --decrypt --id EF00000D --mechanism %s --input-file %sencrypted_%s.txt" % (pkcs11_tool, module_path, mech, output_dir, mech))
        log.info("###################################################")

    log.info("Deleting Key")
    run("%s --module %s --delete-object --type secrkey --label sss:0xEF00000D" % (pkcs11_tool, module_path))
    log.info("###################################################")

    if OPENSC_UNSUPPORTED_VERSION not in opensc_version:
        log.info("Asymmetric rsa encryption/decryption")
        log.info("Generate rsa keypair")
        run("openssl genrsa -out %skeypairrsa.pem 1024"%(output_dir))

        log.info("Do encryption with openssl ")
        run("openssl pkeyutl -in input_data/data.txt -encrypt -inkey %skeypairrsa.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 -out %sencrypted_data.pem"%(output_dir,output_dir))
        log.info("###################################################")

        log.info("Write rsa private key to SE05x ")
        run("%s --module %s --write-object %skeypairrsa.pem --type privkey --label sss:0x10101010" % (pkcs11_tool, module_path, output_dir))
        log.info("###################################################")

        log.info("Decrypt with SE05x ")
        run("%s --module %s --decrypt --mechanism rsa-pkcs-oaep --id 10101010 --input-file %sencrypted_data.pem --hash-algorithm sha-1 -o %sdecrypted.txt" % (pkcs11_tool, module_path, output_dir, output_dir))
        log.info("###################################################")

        log.info("Comparing data")
        decrypted_file = ("%sdecrypted.txt"%(output_dir))
        input_file = "input_data/data.txt"
        compare_data(decrypted_file, input_file)

        log.info("Using RSA-PKCS")
        log.info("Retrieve rsa public key")
        run("openssl rsa -in %skeypairrsa.pem -pubout > %srsapubkey.pem"%(output_dir,output_dir))
        log.info("###################################################")

        log.info("Do encryption with openssl")
        run("openssl rsautl -encrypt -inkey %srsapubkey.pem -in input_data/data20.txt -pubin -out %sdata.crypt"%(output_dir,output_dir))
        log.info("###################################################")

        log.info("Decrypt with SE05x ")
        run("%s --module %s --decrypt  -m RSA-PKCS --id 10101010 --input-file %sdata.crypt -o %sdecrypted_rsa_pkcs.txt" % (pkcs11_tool, module_path, output_dir, output_dir))
        log.info("###################################################")

        log.info("Comparing data")
        decrypted_file = ("%sdecrypted_rsa_pkcs.txt"%(output_dir))
        input_file = "input_data/data20.txt"
        compare_data(decrypted_file, input_file)

        log.info("Deleting Key")
        run("%s --module %s --delete-object --type secrkey --label sss:0x10101010" % (pkcs11_tool, module_path))
        log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()