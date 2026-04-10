#
# Copyright 2023-2024 NXP
# SPDX-License-Identifier: Apache-2.0
#
"""

Generates digest of some data using different algorithms

"""
import binascii
import re
import sys

from pkcs11_utils import *

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

def compare_hash(filename, filename_openssl, ossl_mech, input_file):

    data = read_from_file(filename, binary=False)
    print("se05x digest:",data)

    log.info("Digest using Openssl")
    run("openssl %s -out %s -binary %s" % (ossl_mech, filename_openssl, input_file))
    log.info("###################################################")

    data2 = read_from_file(filename_openssl, binary=False)
    print("openssl digest:",data2)
    log.info("Comparing hashes")
    if(data == data2):
        log.info("Hashes are equal !!")
    else:
        log.error("Hash comparison failed !!")
        sys.exit()

    log.info("###################################################")

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    log.info("Digest with SHA-1")
    run("%s --module %s --hash --mechanism SHA-1 --input-file %sdata.txt --output-file %sout_hash_sha1.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    filename = "%sout_hash_sha1.txt"%(output_dir)
    filename_openssl = "%sout_sha1_openssl"%(output_dir)
    ossl_mech = "sha1"
    input_file = "%sdata.txt"%(input_dir)
    compare_hash(filename, filename_openssl, ossl_mech, input_file)

    log.info("Digest with SHA224")
    run("%s --module %s --hash --mechanism SHA224 --input-file %sdata32.txt --output-file %sout_hash_sha224.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    filename = "%sout_hash_sha224.txt"%(output_dir)
    filename_openssl = "%sout_sha224_openssl"%(output_dir)
    ossl_mech = "sha224"
    input_file = "%sdata32.txt"%(input_dir)
    compare_hash(filename, filename_openssl, ossl_mech, input_file)

    log.info("Digest with SHA256")
    run("%s --module %s --hash --mechanism SHA256 --input-file %sdata1024.txt --output-file %sout_hash_sha256.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    filename = "%sout_hash_sha256.txt"%(output_dir)
    filename_openssl = "%sout_sha256_openssl"%(output_dir)
    ossl_mech = "sha256"
    input_file = "%sdata1024.txt"%(input_dir)
    compare_hash(filename, filename_openssl, ossl_mech, input_file)

    log.info("Digest with SHA384")
    run("%s --module %s --hash --mechanism SHA384 --input-file %sdata600.txt --output-file %sout_hash_sha384.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    filename = "%sout_hash_sha384.txt"%(output_dir)
    filename_openssl = "%sout_sha384_openssl"%(output_dir)
    ossl_mech = "sha384"
    input_file = "%sdata600.txt"%(input_dir)
    compare_hash(filename, filename_openssl, ossl_mech, input_file)

    log.info("Digest with SHA512")
    run("%s --module %s --hash --mechanism SHA512 --input-file %sdata64.txt --output-file %sout_hash_SHA512.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    filename = "%sout_hash_SHA512.txt"%(output_dir)
    filename_openssl = "%sout_sha512_openssl"%(output_dir)
    ossl_mech = "sha512"
    input_file = "%sdata64.txt"%(input_dir)
    compare_hash(filename, filename_openssl, ossl_mech, input_file)

    log.info("Digest with SHA512")
    run("%s --module %s --hash --mechanism SHA512 --input-file %sdata2048.txt --output-file %sout_hash_SHA512.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    filename = "%sout_hash_SHA512.txt"%(output_dir)
    filename_openssl = "%sout_sha512_openssl"%(output_dir)
    ossl_mech = "sha512"
    input_file = "%sdata2048.txt"%(input_dir)
    compare_hash(filename, filename_openssl, ossl_mech, input_file)

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()
