#
# Copyright 2023-2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
"""

Generates keys of type ECC and performs sign and verify operations

"""

import binascii
import sys

from pkcs11_utils import *

OPENSC_UNSUPPORTED_P192 = "0.23.0"

UNSUPPORTED_EC_KEY_TYPES = [
    "EC:prime192v1",
    "EC:secp192k1",
    "EC:brainpoolP192r1",
]

def main():
    args = parse_in_ec_args()
    if args is None:
        return
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    opensc_version = get_opensc_version().strip()
    if OPENSC_UNSUPPORTED_P192 in opensc_version:
        if args.key_type in UNSUPPORTED_EC_KEY_TYPES:
            log.info("%s is not supported for opensc version %s "% (args.key_type, OPENSC_UNSUPPORTED_P192))
            return

    if "prime256v1" in args.key_type:
        ossl_key_type = "prime256v1"
    elif "prime192v1" in args.key_type:
        ossl_key_type = "prime192v1"
    elif "secp224r1" in args.key_type:
        ossl_key_type = "secp224r1"
    elif "secp384r1" in args.key_type:
        ossl_key_type = "secp384r1"
    elif "secp521r1" in args.key_type:
        ossl_key_type = "secp521r1"
    elif "secp192k1" in args.key_type:
        ossl_key_type = "secp192k1"
    elif "secp256k1" in args.key_type:
        ossl_key_type = "secp256k1"
    elif "brainpoolP192r1" in args.key_type:
        ossl_key_type = "brainpoolP192r1"
    elif "brainpoolP224r1" in args.key_type:
        ossl_key_type = "brainpoolP224r1"
    elif "brainpoolP256r1" in args.key_type:
        ossl_key_type = "brainpoolP256r1"
    elif "brainpoolP320r1" in args.key_type:
        ossl_key_type = "brainpoolP320r1"
    elif "brainpoolP384r1" in args.key_type:
        ossl_key_type = "brainpoolP384r1"
    elif "brainpoolP512r1" in args.key_type:
        ossl_key_type = "brainpoolP512r1"

    log.info("Generating keypair: %s" % (args.key_type))
    run("%s --module %s --keypairgen --key-type  %s --label sss:0xEF000001" % (pkcs11_tool, module_path, args.key_type))
    log.info("###################################################")

    log.info("Retrieving Public Key")
    run("%s --module %s --read-object --type pubkey --label sss:0xEF000001 -o %s%s_0xEF000001_public.key" % (pkcs11_tool, module_path, output_dir, args.key_type.split(":")[1]))
    log.info("###################################################")

# provision public key at different keyid
    log.info("Provisioning Public Key")
    run("%s --module %s --write-object %s%s_0xEF000001_public.key --type pubkey --label sss:0xEF000003 " % (pkcs11_tool, module_path, output_dir, args.key_type.split(":")[1]))
    log.info("###################################################") 

    data_len = ["10","20","28","32","48","64"]
    for len in data_len:
        log.info("Signing data with length %s and with key: %s and algo: ECDSA" % (len, args.key_type))
        run("%s --module %s --sign --mechanism ECDSA --id EF000001 --input-file %sdata%s.txt -o %sout_ECDSA_input_%s_%s.sign" % (pkcs11_tool, module_path, input_dir, len, output_dir, len, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length %s and with key: %s and algo: ECDSA" % (len, args.key_type))
        run("%s --module %s --verify --mechanism ECDSA --id EF000001 --input-file %sdata%s.txt --signature-file %sout_ECDSA_input_%s_%s.sign" % (pkcs11_tool, module_path, input_dir, len, output_dir, len, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length %s and with public key: %s id EF000003 and algo: ECDSA" % (len, args.key_type))
        run("%s --module %s --verify --mechanism ECDSA --id EF000003 --input-file %sdata%s.txt --signature-file %sout_ECDSA_input_%s_%s.sign" % (pkcs11_tool, module_path, input_dir, len, output_dir, len, args.key_type.split(":")[1]))
        log.info("###################################################")

    sha_types = ["ECDSA-SHA1", "ECDSA-SHA224", "ECDSA-SHA256","ECDSA-SHA384","ECDSA-SHA512"]
    for sha_type in sha_types:
        log.info("Signing data with length = 600 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --sign --mechanism %s --id EF000001 --input-file %sdata600.txt -o %sout_%s_input_600_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length = 600 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --verify --mechanism %s --id EF000001 --input-file %sdata600.txt --signature-file %sout_%s_input_600_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length = 600 and with key: %s id EF000003 and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --verify --mechanism %s --id EF000003 --input-file %sdata600.txt --signature-file %sout_%s_input_600_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Signing data with length = 1024 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --sign --mechanism %s --id EF000001 --input-file %sdata1024.txt -o %sout_%s_input_1024_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length = 1024 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --verify --mechanism %s --id EF000001 --input-file %sdata1024.txt --signature-file %sout_%s_input_1024_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length = 1024 and with key: %s id EF000003 and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --verify --mechanism %s --id EF000003 --input-file %sdata1024.txt --signature-file %sout_%s_input_1024_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Signing data with length = 2048 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --sign --mechanism %s --id EF000001 --input-file %sdata2048.txt -o %sout_%s_input_2048_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length = 2048 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --verify --mechanism %s --id EF000001 --input-file %sdata2048.txt --signature-file %sout_%s_input_2048_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length = 2048 and with key: %s id EF000003 and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --verify --mechanism %s --id EF000003 --input-file %sdata2048.txt --signature-file %sout_%s_input_2048_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

    log.info("Deleting generated keypair")
    run("%s --module %s --delete-object --type privkey --label sss:0xEF000001" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("Deleting provisioned public key")
    run("%s --module %s --delete-object --type privkey --label sss:0xEF000003" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("Counterpart SIGN with OPENSSL")
    log.info("Generate EC keypair")
    run("openssl ecparam -name %s -genkey -noout -out %sec_%s.key"%(ossl_key_type, output_dir, ossl_key_type))

    log.info("Retrieve EC public key")
    run("openssl ec -in %sec_%s.key -pubout -out %sec_pub_%s.pubkey.pem"%(output_dir, ossl_key_type, output_dir, ossl_key_type))
    log.info("###################################################")

    log.info("Doing Sha256")
    run("openssl sha256 -out %sout_sh256 -binary %sdata10.txt"%(output_dir, input_dir))
    log.info("###################################################")

    log.info("Doing Sign with openssl")
    run("openssl pkeyutl -sign -inkey %sec_%s.key -in %sout_sh256  > %sec%s.sign"%(output_dir, ossl_key_type, output_dir, output_dir, ossl_key_type))
    log.info("###################################################")

    log.info("Provision Public key to SE05x ")
    run("%s --module %s --write-object %sec_pub_%s.pubkey.pem --type pubkey --label sss:0xEF000004" % (pkcs11_tool, module_path, output_dir, ossl_key_type))
    log.info("###################################################")

    log.info("Verifying data with SE05x")
    run("%s --module %s --verify --mechanism ECDSA --id EF000004 --input-file %sout_sh256 --signature-file %sec%s.sign" % (pkcs11_tool, module_path, output_dir, output_dir, ossl_key_type))
    log.info("###################################################")

    log.info("Deleting provisioned public key")
    run("%s --module %s --delete-object --type pubkey --label sss:0xEF000004" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("Counterpart VERIFY with OPENSSL")
    log.info("Generating keypair: %s" % (args.key_type))
    run("%s --module %s --keypairgen --key-type  %s --label sss:0xEF00000A" % (pkcs11_tool, module_path, args.key_type))
    log.info("###################################################")

    log.info("Retrieving Public Key")
    run("%s --module %s --read-object --type pubkey --label sss:0xEF00000A -o %s%s_0xEF00000A_public_ossl.key" % (pkcs11_tool, module_path, output_dir, args.key_type.split(":")[1]))
    log.info("###################################################")

    log.info("Doing Sha256")
    run("openssl sha256 -out %sout_sh256 -binary %sdata10.txt"%(output_dir, input_dir))
    log.info("###################################################")

    log.info("Signing data with length = 2048 and with key: %s and algo: ECDSA" % (args.key_type))
    run("%s --module %s --sign --mechanism ECDSA --id EF00000A --input-file %sout_sh256 -o %sout_sh256.sign" % (pkcs11_tool, module_path, output_dir, output_dir))
    log.info("###################################################")

    raw_sign_file = ("%sout_sh256.sign") %(output_dir)
    encoded_sign = ("%sout_sign.txt") %(output_dir)

    convert_raw_to_asn1(raw_sign_file, encoded_sign)

    log.info("Convert key DER to PEM")
    run("openssl pkey -pubin -in %s%s_0xEF00000A_public_ossl.key -inform DER -outform PEM -out %s%sopenssl_key.pem"%(output_dir, args.key_type.split(":")[1], output_dir,args.key_type.split(":")[1]))
    log.info("###################################################")

    log.info("Doing verify with openssl")
    run("openssl pkeyutl -verify -pubin -inkey %s%sopenssl_key.pem -in %sout_sh256  -sigfile %sout_sign.txt > %sverify_logs"%(output_dir, args.key_type.split(":")[1], output_dir, output_dir, output_dir))
    log.info("###################################################")

    log.info("Parsing the ossl result")
    out_log_file = ("%sverify_logs" %(output_dir))
    parse_log_file(out_log_file)

    log.info("Deleting provisioned public key")
    run("%s --module %s --delete-object --type pubkey --label sss:0xEF00000A" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()