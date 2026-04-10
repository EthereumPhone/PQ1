#
# Copyright 2023-2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
"""

Generates keys of type RSA

"""

from pkcs11_utils import *

def main():
    args = parse_in_rsa_args()
    if args is None:
        return

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    if "1024" in args.key_type:
        ossl_key_type = "1024"
    elif "2048" in args.key_type:
        ossl_key_type = "2048"
    elif "3072" in args.key_type:
        ossl_key_type = "3072"
    elif "4096" in args.key_type:
        ossl_key_type = "4096"

    algorithms_RSA_PKCS = ["SHA1-RSA-PKCS","SHA224-RSA-PKCS","SHA256-RSA-PKCS","SHA384-RSA-PKCS","SHA512-RSA-PKCS"]
    algorithms_RSA_PKCS_PSS = ["SHA1-RSA-PKCS-PSS","SHA224-RSA-PKCS-PSS","SHA256-RSA-PKCS-PSS","SHA384-RSA-PKCS-PSS","SHA512-RSA-PKCS-PSS"]

    log.info("Generating RSA keypair: %s" % (args.key_type))
    run("%s --module %s --keypairgen --key-type  %s --label sss:0xEF00000A" % (pkcs11_tool, module_path, args.key_type))
    log.info("###################################################")

    log.info("Retrieving Public Key")
    run("%s --module %s --read-object --type pubkey --label sss:0xEF00000A -o %srsa_%s_0xEF00000A_public.key" % (pkcs11_tool, module_path, output_dir, args.key_type.split(":")[1]))
    log.info("###################################################")

# provision public key at different keyid
    log.info("Provisioning Public Key")
    run("%s --module %s --write-object %srsa_%s_0xEF00000A_public.key --type pubkey --label sss:0xEF00000B " % (pkcs11_tool, module_path, output_dir, args.key_type.split(":")[1]))
    log.info("###################################################")

    log.info("Signing data with length 10 bytes with key: %s algo: RSA-PKCS" % (args.key_type))
    run("%s --module %s --sign --mechanism RSA-PKCS --id EF00000A --input-file %sdata10.txt --output-file %sout_RSA_%s_input_10.sign" % (pkcs11_tool, module_path, input_dir, output_dir, args.key_type.split(":")[1]) )
    log.info("###################################################")

    log.info("Verifying data with length 10 bytes with key: %s algo: RSA-PKCS" % (args.key_type))
    run("%s --module %s --verify --mechanism RSA-PKCS --id EF00000A --input-file %sdata10.txt --signature-file %sout_RSA_%s_input_10.sign" % (pkcs11_tool, module_path, input_dir, output_dir, args.key_type.split(":")[1]) )
    log.info("###################################################")

    log.info("Verifying data with length 10 bytes with key: %s algo: RSA-PKCS and id EF00000B" % (args.key_type))
    run("%s --module %s --verify --mechanism RSA-PKCS --id EF00000B --input-file %sdata10.txt --signature-file %sout_RSA_%s_input_10.sign" % (pkcs11_tool, module_path, input_dir, output_dir, args.key_type.split(":")[1]) )
    log.info("###################################################")

    log.info("Signing data with length 10 bytes with key: %s algo: RSA-PKCS-PSS" % (args.key_type)) # Only SHA1 data
    run("%s --module %s --sign --mechanism RSA-PKCS-PSS --id EF00000A --input-file %sdata20.txt --output-file %sout_RSA_%s_input_10.sign" % (pkcs11_tool, module_path, input_dir, output_dir, args.key_type.split(":")[1]) )
    log.info("###################################################")

    log.info("Verifying data with length 10 bytes with key: %s algo: RSA-PKCS-PSS" % (args.key_type))
    run("%s --module %s --verify --mechanism RSA-PKCS-PSS --id EF00000A --input-file %sdata20.txt --signature-file %sout_RSA_%s_input_10.sign" % (pkcs11_tool, module_path, input_dir, output_dir, args.key_type.split(":")[1]) )
    log.info("###################################################")


    for algo in algorithms_RSA_PKCS:

        log.info("Signing data with length 10 bytes with key: %s algo: %s" % (args.key_type, algo)) # Only SHA1 data
        run("%s --module %s --sign --mechanism %s --id EF00000A --input-file %sdata1024.txt --output-file %sout_RSA_%s_input_1024.sign" % (pkcs11_tool, module_path, algo, input_dir, output_dir, args.key_type.split(":")[1]) )
        log.info("###################################################")

        log.info("Verifying data with length 10 bytes with key: %s algo: %s" % (args.key_type, algo))
        run("%s --module %s --verify --mechanism %s --id EF00000A --input-file %sdata1024.txt --signature-file %sout_RSA_%s_input_1024.sign" % (pkcs11_tool, module_path, algo, input_dir, output_dir, args.key_type.split(":")[1]) )
        log.info("###################################################")

        log.info("Verifying data with length 10 bytes with key: %s algo: %s and id EF00000B" % (args.key_type, algo))
        run("%s --module %s --verify --mechanism %s --id EF00000B --input-file %sdata1024.txt --signature-file %sout_RSA_%s_input_1024.sign" % (pkcs11_tool, module_path, algo, input_dir, output_dir, args.key_type.split(":")[1]) )
        log.info("###################################################")

    for algo in algorithms_RSA_PKCS_PSS:

        if (args.key_type.lower() == "rsa:1024") and (algo == "SHA512-RSA-PKCS-PSS"):
            continue

        log.info("Signing data with length 10 bytes with key: %s algo: %s" % (args.key_type, algo)) # Only SHA1 data
        run("%s --module %s --sign --mechanism %s --id EF00000A --input-file %sdata1024.txt --output-file %sout_RSA_%s_input_1024.sign" % (pkcs11_tool, module_path, algo, input_dir, output_dir, args.key_type.split(":")[1]) )
        log.info("###################################################")

        log.info("Verifying data with length 10 bytes with key: %s algo: %s" % (args.key_type, algo))
        run("%s --module %s --verify --mechanism %s --id EF00000A --input-file %sdata1024.txt --signature-file %sout_RSA_%s_input_1024.sign" % (pkcs11_tool, module_path, algo, input_dir, output_dir, args.key_type.split(":")[1]) )
        log.info("###################################################")

        log.info("Verifying data with length 10 bytes with key: %s algo: %s id EF00000B" % (args.key_type, algo))
        run("%s --module %s --verify --mechanism %s --id EF00000B --input-file %sdata1024.txt --signature-file %sout_RSA_%s_input_1024.sign" % (pkcs11_tool, module_path, algo, input_dir, output_dir, args.key_type.split(":")[1]) )
        log.info("###################################################")

    log.info("Deleting generated keypair")
    run("%s --module %s --delete-object --type privkey --label sss:0xEF00000A" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("Deleting provisioned public key")
    run("%s --module %s --delete-object --type privkey --label sss:0xEF00000B" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("Counterpart SIGN with OPENSSL")
    log.info("Generate RSA keypair")
    run("openssl genrsa -out %srsa_%s_private.pem %s"%(output_dir, ossl_key_type, ossl_key_type))

    log.info("Retrieve RSA public key")
    run("openssl rsa -in %srsa_%s_private.pem -pubout -out %srsa_pub_%s.pubkey.pem"%(output_dir, ossl_key_type, output_dir, ossl_key_type))
    log.info("###################################################")

    log.info("Doing Sha256")
    run("openssl sha256 -out %sout_sh256 -binary %sdata10.txt"%(output_dir, input_dir))
    log.info("###################################################")

    log.info("Doing Sign with openssl")
    run("openssl pkeyutl -sign -inkey %srsa_%s_private.pem -in %sout_sh256  > %srsa%s.sign"%(output_dir, ossl_key_type, output_dir, output_dir, ossl_key_type))
    log.info("###################################################")

    log.info("Provision Public key to SE05x ")
    run("%s --module %s --write-object %srsa_pub_%s.pubkey.pem --type pubkey --label sss:0xEF000012" % (pkcs11_tool, module_path, output_dir, ossl_key_type))
    log.info("###################################################")

    log.info("Verifying data with SE05x")
    run("%s --module %s --verify --mechanism RSA-PKCS --id EF000012 --input-file %sout_sh256 --signature-file %srsa%s.sign" % (pkcs11_tool, module_path, output_dir, output_dir, ossl_key_type))
    log.info("###################################################")

    log.info("Deleting provisioned public key")
    run("%s --module %s --delete-object --type pubkey --label sss:0xEF000012" % (pkcs11_tool, module_path))
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
    run("%s --module %s --sign --mechanism RSA-PKCS --id EF00000A --input-file %sout_sh256 -o %sout_sh256.sign" % (pkcs11_tool, module_path, output_dir, output_dir))
    log.info("###################################################")

    log.info("Convert key DER to PEM")
    run("openssl pkey -pubin -in %s%s_0xEF00000A_public_ossl.key -inform DER -outform PEM -out %s%sopenssl_key.pem"%(output_dir, args.key_type.split(":")[1], output_dir,args.key_type.split(":")[1]))
    log.info("###################################################")

    log.info("Doing verify with openssl")
    run("openssl pkeyutl -verify -pubin -inkey %s%sopenssl_key.pem -in %sout_sh256  -sigfile %sout_sh256.sign > %sverify_logs"%(output_dir, args.key_type.split(":")[1], output_dir, output_dir, output_dir))
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