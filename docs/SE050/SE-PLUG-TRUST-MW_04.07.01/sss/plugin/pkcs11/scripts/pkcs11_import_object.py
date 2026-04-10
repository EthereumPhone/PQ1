#
# Copyright 2023-2024 NXP
# SPDX-License-Identifier: Apache-2.0
#
"""

Creates objects (Certificate, Public key and Private key)

"""

from pkcs11_utils import *

OPENSC_UNSUPPORTED_VERSION = "0.23.0"

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    opensc_version = get_opensc_version().strip()

    obj_type = "cert"
    file_name = "test_certificate.der"
    file_dir = key_dir + os.sep + file_name

    log.info("Importing certificate into SE: %s" % (file_name))
    run("%s --module %s --write-object %s --type  %s --label sss:0xEF000003" % (pkcs11_tool, module_path, file_dir, obj_type))
    log.info("###################################################")

    log.info("Reading certificate object: %s" % (file_name))
    run("%s --module %s --read-object --type %s --label sss:0xEF000003 -o %s%s" % (pkcs11_tool, module_path, obj_type, output_dir, file_name))
    log.info("###################################################")

    log.info("Deleting the certificate from SE")
    run("%s --module %s --delete-object --type %s --label sss:0xEF000003" % (pkcs11_tool, module_path, obj_type))
    log.info("###################################################")

    obj_type = "cert"
    file_name = "demo_cert.pem"
    file_dir = key_dir + os.sep + file_name

    log.info("Importing certificate into SE: %s" % (file_name))
    run("%s --module %s --write-object %s --type  %s --label sss:0xEF000003" % (pkcs11_tool, module_path, file_dir, obj_type))
    log.info("###################################################")

    log.info("Reading certificate object: %s" % (file_name))
    run("%s --module %s --read-object --type %s --label sss:0xEF000003 -o %s%s" % (pkcs11_tool, module_path, obj_type, output_dir, file_name))
    log.info("###################################################")

    log.info("Deleting the certificate from SE")
    run("%s --module %s --delete-object --type %s --label sss:0xEF000003" % (pkcs11_tool, module_path, obj_type))
    log.info("###################################################")

    if OPENSC_UNSUPPORTED_VERSION not in opensc_version:
        key_len = ["2048","3072"]
        for len in key_len:

            obj_type = "privkey"
            file_name = "rsa_priv_%s.pem" % (len)
            file_dir = key_dir + os.sep + file_name

            log.info("Importing RSA Private key object: %s" % (file_name))
            run("%s --module %s --write-object %s --type  %s --label sss:0xEF000001" % (pkcs11_tool, module_path, file_dir, obj_type))
            log.info("###################################################")

            log.info("Deleting the private key")
            run("%s --module %s --delete-object --type %s --label sss:0xEF000001" % (pkcs11_tool, module_path, obj_type))
            log.info("###################################################")

            obj_type = "pubkey"
            file_name = "rsa_pub_%s.pem" % (len)
            file_dir = key_dir + os.sep + file_name

            log.info("Importing RSA Public key object: %s" % (file_name))
            run("%s --module %s --write-object %s --type  %s --label sss:0xEF000001" % (pkcs11_tool, module_path, file_dir, obj_type))
            log.info("###################################################")

            log.info("Deleting the public key")
            run("%s --module %s --delete-object --type %s --label sss:0xEF000001" % (pkcs11_tool, module_path, obj_type))
            log.info("###################################################")

    prime_type = ["prime192","prime256"]
    for prime in prime_type:

        obj_type = "privkey"
        file_name = "ec_%s_priv.pem" % (prime)
        file_dir = key_dir + os.sep + file_name

        log.info("Importing ECC Private key object: %s" % (file_name))
        run("%s --module %s --write-object %s --type  %s --label sss:0xEF000001" % (pkcs11_tool, module_path, file_dir, obj_type))
        log.info("###################################################")

        log.info("Deleting the private key")
        run("%s --module %s --delete-object --type %s --label sss:0xEF000001" % (pkcs11_tool, module_path, obj_type))
        log.info("###################################################")

        obj_type = "pubkey"
        file_name = "ec_%s_pub.pem" % (prime)
        file_dir = key_dir + os.sep + file_name

        log.info("Importing ECC Public key object: %s" % (file_name))
        run("%s --module %s --write-object %s --type  %s --label sss:0xEF000001" % (pkcs11_tool, module_path, file_dir, obj_type))
        log.info("###################################################")

        log.info("Deleting the public key")
        run("%s --module %s --delete-object --type %s --label sss:0xEF000001" % (pkcs11_tool, module_path, obj_type))
        log.info("###################################################")

    obj_type = "pubkey"
    file_name = "rsa1024_public.pem"
    file_dir = key_dir + os.sep + file_name

    log.info("Importing RSA Public key object: %s" % (file_name))
    run("%s --module %s --write-object %s --type  %s --label sss:0xEF000005" % (pkcs11_tool, module_path, file_dir, obj_type))
    log.info("###################################################")

    log.info("Deleting the public key")
    run("%s --module %s --delete-object --type %s --label sss:0xEF000005" % (pkcs11_tool, module_path, obj_type))

    obj_type = "secrkey"
    key_sizes = ["16","32"]
    file_dir = key_dir + os.sep

    for key_size in key_sizes:

        log.info("Importing Secret key object of %s Bytes" % (key_size))
        run("%s --module %s --write-object %ssecr_key_%s.key --type  %s --label sss:0xEF000001" % (pkcs11_tool, module_path, file_dir, key_size, obj_type))
        log.info("###################################################")

        log.info("Deleting the Secret Key")
        run("%s --module %s --delete-object --type %s --label sss:0xEF000001" % (pkcs11_tool, module_path, obj_type))
        log.info("###################################################")

    log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()