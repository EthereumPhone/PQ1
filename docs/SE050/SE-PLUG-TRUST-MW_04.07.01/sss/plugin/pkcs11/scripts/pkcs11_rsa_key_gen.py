#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#
"""

Generates keys of type RSA and performs sign and verify operations

"""

from pkcs11_utils import *

def main():

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    keys = {"rsa:1024":"0xEF000006", "rsa:2048":"0xEF000007", "rsa:3072":"0xEF000008", "rsa:4096":"0xEF000009"}

    for key_type in keys:
        log.info("Generating RSA keypair: %s" % (key_type))
        run("%s --module %s --keypairgen --key-type  %s --label sss:%s" % (pkcs11_tool, module_path, key_type, keys[key_type]))
        log.info("###################################################")

        log.info("Retrieving Public Key")
        run("%s --module %s --read-object --type pubkey --label sss:%s -o %srsa_%s_%s_public.key" % (pkcs11_tool, module_path, keys[key_type], output_dir, key_type.split(":")[1], keys[key_type]))
        log.info("###################################################")

        log.info("Deleting generated keypair")
        run("%s --module %s --delete-object --type privkey --label sss:%s" % (pkcs11_tool, module_path, keys[key_type]))
        log.info("###################################################")

    log.info("Generating keypair with id")
    run("%s --module %s --keypairgen --key-type  rsa:1024 --id EF000006" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("Deleting generated keypair")
    run("%s --module %s --delete-object --type privkey --id EF000006" % (pkcs11_tool, module_path))

    log.info("###################################################")
    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()