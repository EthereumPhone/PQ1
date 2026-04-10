#
# Copyright 2023-2024 NXP
# SPDX-License-Identifier: Apache-2.0
#

"""
Generates keys of type ECC
"""

from pkcs11_utils import *

OPENSC_UNSUPPORTED_P192 = "0.23.0"

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    opensc_version = get_opensc_version().strip()
    if OPENSC_UNSUPPORTED_P192 in opensc_version:
        keys = {"EC:prime256v1":"0xEF000001", "EC:secp256k1":"0xEF000002",
                "EC:brainpoolP256r1":"0xEF000003", "EC:brainpoolP512r1":"0xEF000004"}
    else:
        keys = {"EC:prime192v1":"0xEF000001", "EC:prime256v1":"0xEF000002",
                "EC:secp224r1":"0xEF000001", "EC:secp384r1":"0xEF000003",
                "EC:secp521r1":"0xEF000004", "EC:secp192k1":"0xEF000005",
                "EC:secp256k1":"0xEF000006", "EC:brainpoolP192r1":"0xEF000003",
                "EC:brainpoolP224r1":"0xEF000003", "EC:brainpoolP256r1":"0xEF000003",
                "EC:brainpoolP320r1":"0xEF000003", "EC:brainpoolP384r1":"0xEF000003",
                "EC:brainpoolP512r1":"0xEF000003"}

    for key_type in keys:
        log.info("Generating keypair: %s" % (key_type))
        run("%s --module %s --keypairgen --key-type  %s --label sss:%s" % (pkcs11_tool, module_path, key_type, keys[key_type]))
        log.info("###################################################")

        log.info("Retrieving Public Key")
        run("%s --module %s --read-object --type pubkey --label sss:%s -o %s%s_%s_public.key" % (pkcs11_tool, module_path, keys[key_type], output_dir, key_type.split(":")[1], keys[key_type]))
        log.info("###################################################")

        log.info("Deleting generated keypair")
        run("%s --module %s --delete-object --type privkey --label sss:%s" % (pkcs11_tool, module_path, keys[key_type]))
        log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()