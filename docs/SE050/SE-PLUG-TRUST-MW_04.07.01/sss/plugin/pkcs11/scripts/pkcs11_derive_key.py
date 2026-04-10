#
# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0
#

"""
Generates derive key
"""

from pkcs11_utils import *

OPENSC_UNSUPPORTED_P192 = "0.23.0"

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    opensc_version = get_opensc_version().strip()
    if OPENSC_UNSUPPORTED_P192 in opensc_version:
        keys = {"EC:prime256v1":"0xEF000001", "EC:prime521v1":"0xEF000002",
                "EC:secp256k1":"0xEF000003", "EC:brainpoolP256r1":"0xEF000004",
                "EC:brainpoolP512r1":"0xEF000005"}
    else:
        keys = {"EC:prime192v1":"0xEF000001","EC:prime256v1":"0xEF000002",
                "EC:secp256k1":"0xEF000003", "EC:brainpoolP256r1":"0xEF000004",
                "EC:brainpoolP512r1":"0xEF000005"}

    for key_type in keys:
        log.info("Generating keypair: %s" % (key_type))
        run("%s --module %s --keypairgen --key-type  %s --label sss:%s" % (pkcs11_tool, module_path, key_type, keys[key_type]))
        log.info("###################################################")

        log.info("Retrieving Public Key")
        run("%s --module %s --read-object --type pubkey --label sss:%s -o %s%s_%s_public.key" % (pkcs11_tool, module_path, keys[key_type], output_dir, key_type.split(":")[1], keys[key_type]))
        log.info("###################################################")

        log.info("create shared secret")
        run("%s --module %s --derive --mechanism ECDH1-DERIVE --label sss:%s --input-file %s%s_%s_public.key -o %sshared.key" % (pkcs11_tool, module_path,keys[key_type],output_dir, key_type.split(":")[1], keys[key_type],output_dir))

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