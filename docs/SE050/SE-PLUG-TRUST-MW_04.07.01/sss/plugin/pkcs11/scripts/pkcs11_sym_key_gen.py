#
# Copyright 2023,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#

"""
Generates symmetric key of type AES
"""

from pkcs11_utils import *

OPENSC_UNSUPPORTED_VERSION = ["0.23.0",
     "0.22.0",
     "0.21.0",
     "0.20.0"]

def main():
    opensc_version = get_opensc_version().strip()
    keys = ["aes:16", "aes:24", "aes:32"]
    for key in keys:
        log.info("Generating symmetric key: %s.. (Generates random data and set key)" % (key))
        run("%s --module %s --keygen --key-type %s --label sss:0xEF00000B" % (pkcs11_tool, module_path, key))
        log.info("###################################################")

        log.info("Deleting Key")
        run("%s --module %s --delete-object --type secrkey --label sss:0xEF00000B" % (pkcs11_tool, module_path))
        log.info("###################################################")

    for version in OPENSC_UNSUPPORTED_VERSION:
        if version in opensc_version:
            log.info("generic keytype is not supported for opensc version %s"%(version))
            return

    keys = ["generic:16", "generic:24", "generic:32"]
    for key in keys:
        log.info("Generating symmetric key: %s.. (Generates random data and set key)" % (key))
        run("%s --module %s --keygen --key-type %s --label sss:0xEF00000C" % (pkcs11_tool, module_path, key))
        log.info("###################################################")

        log.info("Deleting Key")
        run("%s --module %s --delete-object --type secrkey --label sss:0xEF00000C" % (pkcs11_tool, module_path))
        log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()