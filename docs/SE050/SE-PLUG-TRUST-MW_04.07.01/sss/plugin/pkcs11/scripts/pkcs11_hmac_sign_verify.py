#
# Copyright 2024-2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
"""

Generates generic key and performs hmac sign and verify operations

"""

from pkcs11_utils import *

OPENSC_UNSUPPORTED_VERSION = ["0.23.0",
     "0.22.0",
     "0.21.0",
     "0.20.0"]

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    opensc_version = get_opensc_version().strip()
    for version in OPENSC_UNSUPPORTED_VERSION:
        if version in opensc_version:
            log.info("Script is not supported for opensc version %s"%(version))
            return 

    obj_type = "secrkey"
    filename = "secr_key_16.key"
    key_type = "GENERIC:16"
    file_dir = key_dir + os.sep + filename
    log.info("Importing key: %s", file_dir)
    # set hmac key
    run("%s --module %s --write-object  %s --type %s --key-type  %s --label sss:0xEF000001" % (pkcs11_tool, module_path, file_dir, obj_type, key_type))
    log.info("###################################################")

    sha_types = ["SHA-1-HMAC","SHA256-HMAC","SHA384-HMAC","SHA512-HMAC"]
    for sha_type in sha_types:
        log.info("Signing data with length = 600 and with key: %s and algo: %s" % (filename, sha_type))
        run("%s --module %s --sign --mechanism %s --id EF000001 --input-file %sdata600.txt -o %sout_%s_input_600_hmac.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type))
        log.info("###################################################")

        log.info("Verifying data with length = 600 and with key: %s and algo: %s" % (filename, sha_type))
        run("%s --module %s --verify --mechanism %s --id EF000001 --input-file %sdata600.txt --signature-file %sout_%s_input_600_hmac.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type))
        log.info("###################################################")


        log.info("Signing data with length = 1024 and with key: %s and algo: %s" % (filename, sha_type))
        run("%s --module %s --sign --mechanism %s --id EF000001 --input-file %sdata1024.txt -o %sout_%s_input_600_hmac.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type))
        log.info("###################################################")

        log.info("Verifying data with length = 1024 and with key: %s and algo: %s" % (filename, sha_type))
        run("%s --module %s --verify --mechanism %s --id EF000001 --input-file %sdata1024.txt --signature-file %sout_%s_input_600_hmac.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type))
        log.info("###################################################")


        log.info("Signing data with length = 2048 and with key: %s and algo: %s" % (filename, sha_type))
        run("%s --module %s --sign --mechanism %s --id EF000001 --input-file %sdata2048.txt -o %sout_%s_input_600_hmac.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type))
        log.info("###################################################")

        log.info("Verifying data with length = 2048 and with key: %s and algo: %s" % (filename, sha_type))
        run("%s --module %s --verify --mechanism %s --id EF000001 --input-file %sdata2048.txt --signature-file %sout_%s_input_600_hmac.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type))
        log.info("###################################################")


    log.info("Deleting generated keypair")
    run("%s --module %s --delete-object --type privkey --label sss:0xEF000001" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()