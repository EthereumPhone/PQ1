#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#

"""
Shows basic infor of PKCS11 module
"""

from pkcs11_utils import *

def main():
    log.info("PKCS11 Show info")
    run("%s --module %s --show-info" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("Listing slots")
    run("%s --module %s --list-slots" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("Listing token slots")
    run("%s --module %s --list-token-slots" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("Listing supported mechanisms")
    run("%s --module %s --list-mechanisms" % (pkcs11_tool, module_path))
    log.info("###################################################")

    # log.info("Listing interfaces")
    # run("%s --module %s --list-interfaces" % (pkcs11_tool, module_path))
    # log.info("###################################################")

    log.info("Listing Objects ")
    run("%s --module %s -O" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()