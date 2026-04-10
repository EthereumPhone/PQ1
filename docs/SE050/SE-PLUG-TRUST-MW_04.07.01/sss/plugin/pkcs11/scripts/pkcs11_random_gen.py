#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#

"""
Generates random data
"""

from pkcs11_utils import *

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    sizes = [1,16,32,64,128,512,1024]
    for size in sizes:
        log.info("Generating random data of %s bytes" % (size))
        run("%s --module %s --generate-random  %s -o %srandom_data.txt" % (pkcs11_tool, module_path, size, output_dir))
        log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()