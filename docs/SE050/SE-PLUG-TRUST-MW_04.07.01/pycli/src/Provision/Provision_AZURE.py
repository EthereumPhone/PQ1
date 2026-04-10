#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

import os
import traceback
import sys
sss_dir = os.path.abspath(os.getcwd()
                                + os.sep + ".."
                                + os.sep + ".."
                                + os.sep + "pycli"
                                + os.sep + "src")
sys.path.append(sss_dir)

from Provision import GenerateAZURECredentials
from Provision import ResetAndUpdate_AZURE
from Provision.Provision_util import *

# Keypair and certificate index for AZURE (simw-top\demos\ksdk\azure\azure_iot_config.h)
KEYPAIR_INDEX_CLIENT_PRIVATE = 0x223344
CERTIFICATE_INDEX = 0x223345


def main():
    try:
        # working directory for SIMW-TOP/binaries/PCWindows/ssscli
        cur_dir = os.getcwd()
        # SIMW-TOP directory for SIMW-TOP/binaries/PCWindows/ssscli
        simw_top_dir = os.path.join(cur_dir, '..', '..', '..')
        status = GenerateAZURECredentials.generateCredentials(cur_dir, simw_top_dir)
        if status == STATUS_SUCCESS:
            ResetAndUpdate_AZURE.reset_and_update(cur_dir,
                                                  KEYPAIR_INDEX_CLIENT_PRIVATE,
                                                  CERTIFICATE_INDEX)
    except Exception as exc:
        log.error("%s" % str(exc))
        error_file = os.getcwd() + os.sep + "error_log.txt"
        if not os.path.isfile(error_file):
            err_write = open(error_file, 'w+')
        else:
            err_write = open(error_file, 'a+')
            err_write.write("\n\n")
        traceback.print_exc(None, err_write)
        err_write.close()


if __name__ == '__main__':
    main()
