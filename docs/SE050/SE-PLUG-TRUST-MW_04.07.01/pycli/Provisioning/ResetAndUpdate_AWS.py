#
# Copyright 2018-2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

"""License text"""

# This script is used to provision key, intermediate key, certificate and
# intermediate certificate to secure element.
# These Provisioned keys and certificates are used in aws demo

import os
import sys
import logging

log = logging.getLogger(__name__)
logging.basicConfig(format='%(message)s', level=logging.INFO)

# Keypair, intermediate keypair, certificate and intermediate certificate index for AWS
# (simw-top\demos\ksdk\common\aws_iot_config.h)
KEYPAIR_INDEX_CLIENT_PRIVATE = 0x20181005
KEYPAIR_INDEX_CLIENT_INTERMEDIATE = 0x20181006
CERTIFICATE_INDEX_CLIENT = 0x20181007
CERTIFICATE_INDEX_INTERMEDIATE = 0x20181008


def main():
    """
    This function provision the generated key pair and certificates for AWS cloud.
    :return: None
    """

    # Implementation of this function has been
    # moved to simw-top/pycli/src/Provision/ResetAndUpdate_AWS.py
    sys.path.append(os.path.abspath(os.path.dirname(__file__)
                                    + os.sep + ".."
                                    + os.sep + "src"))
    from Provision import ResetAndUpdate_AWS  # pylint: disable=import-outside-toplevel

    cur_dir = os.getcwd()
    ResetAndUpdate_AWS.reset_and_update(cur_dir,
                                        KEYPAIR_INDEX_CLIENT_PRIVATE,
                                        KEYPAIR_INDEX_CLIENT_INTERMEDIATE,
                                        CERTIFICATE_INDEX_CLIENT,
                                        CERTIFICATE_INDEX_INTERMEDIATE)


if __name__ == '__main__':
    main()
