#
# Copyright 2018-2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

"""License text"""

# This script is used to generate keys and CA certificates using openssl engine.
# The generated keys shall be available in aws directory
# These keys are used to provision to the secure element

import os
import sys
import logging
logging.basicConfig(format='%(message)s', level=logging.INFO)
log = logging.getLogger(__name__)


def main():
    """
    This function generates key pair and certificates for AWS cloud.
    :return: None
    """

    # Implementation of this function has been
    # moved to simw-top/pycli/src/Provision/GenerateAWSCredentials.py
    sys.path.append(os.path.abspath(os.path.dirname(__file__)
                                    + os.sep + ".."
                                    + os.sep + "src"))
    from Provision import GenerateAWSCredentials  # pylint: disable=import-outside-toplevel

    cur_dir = os.path.abspath(os.getcwd())
    GenerateAWSCredentials.generateCredentials(cur_dir)


if __name__ == "__main__":
    main()
