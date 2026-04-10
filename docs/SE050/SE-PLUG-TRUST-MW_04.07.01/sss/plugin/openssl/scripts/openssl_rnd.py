#
# Copyright 2019,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#

"""

Generate few random numbers from the attached secure element.

"""

import argparse

from openssl_util import *

example_text = '''

Example invocation::

    python %s --connection_data 127.0.0.1:8050

''' % (__file__,)


def parse_in_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=example_text,
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        '--connection_data',
        default="none",
        help='Parameter to connect to SE => eg. ``COM3``, ``127.0.0.1:8050``, ``none``. Default: ``none``')

    args = parser.parse_args()

    if args.connection_data.find(':') >= 0:
        port_data = args.connection_data.split(':')
        jrcp_host_name = port_data[0]
        jrcp_port = port_data[1]
        os.environ['JRCP_HOSTNAME'] = jrcp_host_name
        os.environ['JRCP_PORT'] = jrcp_port
        os.environ['EX_SSS_BOOT_SSS_PORT'] = args.connection_data
        log.info("JRCP_HOSTNAME: %s" % jrcp_host_name)
        log.info("JRCP_PORT: %s" % jrcp_port)
        log.info("EX_SSS_BOOT_SSS_PORT: %s" % args.connection_data)
    elif args.connection_data.find('COM') >= 0:
        os.environ['EX_SSS_BOOT_SSS_PORT'] = args.connection_data


def main():
    parse_in_args()
    run("%s rand -engine %s -hex 8" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 16" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 32" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 64" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 128" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 256" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 384" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 512" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 748" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 5000" % (openssl, openssl_engine))

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
