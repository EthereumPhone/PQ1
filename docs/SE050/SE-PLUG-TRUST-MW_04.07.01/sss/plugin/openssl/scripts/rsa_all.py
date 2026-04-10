#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#

"""

Validation of OpenSSL Engine using RSA keys


This example injects keys with different supported RSA keys,
then showcases Crypto & sign verify operations using those keys.

"""

import argparse

from openssl_util import *

example_text = '''

Example invocation::

    python %s
    python %s --connection_data 169.254.0.1:8050
    python %s --connection_data 127.0.0.1:8050 --connection_type jrcpv2
    python %s --connection_data COM3

''' % (__file__, __file__, __file__, __file__,)


def parse_in_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=example_text,
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        '--connection_data',
        default="none",
        help='Parameter to connect to SE => eg. ``COM3``, ``127.0.0.1:8050``, ``none``. Default: ``none``')
    parser.add_argument(
        '--connection_type',
        default="t1oi2c",
        help='Supported connection types => ``%s``. Default: ``t1oi2c``' % ("``, ``".join(SUPPORTED_CONNECTION_TYPES)))
    parser.add_argument(
        '--subsystem',
        default="se050",
        help='Supported subsystem => ``se05x``. Default: ``se05x``')
    parser.add_argument(
        '--auth_type',
        default="None",
        help='Supported subsystem => ``None``, ``PlatformSCP``, ``UserID``, ``ECKey``, ``AESKey``. Default: ``None``')
    parser.add_argument(
        '--scpkey',
        default="None",
        help='')
    parser.add_argument(
        '--disable_sha1',
        default="False",
        help='Parameter to disable SHA1 => eg. ``True``, ``False``. Default: ``False``')
    parser.add_argument(
        '--fips',
        default="False",
        help='FIPS Testing => eg. ``True``, ``False``. Default: ``False``')

    args = parser.parse_args()

    if args.subsystem not in ["se050"]:
        parser.print_help(sys.stderr)
        return None

    if args.connection_data.find(':') >= 0:
        port_data = args.connection_data.split(':')
        jrcp_host_name = port_data[0]
        jrcp_port = port_data[1]
        os.environ['JRCP_HOSTNAME'] = jrcp_host_name
        os.environ['JRCP_PORT'] = jrcp_port
        log.info("JRCP_HOSTNAME: %s" % jrcp_host_name)
        log.info("JRCP_PORT: %s" % jrcp_port)
        if args.connection_type == "t1oi2c":
            args.connection_type = "jrcpv1"
    elif args.connection_data.find('COM') >= 0:
        if args.connection_type == "t1oi2c":
            args.connection_type = "vcom"
    elif args.connection_data.find('none') >= 0:
        if args.subsystem == "a71ch":
            args.connection_type = "sci2c"
    else:
        parser.print_help(sys.stderr)
        return None

    if args.connection_type not in SUPPORTED_CONNECTION_TYPES:
        parser.print_help(sys.stderr)
        return None

    return args


def main():
    args = parse_in_args()
    if args is None:
        return

    if args.fips == 'True':
        rsa_bit_len = SUPPORTED_RSA_KEY_TYPES_FIPS
    else:
        rsa_bit_len = SUPPORTED_RSA_KEY_TYPES

    python_exe = sys.executable

    for bit_len in rsa_bit_len:
        print(bit_len)
        run("%s openssl_provisionRSA.py --key_type %s --connection_type %s --connection_data %s --auth_type %s --scpkey %s" %
            (python_exe, bit_len, args.connection_type, args.connection_data, args.auth_type, args.scpkey))
        run("%s openssl_RSA.py --key_type %s --connection_data %s --disable_sha1 %s" % (python_exe, bit_len, args.connection_data, args.disable_sha1))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
