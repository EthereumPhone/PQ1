#
# Copyright 2022,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
import argparse

import sss.sss_api as apis

from openssl_util import *

example_text = '''

Example invocation::

    python %s --key_type rsa1024
    python %s --key_type rsa2048 --connection_data 169.254.0.1:8050
    python %s --key_type rsa2048 --connection_data 127.0.0.1:8050 --connection_type jrcpv2
    python %s --key_type rsa2048 --connection_data COM3

''' % (__file__, __file__, __file__, __file__,)


def parse_in_args():
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=example_text,
        formatter_class=argparse.RawTextHelpFormatter)
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    required.add_argument(
        '--key_type',
        default="",
        help='Supported key types => ``%s``' % ("``, ``".join(SUPPORTED_RSA_KEY_TYPES)), required=True)
    optional.add_argument(
        '--connection_type',
        default="t1oi2c",
        help='Supported connection types => ``%s``. Default: ``t1oi2c``' % ("``, ``".join(SUPPORTED_CONNECTION_TYPES)))
    optional.add_argument(
        '--connection_data',
        default="none",
        help='Parameter to connect to SE => eg. ``COM3``, ``127.0.0.1:8050``, ``none``. Default: ``none``')
    optional.add_argument(
        '--subsystem',
        default="se05x",
        help='Supported subsystem => ``se05x``, ``mbedtls``. Default: ``se05x``')
    optional.add_argument(
        '--auth_type',
        default="None",
        help='Supported subsystem => ``None``, ``PlatformSCP``, ``UserID``, ``ECKey``, ``AESKey``, '
        '``UserID_PlatformSCP``, ``ECKey_PlatformSCP``, ``AESKey_PlatformSCP``. Default: ``None``')
    optional.add_argument(
        '--scpkey',
        default="None",
        help='')
    optional.add_argument(
        '--no_reset',
        action="store_true",
        help="do not reset contents of attached secure element")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return None

    args = parser.parse_args()
    if args.key_type not in SUPPORTED_RSA_KEY_TYPES:
        parser.print_help(sys.stderr)
        return None

    if args.auth_type not in ["None", "PlatformSCP", "UserID", "ECKey", "AESKey", "UserID_PlatformSCP", "ECKey_PlatformSCP", "AESKey_PlatformSCP"]:
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
        pass

    if args.connection_type not in SUPPORTED_CONNECTION_TYPES:
        parser.print_help(sys.stderr)
        return None

    if args.subsystem not in ["se05x", "mbedtls"]:
        parser.print_help(sys.stderr)
        return None

    return args


def main():
    key_id = 0x6DCCBB11

    args = parse_in_args()
    if args is None:
        return

    keys_dir = os.path.join(cur_dir, '..', 'keys', args.key_type)

    key_size = args.key_type.replace("rsa", "")
    if not os.path.exists(keys_dir):
        os.mkdir(keys_dir)

    rsa_key_pair = keys_dir + os.sep + "rsa_1_prv.pem"
    rsa_pub_key  =  keys_dir + os.sep + "rsa_1_pub.pem"
    rsa_ref_key_pair = keys_dir + os.sep + "rsa_ref_prv.pem"

    run("%s genrsa -out %s %d" % (openssl_bin, rsa_key_pair, int(key_size)))
    run("%s rsa -in %s -pubout > %s"%(openssl_bin,rsa_key_pair,rsa_pub_key))

    session_close(None)

    session = session_open(args.subsystem, args.connection_data, args.connection_type, args.auth_type, args.scpkey)
    if session is None:
        return

    if not args.no_reset:
        reset(session)
    # Inject rsa key pair into the Secure Element
    status = set_rsa_pair(session, key_id, rsa_key_pair)
    if status != apis.kStatus_SSS_Success:
        return
    # Generate Reference key from the key injected. Store it in file referred by "rsa_ref_key_pair" variable.
    status = refpem_rsa(session, key_id, rsa_ref_key_pair)
    if status != apis.kStatus_SSS_Success:
        return

    session_close(session)

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
