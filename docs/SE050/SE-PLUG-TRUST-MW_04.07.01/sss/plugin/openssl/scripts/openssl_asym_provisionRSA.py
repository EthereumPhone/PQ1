# Copyright 2020,2025 NXP
#
# SPDX-License-Identifier: Apache-2.0
#


"""

Optionally create a set of RSA key files (*.pem) (existing ones overwritten).
Optionally perform a debug reset of the attached secure element.
Provision attached secure element with RSA key.
Create reference key for the injected RSA key.

PYTHONPATH=../scripts/ python3 openssl_asym_provisionRSA.py --no_reset --create --key_type rsa2048 --connection_data 192.168.1.190:8040

"""

import argparse

import sss.sss_api as apis

from openssl_util import *

example_text = '''

Example invocation::

    python %s --key_type rsa1024
    python %s --key_type rsa2048 --no_reset --connection_data 127.0.0.1:8050
    python %s --key_type rsa2048 --create --connection_data 127.0.0.1:8040

''' % (__file__, __file__, __file__,)


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
        '--create',
        action="store_true",
        help="create (and overwrite) credentials")
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
    else:
        parser.print_help(sys.stderr)
        return None

    if args.connection_type not in SUPPORTED_CONNECTION_TYPES:
        parser.print_help(sys.stderr)
        return None

    if args.subsystem not in ["se05x", "mbedtls"]:
        parser.print_help(sys.stderr)
        return None

    return args


def main():
    args = parse_in_args()
    if args is None:
        return

    keys_dir = os.path.join(cur_dir, '..', 'tst_keys')

    key_size = args.key_type.replace("rsa", "")
    # if not os.path.exists(keys_dir):
    #     os.mkdir(keys_dir)



    rsa_key_pair_a = keys_dir + os.sep + "rsa_A_" + key_size + "_kp.pem"
    rsa_key_pub_a = keys_dir + os.sep + "rsa_A_" + key_size + "_pub.pem"
    rsa_ref_key_pair_a = keys_dir + os.sep + "rsa_A_" + key_size + "_kp_ref.pem"

    rsa_key_pair_b = keys_dir + os.sep + "rsa_B_" + key_size + "_kp.pem"
    rsa_key_pub_b = keys_dir + os.sep + "rsa_B_" + key_size + "_pub.pem"
    rsa_ref_key_pair_b = keys_dir + os.sep + "rsa_B_" + key_size + "_kp_ref.pem"
    
    if args.create:
        run("%s genrsa -out %s %d" % (openssl, rsa_key_pair_a, int(key_size)))
        run("%s genrsa -out %s %d" % (openssl, rsa_key_pair_b, int(key_size)))
        run("%s rsa -in %s -RSAPublicKey_out -out %s" % (openssl, rsa_key_pair_a, rsa_key_pub_a))
        run("%s rsa -in %s -RSAPublicKey_out -out %s" % (openssl, rsa_key_pair_b, rsa_key_pub_b))


    session_close(None)

    session = session_open(args.subsystem, args.connection_data, args.connection_type, args.auth_type, args.scpkey)
    if session is None:
        return

    if not args.no_reset:
        reset(session)

    key_id = [0x7D010000, 0x7D010001]
    key_kp = [rsa_key_pair_a, rsa_key_pair_b]
    key_ref = [rsa_ref_key_pair_a, rsa_ref_key_pair_b]
    i = 0
    while i < len(key_id):
        status = set_rsa_pair(session, key_id[i], key_kp[i])
        if status != apis.kStatus_SSS_Success:
            return
        status = refpem_rsa(session, key_id[i], key_ref[i])
        if status != apis.kStatus_SSS_Success:
            return
        i += 1

    session_close(session)

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
