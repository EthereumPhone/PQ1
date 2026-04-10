#
# Copyright 2019-2021,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#


"""

Provision attached secure element with EC montogomery keys

This example generates EC montogomery key files (*.pem) (existing ones overwritten).
Performs debug reset the attached secure element.
Attached secure element provisioned with EC montogomery key.
Creates reference key from the injected EC montogomery key.

"""

import argparse

from openssl_util import *

example_text = '''

Example invocation::

    python %s --key_type x25519
    python %s --key_type x25519 --connection_data 169.254.0.1:8050
    python %s --key_type x448  --connection_type jrcpv2 --connection_data 127.0.0.1:8050
    python %s --key_type x448 --connection_data COM3


''' % (__file__, __file__, __file__, __file__,)


def execute_openssl_cmd(algorithm, ecx_key_kp, ecx_key_kp_pubonly):
    cmd_str = "\"%s\" genpkey -algorithm \"%s\" -out \"%s\" " % (openssl, algorithm, ecx_key_kp)
    run(cmd_str)
    cmd_str = "\"%s\" pkey -in \"%s\" -pubout -out \"%s\"" % (openssl, ecx_key_kp, ecx_key_kp_pubonly)
    run(cmd_str)


def parse_in_args():
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=example_text,
        formatter_class=argparse.RawTextHelpFormatter)
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    required.add_argument(
        '--key_type',
        default="",
        help='Supported key types => ``%s``' % ("``, ``".join(SUPPORTED_ECX_KEY_TYPES)),
        required=True)
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
        help='Supported subsystem => ``se05x``, ``a71ch``, ``mbedtls``. Default: ``se05x``')
    optional.add_argument(
        '--auth_type',
        default="None",
        help='Supported subsystem => ``None``, ``PlatformSCP``, ``UserID``, ``ECKey``, ``AESKey``, '
        '``UserID_PlatformSCP``, ``ECKey_PlatformSCP``, ``AESKey_PlatformSCP``. Default: ``None``')
    optional.add_argument(
        '--scpkey',
        default="None",
        help='')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return None

    args = parser.parse_args()

    if args.key_type not in SUPPORTED_ECX_KEY_TYPES:
        parser.print_help(sys.stderr)
        return None

    if args.subsystem not in ["se05x", "mbedtls"]:
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
        if args.subsystem == "a71ch":
            args.connection_type = "sci2c"

    if args.connection_type not in SUPPORTED_CONNECTION_TYPES:
        parser.print_help(sys.stderr)
        return None

    return args


def main():
    args = parse_in_args()
    if args is None:
        return

    keys_dir = os.path.join(cur_dir, '..', 'keys', args.key_type)
    import sss.sss_api as apis

    if not os.path.exists(keys_dir):
        os.mkdir(keys_dir)

    # ECX keys to be stored in SE051
    # ------------------------------
    ecx_key_kp_0 = keys_dir + os.sep + "ecx_key_kp_0.pem"
    ecx_key_kp_pubonly_0 = keys_dir + os.sep + "ecx_key_kp_pubonly_0.pem"
    ecx_key_kp_0_ref = keys_dir + os.sep + "ecx_key_kp_0_ref.pem"

    ecx_key_kp_1 = keys_dir + os.sep + "ecx_key_kp_1.pem"
    ecx_key_kp_pubonly_1 = keys_dir + os.sep + "ecx_key_kp_pubonly_1.pem"
    ecx_key_kp_1_ref = keys_dir + os.sep + "ecx_key_kp_1_ref.pem"

    ecx_key_kp_2 = keys_dir + os.sep + "ecx_key_kp_2.pem"
    ecx_key_kp_pubonly_2 = keys_dir + os.sep + "ecx_key_kp_pubonly_2.pem"
    ecx_key_kp_2_ref = keys_dir + os.sep + "ecx_key_kp_2_ref.pem"

    ecx_key_kp_3 = keys_dir + os.sep + "ecx_key_kp_3.pem"
    ecx_key_kp_pubonly_3 = keys_dir + os.sep + "ecx_key_kp_pubonly_3.pem"
    ecx_key_kp_3_ref = keys_dir + os.sep + "ecx_key_kp_3_ref.pem"


    execute_openssl_cmd(args.key_type, ecx_key_kp_0, ecx_key_kp_pubonly_0)
    execute_openssl_cmd(args.key_type, ecx_key_kp_1, ecx_key_kp_pubonly_1)
    execute_openssl_cmd(args.key_type, ecx_key_kp_2, ecx_key_kp_pubonly_2)
    execute_openssl_cmd(args.key_type, ecx_key_kp_3, ecx_key_kp_pubonly_3)

    session_close(None)

    session = session_open(args.subsystem, args.connection_data, args.connection_type, args.auth_type, args.scpkey)
    if session is None:
        return

    reset(session)

    key_id = [0x7DCCBB10, 0x7DCCBB11, 0x7DCCBB12, 0x7DCCBB13]
    key_kp = [ecx_key_kp_0, ecx_key_kp_1, ecx_key_kp_2, ecx_key_kp_3]
    key_ref = [ecx_key_kp_0_ref, ecx_key_kp_1_ref, ecx_key_kp_2_ref, ecx_key_kp_3_ref]
    i = 0
    while i < len(key_id):
        status = set_ecc_pair(session, key_id[i], key_kp[i])
        if status != apis.kStatus_SSS_Success:
            return
        status = refpem_ecc_pair(session, key_id[i], key_ref[i])
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
    main()
