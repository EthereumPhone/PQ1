#
# Copyright 2019-2021,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#


"""

Provision attached secure element with EC keys

This example generates a complete set of ECC key files (*.pem) (existing ones overwritten).
Performs debug reset the attached secure element.
Attached secure element provisioned with EC key.
Creates reference key from the injected EC key.

"""

import argparse

from openssl_util import *

example_text = '''

Example invocation::

    python %s --key_type prime256v1
    python %s --key_type prime256v1 --connection_data 169.254.0.1:8050
    python %s --key_type secp224k1  --connection_type jrcpv2 --connection_data 127.0.0.1:8050
    python %s --key_type brainpoolP256r1 --connection_data COM3
    python %s --key_type prime256v1 --subsystem a71ch

''' % (__file__, __file__, __file__, __file__, __file__,)


def execute_openssl_cmd(ecc_param_pem, ecc_key_kp, ecc_key_kp_pubonly):
    cmd_str = "\"%s\" ecparam -in \"%s\" -genkey -noout -out \"%s\"" % (openssl, ecc_param_pem, ecc_key_kp)
    run(cmd_str)
    cmd_str = "\"%s\" ec -in \"%s\" -pubout -out \"%s\"" % (openssl, ecc_key_kp, ecc_key_kp_pubonly)
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
        help='Supported key types => ``%s``' % ("``, ``".join(SUPPORTED_EC_KEY_TYPES)),
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
    optional.add_argument(
        '--no_reset',
        action="store_true",
        help="do not reset contents of attached secure element")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return None

    args = parser.parse_args()

    if args.key_type in ["brainpoolP160r1", "brainpoolP192r1", "brainpoolP224r1", "brainpoolP320r1",
                        "secp160k1", "secp192k1", "secp224k1"]:
        print(f"The key type '{args.key_type}' is not supported with the latest version of cryptography library.")
        return None
    if args.key_type not in SUPPORTED_EC_KEY_TYPES:
        parser.print_help(sys.stderr)
        return None

    if args.subsystem not in ["se05x", "a71ch", "mbedtls"]:
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

    ecc_param_pem = keys_dir + os.sep + args.key_type + ".pem"

    # ECC keys to be stored in SE050/A71CH
    # ------------------------------
    ecc_key_kp_0 = keys_dir + os.sep + "ecc_key_kp_0.pem"
    ecc_key_kp_pubonly_0 = keys_dir + os.sep + "ecc_key_kp_pubonly_0.pem"
    ecc_key_kp_0_ref = keys_dir + os.sep + "ecc_key_kp_0_ref.pem"

    ecc_key_kp_1 = keys_dir + os.sep + "ecc_key_kp_1.pem"
    ecc_key_kp_pubonly_1 = keys_dir + os.sep + "ecc_key_kp_pubonly_1.pem"
    ecc_key_kp_1_ref = keys_dir + os.sep + "ecc_key_kp_1_ref.pem"

    ecc_key_kp_2 = keys_dir + os.sep + "ecc_key_kp_2.pem"
    ecc_key_kp_pubonly_2 = keys_dir + os.sep + "ecc_key_kp_pubonly_2.pem"
    ecc_key_kp_2_ref = keys_dir + os.sep + "ecc_key_kp_2_ref.pem"

    ecc_key_kp_3 = keys_dir + os.sep + "ecc_key_kp_3.pem"
    ecc_key_kp_pubonly_3 = keys_dir + os.sep + "ecc_key_kp_pubonly_3.pem"
    ecc_key_kp_3_ref = keys_dir + os.sep + "ecc_key_kp_3_ref.pem"

    ecc_key_kp_A = keys_dir + os.sep + "ecc_key_kp_A.pem"
    ecc_key_kp_pubonly_A = keys_dir + os.sep + "ecc_key_kp_pubonly_A.pem"

    ecc_key_pub_0 = keys_dir + os.sep + "ecc_key_pub_0.pem"
    ecc_key_pub_pubonly_0 = keys_dir + os.sep + "ecc_key_pub_pubonly_0.pem"
    ecc_key_pub_0_ref = keys_dir + os.sep + "ecc_key_pub_0_ref.pem"

    ecc_key_pub_1 = keys_dir + os.sep + "ecc_key_pub_1.pem"
    ecc_key_pub_pubonly_1 = keys_dir + os.sep + "ecc_key_pub_pubonly_1.pem"
    ecc_key_pub_1_ref = keys_dir + os.sep + "ecc_key_pub_1_ref.pem"

    ecc_key_pub_2 = keys_dir + os.sep + "ecc_key_pub_2.pem"
    ecc_key_pub_pubonly_2 = keys_dir + os.sep + "ecc_key_pub_pubonly_2.pem"
    ecc_key_pub_2_ref = keys_dir + os.sep + "ecc_key_pub_2_ref.pem"

    ecc_key_pub_A = keys_dir + os.sep + "ecc_key_pub_A.pem"
    ecc_key_pub_pubonly_A = keys_dir + os.sep + "ecc_key_pub_pubonly_A.pem"

    run("\"%s\" ecparam -name %s -out \"%s\"" % (openssl, args.key_type, ecc_param_pem,))

    execute_openssl_cmd(ecc_param_pem, ecc_key_kp_0, ecc_key_kp_pubonly_0)
    execute_openssl_cmd(ecc_param_pem, ecc_key_kp_1, ecc_key_kp_pubonly_1)
    execute_openssl_cmd(ecc_param_pem, ecc_key_kp_2, ecc_key_kp_pubonly_2)
    execute_openssl_cmd(ecc_param_pem, ecc_key_kp_3, ecc_key_kp_pubonly_3)
    execute_openssl_cmd(ecc_param_pem, ecc_key_pub_0, ecc_key_pub_pubonly_0)
    execute_openssl_cmd(ecc_param_pem, ecc_key_pub_1, ecc_key_pub_pubonly_1)
    execute_openssl_cmd(ecc_param_pem, ecc_key_pub_2, ecc_key_pub_pubonly_2)
    execute_openssl_cmd(ecc_param_pem, ecc_key_kp_A, ecc_key_kp_pubonly_A)
    execute_openssl_cmd(ecc_param_pem, ecc_key_pub_A, ecc_key_pub_pubonly_A)

    session_close(None)

    session = session_open(args.subsystem, args.connection_data, args.connection_type, args.auth_type, args.scpkey)
    if session is None:
        return

    if not args.no_reset:
        reset(session)

    key_id = [0x7DCCBB10, 0x7DCCBB11, 0x7DCCBB12, 0x7DCCBB13]
    key_kp = [ecc_key_kp_0, ecc_key_kp_1, ecc_key_kp_2, ecc_key_kp_3]
    key_ref = [ecc_key_kp_0_ref, ecc_key_kp_1_ref, ecc_key_kp_2_ref, ecc_key_kp_3_ref]
    i = 0
    while i < len(key_id):
        status = set_ecc_pair(session, key_id[i], key_kp[i])
        if status != apis.kStatus_SSS_Success:
            return
        status = refpem_ecc_pair(session, key_id[i], key_ref[i])
        if status != apis.kStatus_SSS_Success:
            return
        i += 1

    key_id = [0x7DCCBB20, 0x7DCCBB21, 0x7DCCBB22]
    key_pub = [ecc_key_pub_pubonly_0, ecc_key_pub_pubonly_1, ecc_key_pub_pubonly_2]
    key_ref = [ecc_key_pub_0_ref, ecc_key_pub_1_ref, ecc_key_pub_2_ref]
    i = 0
    while i < len(key_id):
        status = set_ecc_pub(session, key_id[i], key_pub[i])
        if status != apis.kStatus_SSS_Success:
            return
        status = refpem_ecc_pub(session, key_id[i], key_ref[i])
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
