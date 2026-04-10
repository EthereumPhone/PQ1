#
# Copyright 2019,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#

"""

Validation of ECDH with OpenSSL engine using EC keys

This example showcases ECDH between openssl engine and openssl.

Precondition:
    - Inject keys using ``openssl_provisionEC.py``.

"""

import argparse

from openssl_util import *

example_text = '''

Example invocation::

    python %s --key_type prime256v1
    python %s --key_type secp160k1 --connection_data 127.0.0.1:8050

''' % (__file__, __file__,)


def parse_in_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=example_text,
        formatter_class=argparse.RawTextHelpFormatter)
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    required.add_argument(
        '--key_type',
        default="",
        help='Supported key types => ``%s``' % ("``, ``".join(SUPPORTED_EC_KEY_TYPES)),
        required=True)
    optional.add_argument(
        '--connection_data',
        default="none",
        help='Parameter to connect to SE => eg. ``COM3``, ``127.0.0.1:8050``, ``none``. Default: ``none``')
    optional.add_argument(
        '--disable_sha1',
        default="False",
        help='Parameter to disable SHA1 => eg. ``True``, ``False``. Default: ``False``')
    optional.add_argument(
        '--output_dirname',
        default="output",
        help='Directory name of directory storing calculated signatures (used in case of concurrent invocation)')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return None

    args = parser.parse_args()

    if args.key_type not in SUPPORTED_EC_KEY_TYPES:
        parser.print_help(sys.stderr)
        return None

    if args.disable_sha1 not in ["True", "False"]:
        parser.print_help(sys.stderr)
        return None

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

    return args


def main():
    args = parse_in_args()
    if args is None:
        return

    keys_dir = os.path.join(cur_dir, '..', 'keys', args.key_type)

    output_dir = cur_dir + os.sep + args.output_dirname
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    KEYPAIR_REF_0 = keys_dir + os.sep + "ecc_key_kp_0_ref.pem"
    KEYPAIR_0 = keys_dir + os.sep + "ecc_key_kp_0.pem"
    KEYPAIR_REF_1 = keys_dir + os.sep + "ecc_key_kp_1_ref.pem"
    KEYPAIR_1 = keys_dir + os.sep + "ecc_key_kp_1.pem"
    KEYPAIR_REF_2 = keys_dir + os.sep + "ecc_key_kp_2_ref.pem"
    KEYPAIR_2 = keys_dir + os.sep + "ecc_key_kp_2.pem"
    KEYPAIR_REF_3 = keys_dir + os.sep + "ecc_key_kp_3_ref.pem"
    KEYPAIR_3 = keys_dir + os.sep + "ecc_key_kp_3.pem"

    ECC_KEY_KP_A = keys_dir + os.sep + "ecc_key_kp_A.pem"
    ECC_KEY_KP_PUBONLY_A = keys_dir + os.sep + "ecc_key_kp_pubonly_A.pem"

    PUBKEY_0 = keys_dir + os.sep + "ecc_key_pub_pubonly_0.pem"
    PUBKEY_1 = keys_dir + os.sep + "ecc_key_pub_pubonly_1.pem"
    PUBKEY_2 = keys_dir + os.sep + "ecc_key_pub_pubonly_2.pem"

    ECC_KEY_PUB_A = keys_dir + os.sep + "ecc_key_pub_A.pem"
    ECC_KEY_PUB_PUBONLY_A = keys_dir + os.sep + "ecc_key_pub_pubonly_A.pem"

    SHARED_SECRET_HOST_0 = output_dir + os.sep + "ecdh_host_0.bin"
    SHARED_SECRET_ENGINE_0 = output_dir + os.sep + "ecdh_engine_0.bin"
    SHARED_SECRET_HOST_1 = output_dir + os.sep + "ecdh_host_1.bin"
    SHARED_SECRET_ENGINE_1 = output_dir + os.sep + "ecdh_engine_1.bin"
    SHARED_SECRET_HOST_2 = output_dir + os.sep + "ecdh_host_2.bin"
    SHARED_SECRET_ENGINE_2 = output_dir + os.sep + "ecdh_engine_2.bin"
    SHARED_SECRET_HANDOVER_A = output_dir + os.sep + "ecdh_handover_A.bin"
    SHARED_SECRET_HOST_A = output_dir + os.sep + "ecdh_host_A.bin"

    log.info("## Clean up %s, %s etc." % (SHARED_SECRET_HOST_0, SHARED_SECRET_ENGINE_0))
    log.info("######################################################")
    if sys.platform.startswith("win"):
        run("del -f %s" % (SHARED_SECRET_HOST_0,))
        run("del -f %s" % (SHARED_SECRET_ENGINE_0,))
        run("del -f %s" % (SHARED_SECRET_HOST_1,))
        run("del -f %s" % (SHARED_SECRET_ENGINE_1,))
        run("del -f %s" % (SHARED_SECRET_HOST_2,))
        run("del -f %s" % (SHARED_SECRET_ENGINE_2,))
        run("del -f %s" % (SHARED_SECRET_HANDOVER_A,))
        run("del -f %s" % (SHARED_SECRET_HOST_A,))
    else:
        run("rm -f %s %s" % (SHARED_SECRET_HOST_0, SHARED_SECRET_ENGINE_0))
        run("rm -f %s %s %s %s" % (SHARED_SECRET_HOST_1, SHARED_SECRET_ENGINE_1, SHARED_SECRET_HOST_2,
                                   SHARED_SECRET_ENGINE_2))
        run("rm -f %s %s" % (SHARED_SECRET_HANDOVER_A, SHARED_SECRET_HOST_A))

    log.info("## Do ECDH on Host (%s)" % (KEYPAIR_0,))
    log.info("######################################")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" % (openssl, KEYPAIR_0, PUBKEY_0,
                                                                       SHARED_SECRET_HOST_0))
    log.info("## Do ECDH with Engine (%s)" % (KEYPAIR_REF_0,))
    log.info("##############################################")
    run("%s pkeyutl -engine %s -inkey %s -peerkey %s -derive -hexdump -out %s" %
        (openssl, openssl_engine, KEYPAIR_REF_0, PUBKEY_0, SHARED_SECRET_ENGINE_0))
    log.info("## Confirm the two calculations are the same")
    log.info("############################################")
    compare(SHARED_SECRET_HOST_0, SHARED_SECRET_ENGINE_0)

    log.info("## Do ECDH on Host (%s) " % (KEYPAIR_1,))
    log.info("############################################")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" % (openssl, KEYPAIR_1, PUBKEY_1,
                                                                       SHARED_SECRET_HOST_1))
    log.info("## Do ECDH with Engine (%s) " % (KEYPAIR_REF_1,))
    log.info("############################################")
    run("%s pkeyutl -engine %s -inkey %s -peerkey %s -derive -hexdump -out %s" %
        (openssl, openssl_engine, KEYPAIR_REF_1, PUBKEY_1, SHARED_SECRET_ENGINE_1))
    compare(SHARED_SECRET_HOST_1, SHARED_SECRET_ENGINE_1)

    log.info("## Do ECDH on Host (%s) " % (KEYPAIR_2,))
    log.info("############################################")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" %
        (openssl, KEYPAIR_2, PUBKEY_2, SHARED_SECRET_HOST_2))
    log.info("## Do ECDH with Engine (%s) " % (KEYPAIR_REF_2,))
    log.info("############################################")
    run("%s pkeyutl -engine %s -inkey %s -peerkey %s -derive -hexdump -out %s" %
        (openssl, openssl_engine, KEYPAIR_REF_2, PUBKEY_2, SHARED_SECRET_ENGINE_2))
    compare(SHARED_SECRET_HOST_2, SHARED_SECRET_ENGINE_2)

    log.info("## #################################################################")
    log.info("## Validate Key Handover from Engine to OpenSSL SW implementation")
    log.info("## Do ECDH (%s) with Handover" % (ECC_KEY_KP_A))
    log.info("## #################################")
    run("%s pkeyutl -engine %s -inkey %s -peerkey %s -derive -hexdump -out %s" %
        (openssl, openssl_engine, ECC_KEY_KP_A, ECC_KEY_PUB_PUBONLY_A, SHARED_SECRET_HANDOVER_A))
    log.info("## Do ECDH (%s) on Host" % (ECC_KEY_KP_A,))
    log.info("## #################################")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" %
        (openssl, ECC_KEY_KP_A, ECC_KEY_PUB_PUBONLY_A, SHARED_SECRET_HOST_A))
    compare(SHARED_SECRET_HOST_A, SHARED_SECRET_HANDOVER_A)

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
