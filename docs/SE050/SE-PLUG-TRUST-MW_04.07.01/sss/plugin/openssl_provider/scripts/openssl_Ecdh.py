#
# Copyright 2022,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#

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

    KEYPAIR_0 = keys_dir + os.sep + "ecc_key_kp_0.pem"
    KEYPAIR_1 = keys_dir + os.sep + "ecc_key_kp_1.pem"
    KEYPAIR_2 = keys_dir + os.sep + "ecc_key_kp_2.pem"

    PUBKEY_0 = keys_dir + os.sep + "ecc_key_pub_pubonly_0.pem"
    PUBKEY_1 = keys_dir + os.sep + "ecc_key_pub_pubonly_1.pem"
    PUBKEY_2 = keys_dir + os.sep + "ecc_key_pub_pubonly_2.pem"

    REF_KEY_0 = "nxp:" + keys_dir + os.sep + "ecc_key_kp_0_ref.pem"
    REF_KEY_1 = "nxp:" + keys_dir + os.sep + "ecc_key_kp_1_ref.pem"
    REF_KEY_2 = "nxp:" + keys_dir + os.sep + "ecc_key_kp_2_ref.pem"
    REF_KEY_3 = "nxp:" + keys_dir + os.sep + "ecc_key_kp_3_ref.pem"

    SHARED_SECRET_HOST_0 = output_dir + os.sep + "ecdh_host_0.bin"
    SHARED_SECRET_provider_0 = output_dir + os.sep + "ecdh_provider_0.bin"
    SHARED_SECRET_HOST_1 = output_dir + os.sep + "ecdh_host_1.bin"
    SHARED_SECRET_provider_1 = output_dir + os.sep + "ecdh_provider_1.bin"
    SHARED_SECRET_HOST_2 = output_dir + os.sep + "ecdh_host_2.bin"
    SHARED_SECRET_provider_2 = output_dir + os.sep + "ecdh_provider_2.bin"

    log.info("############### ECDH by using key labels in Provider ####################\n")

    log.info("############## Do ECDH on host ###############")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" % (openssl_bin, KEYPAIR_0, PUBKEY_0, SHARED_SECRET_HOST_0))
    log.info("############## Do ECDH with provider (using key labels) ##########")
    run("%s pkeyutl -derive  --provider default --provider %s --provider default -inkey nxp:0x7DCCBB10 -peerkey %s -hexdump -out %s" %(openssl_bin, provider, PUBKEY_0, SHARED_SECRET_provider_0))
    compare(SHARED_SECRET_HOST_0, SHARED_SECRET_provider_0)
    log.info("#######################################################\n")

    log.info("############## Do ECDH on host ###############")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" % (openssl_bin,  KEYPAIR_1,  PUBKEY_1, SHARED_SECRET_HOST_1))
    log.info("############## Do ECDH with provider (using key labels) ##########")
    run("%s pkeyutl -derive  --provider default --provider %s --provider default -inkey nxp:0x7DCCBB11 -peerkey %s -hexdump -out %s" %(openssl_bin, provider, PUBKEY_1, SHARED_SECRET_provider_1))
    compare(SHARED_SECRET_HOST_0, SHARED_SECRET_provider_0)
    log.info("#######################################################\n")

    log.info("############## Do ECDH on host ###############")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" % (openssl_bin, KEYPAIR_2,  PUBKEY_2, SHARED_SECRET_HOST_2))
    log.info("############## Do ECDH with provider (using key labels) ##########")
    run("%s pkeyutl -derive  --provider default --provider %s --provider default -inkey nxp:0x7DCCBB12 -peerkey %s -hexdump -out %s" %(openssl_bin, provider, PUBKEY_2, SHARED_SECRET_provider_2))
    compare(SHARED_SECRET_HOST_0, SHARED_SECRET_provider_0)
    log.info("#######################################################\n")

    log.info("############### ECDH by passing refernce keys to Provider ####################\n")

    log.info("############## Do ECDH on host ###############")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" % (openssl_bin,  KEYPAIR_0,  PUBKEY_0, SHARED_SECRET_HOST_0))
    log.info("############## Do ECDH with provider (using reference keys) ##########")
    run("%s pkeyutl -derive  --provider default --provider %s --provider default -inkey %s -peerkey %s -hexdump -out %s" %(openssl_bin, provider, REF_KEY_0, PUBKEY_0, SHARED_SECRET_provider_0))
    compare(SHARED_SECRET_HOST_0, SHARED_SECRET_provider_0)
    log.info("#######################################################\n")

    log.info("############## Do ECDH on host ###############")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" % (openssl_bin, KEYPAIR_1, PUBKEY_1,SHARED_SECRET_HOST_1))
    log.info("############## Do ECDH with provider (using reference keys) ##########")
    run("%s pkeyutl -derive  --provider default --provider %s --provider default -inkey %s -peerkey %s -hexdump -out %s" %(openssl_bin, provider, REF_KEY_1, PUBKEY_1, SHARED_SECRET_provider_1))
    compare(SHARED_SECRET_HOST_0, SHARED_SECRET_provider_0)
    log.info("#######################################################\n")

    log.info("############## Do ECDH on host ###############")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" % (openssl_bin, KEYPAIR_2, PUBKEY_2, SHARED_SECRET_HOST_2))
    log.info("############## Do ECDH with provider (using reference keys) ##########")
    run("%s pkeyutl -derive  --provider default --provider %s --provider default -inkey %s -peerkey %s -hexdump -out %s" %(openssl_bin, provider, REF_KEY_2, PUBKEY_2, SHARED_SECRET_provider_2))
    compare(SHARED_SECRET_HOST_0, SHARED_SECRET_provider_0)
    log.info("#######################################################\n")



    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
