#
# Copyright 2023,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
import argparse

from openssl_util import *

log = logging.getLogger(__name__)

example_text = '''

Example invocation::

    python %s --key_type prime256v1
    python %s --key_type secp160k1 --connection_data 127.0.0.1:8050

''' % (__file__,  __file__, )

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
    key_type = sys.argv[2]
    key_type_keyid = key_type+":0xEF000002"
    output_dir = cur_dir + os.sep + "output"
    output_keys_dir = cur_dir + os.sep + "output" + os.sep + key_type

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    if not os.path.exists(output_keys_dir):
        os.mkdir(output_keys_dir)

    ref_ec_key_default = output_keys_dir + os.sep + "ecc_ref_key_default.pem"
    ref_ec_key_0xEF000002 = output_keys_dir + os.sep + "ecc_ref_key_0xEF000002.pem"

    log.info("\n########### Generate EC Keys Using Openssl Provider at default location ###############")
    run("%s ecparam --provider %s --provider default -name %s -genkey -out %s" %(openssl_bin, provider, key_type, ref_ec_key_default))

    log.info("\n########### Generate EC Keys Using Openssl Provider at 0xEF000002 location ###############")
    run("%s ecparam --provider %s --provider default -name %s -genkey -out %s" %(openssl_bin, provider, key_type_keyid, ref_ec_key_0xEF000002))

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
