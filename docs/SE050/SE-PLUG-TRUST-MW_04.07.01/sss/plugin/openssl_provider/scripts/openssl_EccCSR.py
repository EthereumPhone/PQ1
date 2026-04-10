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

    output_dir = cur_dir + os.sep + "output"
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    keys_dir = cur_dir + os.sep + "output" + os.sep + key_type
    if not os.path.exists(keys_dir):
        os.mkdir(keys_dir)

    rootca_key = cur_dir + os.sep + "ca_keys_for_csr" + os.sep + "rootca_key.pem"
    rootca_cer = cur_dir + os.sep + "ca_keys_for_csr" + os.sep + "rootca.cer"
    ref_ec_key = "nxp:" + cur_dir + os.sep + ".." + os.sep + "keys" + os.sep + key_type + os.sep + "ecc_key_kp_0_ref.pem"
    output_csr = cur_dir + os.sep + "output" + os.sep + key_type + os.sep + "ecc_key_kp_0.csr"
    output_crt = cur_dir + os.sep + "output" + os.sep + key_type + os.sep + "ecc_key_kp_0.crt"

    subject = "-subj \"/C=11/ST=111/L=111/O=NXP/OU=NXP/CN=example.com\""

    run("%s req -new --provider default --provider %s -key %s -out %s %s -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt=yes\" " %(openssl_bin, provider, ref_ec_key, output_csr, subject))
    run("%s x509 -req --provider default --provider %s -in %s -CAcreateserial -out %s -days 5000 -CA %s -CAkey %s -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt=yes\" " %(openssl_bin, provider, output_csr, output_crt, rootca_cer, rootca_key))


    run("%s x509 -in %s -text -noout" %(openssl_bin, output_crt))


    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
