#
# Copyright 2022,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#

import argparse

from openssl_util import *

log = logging.getLogger(__name__)

example_text = '''

Example invocation::

    python %s --key_type rsa2048
    python %s --key_type rsa4096 --connection_data 127.0.0.1:8050

''' % (__file__, __file__,)


def parse_in_args():
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=example_text,
        formatter_class=argparse.RawTextHelpFormatter)
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    required.add_argument(
        '--key_type',
        default="",
        help='Supported key types =>  ``%s``' % ("``, ``".join(SUPPORTED_RSA_KEY_TYPES)),
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
    optional.add_argument(
        '--disable_refkey_tests',
        default="False",
        help='Disable reference key tests => eg. ``True``, ``False``. Default: ``False``')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return None

    args = parser.parse_args()

    if args.key_type not in SUPPORTED_RSA_KEY_TYPES:
        parser.print_help(sys.stderr)
        return None

    if args.disable_sha1 not in ["True", "False"]:
        parser.print_help(sys.stderr)
        return None

    if args.disable_refkey_tests not in ["True", "False"]:
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

    key_size = args.key_type.replace("rsa", "")

    keys_dir = os.path.join(cur_dir, '..', 'keys', args.key_type)
    if not os.path.exists(keys_dir):
        log.error("keys are not generated. Please run \"openssl_provisionRSA.py\" first.")
    tst_keys_dir=os.path.join(cur_dir,'..','tst_keys')

    output_dir = cur_dir + os.sep + args.output_dirname
    if not os.path.exists(output_dir):
        log.info(" %s Folder does not exist. Creating it.")
        os.mkdir(output_dir)
    sha_types = ["sha1", "sha224", "sha256", "sha384", "sha512"]
    TO_SIGN = cur_dir + os.sep + "input_data" + os.sep + "input_data_100_bytes.txt"
    TO_SIGN_32_Bytes=cur_dir + os.sep + "input_data" + os.sep + "input_data_32_bytes.txt"
    SIGNATURE_0 = output_dir + os.sep + "signature_hash_0.bin"
    rsa_key_pair = keys_dir + os.sep + "rsa_1_prv.pem"
    SIGNATURE_1=output_dir+os.sep+ "signature_hash_1.bin"
    rsa_pub_key  =  keys_dir+os.sep+"rsa_1_pub.pem"
    rsa_ref_key="nxp:"+keys_dir+os.sep+"rsa_ref_prv.pem"
    rsa_dummy_key_pub=tst_keys_dir+os.sep+"rsa_dummy_pub_1024"

    for sha_type in sha_types:
        log.info("################################################## \n")

        log.info("Sign using Provider (Using key labels) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.rsa=yes,?nxp_prov.keymgmt.rsa=yes\" --provider default --provider %s -inkey nxp:0x6DCCBB11 -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, TO_SIGN, SIGNATURE_0, sha_type))
        log.info("###################################################")
        log.info("Verify using host")
        run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin, rsa_pub_key, SIGNATURE_0, TO_SIGN, sha_type))
        log.info("####################################################\n")

        log.info("Signature using host")
        run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin, rsa_key_pair, TO_SIGN, SIGNATURE_1, sha_type))
        log.info("#####################################################")
        log.info("Verify using openssl provider (Using key labels)")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.rsa=yes,?nxp_prov.keymgmt.rsa=yes\" --provider default --provider %s -inkey nxp:0x6DCCBB11 -rawin -in %s -digest %s -verify -sigfile %s" % (openssl_bin, provider, TO_SIGN, sha_type, SIGNATURE_1))
        log.info("####################################################\n")

        if args.disable_refkey_tests == "False":
            log.info("Sign using Provider (Using reference keys) ")
            run("%s pkeyutl -propquery \"?nxp_prov.signature.rsa=yes,?nxp_prov.keymgmt.rsa=yes\" --provider default --provider %s -inkey %s -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, rsa_ref_key, TO_SIGN, SIGNATURE_0, sha_type))
            log.info("###################################################")
            log.info("Verify signature using host")
            run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin, rsa_pub_key, SIGNATURE_0, TO_SIGN, sha_type))
            log.info("####################################################\n")

            log.info("Signature using host")
            run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin, rsa_key_pair, TO_SIGN,SIGNATURE_0, sha_type))
            log.info("#####################################################")
            log.info("Verify using openssl provider (Using reference keys) ")
            run("%s pkeyutl -propquery \"?nxp_prov.signature.rsa=yes,?nxp_prov.keymgmt.rsa=yes\" --provider default --provider %s -inkey %s -rawin -in %s -digest %s -verify -sigfile %s" % (openssl_bin, provider, rsa_ref_key, TO_SIGN, sha_type, SIGNATURE_0))
            log.info("#######################################################\n")

    log.info("Sign using Provider (Using key labels) on hash data - 32 Bytes ")
    run("%s pkeyutl -propquery \"?nxp_prov.signature.rsa=yes,?nxp_prov.keymgmt.rsa=yes\" --provider default --provider %s -inkey nxp:0x6DCCBB11 -sign -in %s -out %s" % (openssl_bin, provider, TO_SIGN_32_Bytes, SIGNATURE_0))
    log.info("Verify on host (hash data - 32 Bytes) ")
    run("%s pkeyutl -inkey %s -verify -pubin -in %s -sigfile %s" % (openssl_bin, rsa_pub_key, TO_SIGN_32_Bytes, SIGNATURE_0))

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()
