#
# Copyright 2022,2025 NXP
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
        help='Supported key types => ``%s``' % ("``,  ``".join(SUPPORTED_EC_KEY_TYPES)),
        required=True)
    optional.add_argument(
        '--connection_data',
        default="none",
        help='Parameter to connect to SE => eg. ``COM3``,  ``127.0.0.1:8050``,  ``none``. Default: ``none``')
    optional.add_argument(
        '--disable_sha1',
        default="False",
        help='Parameter to disable SHA1 => eg. ``True``,  ``False``. Default: ``False``')
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

    if args.disable_sha1 not in ["True",  "False"]:
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
    key_type_hash_map = {
        "prime192v1": "sha1",
        "secp224r1": "sha224",
        "prime256v1": "sha256",
        "secp384r1": "sha384",
        "secp521r1": "sha512",
    }

    args = parse_in_args()
    if args is None:
        return

    if args.disable_sha1 == "True":
        for (key,  value) in key_type_hash_map.items():
            if value == 'sha1':
                key_type_hash_map.pop(key)
                break

    output_dir = cur_dir + os.sep + args.output_dirname
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    keys_dir = os.path.join(cur_dir,  '..',  'keys',  args.key_type)
    SIGNATURE_0 = output_dir + os.sep + "signature_hash_0.bin"
    SIGNATURE_1 = output_dir + os.sep + "signature_hash_1.bin"
    SIGNATURE_2 = output_dir + os.sep + "signature_hash_2.bin"
    SIGNATURE_3 = output_dir + os.sep + "signature_hash_3.bin"

    VERIFY_KEY_0 = keys_dir + os.sep + "ecc_key_kp_pubonly_0.pem"
    VERIFY_KEY_1 = keys_dir + os.sep + "ecc_key_kp_pubonly_1.pem"
    VERIFY_KEY_2 = keys_dir + os.sep + "ecc_key_kp_pubonly_2.pem"
    VERIFY_KEY_3 = keys_dir + os.sep + "ecc_key_kp_pubonly_3.pem"

    SIGNTURE_KEY_0=keys_dir+os.sep+"ecc_key_kp_0.pem"
    SIGNTURE_KEY_1=keys_dir+os.sep+"ecc_key_kp_1.pem"
    SIGNTURE_KEY_2=keys_dir+os.sep+"ecc_key_kp_2.pem"
    SIGNTURE_KEY_3=keys_dir+os.sep+"ecc_key_kp_3.pem"

    SIGN_KEY_REF_0 = "nxp:" + keys_dir + os.sep + "ecc_key_kp_0_ref.pem"
    SIGN_KEY_REF_1 = "nxp:" + keys_dir + os.sep + "ecc_key_kp_1_ref.pem"
    SIGN_KEY_REF_2 = "nxp:" + keys_dir + os.sep + "ecc_key_kp_2_ref.pem"
    SIGN_KEY_REF_3 = "nxp:" + keys_dir + os.sep + "ecc_key_kp_3_ref.pem"

    TO_SIGN = cur_dir + os.sep + "input_data" + os.sep + "input_data_100_bytes.txt"
    TO_SIGN_1024_Bytes=cur_dir + os.sep + "input_data" + os.sep + "input_data_1024_bytes.txt"
    TO_SIGN_2048_Bytes=cur_dir + os.sep + "input_data" + os.sep + "input_data_2048_bytes.txt"
    TO_SIGN_32_Bytes=cur_dir + os.sep + "input_data" + os.sep + "input_data_32_bytes.txt"

    for sha_type in key_type_hash_map.values():
        log.info("\n######### Positive Signature test cases using key labels ##########")
        log.info("################################################## \n")

        log.info("Sign using Provider (Using key labels) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7dccbb10 -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, TO_SIGN, SIGNATURE_0, sha_type))
        log.info("###################################################")
        log.info("Verify signature using host  ")
        run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin,VERIFY_KEY_0,SIGNATURE_0,TO_SIGN,sha_type))
        log.info("#################################################### \n")

        log.info("Sign using Provider (Using key labels)  (1024 Bytes data) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7dccbb10 -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, TO_SIGN_1024_Bytes, SIGNATURE_0, sha_type))
        log.info("###################################################")
        log.info("Verify signature using host  ")
        run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin,VERIFY_KEY_0,SIGNATURE_0,TO_SIGN_1024_Bytes,sha_type))
        log.info("#################################################### \n")

        log.info("Sign using Provider (Using key labels) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7DCCBB11 -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, TO_SIGN, SIGNATURE_1, sha_type))
        log.info("###################################################")
        log.info("Verify signature using host")
        run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin,VERIFY_KEY_1,SIGNATURE_1,TO_SIGN,sha_type))
        log.info("####################################################\n")

        log.info("Sign using Provider (Using key labels) (2048 Bytes data)")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7DCCBB11 -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, TO_SIGN_2048_Bytes, SIGNATURE_1, sha_type))
        log.info("###################################################")
        log.info("Verify signature using host")
        run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin,VERIFY_KEY_1,SIGNATURE_1,TO_SIGN_2048_Bytes,sha_type))
        log.info("####################################################\n")

        log.info("Sign using Provider (Using key labels) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7DCCBB12 -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, TO_SIGN, SIGNATURE_2, sha_type))
        log.info("###################################################")
        log.info("Verify signature using host")
        run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin,VERIFY_KEY_2,SIGNATURE_2,TO_SIGN,sha_type))
        log.info("####################################################\n")

        log.info("Sign using Provider (Using key labels) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7DCCBB13 -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, TO_SIGN, SIGNATURE_3, sha_type))
        log.info("###################################################")
        log.info("Verify signature using host")
        run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin,VERIFY_KEY_3,SIGNATURE_3,TO_SIGN,sha_type))
        run("%s dgst -%s -verify %s -signature %s %s"%(openssl_bin, sha_type, VERIFY_KEY_3, SIGNATURE_3, TO_SIGN))
        log.info("####################################################\n")



        log.info("\n\n####### Positive verification testcases using key labels ##############")
        log.info("#######################################################\n")
        log.info("Signature using host")
        run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin,SIGNTURE_KEY_0,TO_SIGN,SIGNATURE_0,sha_type))
        log.info("#####################################################")
        log.info("Verify using openssl provider (Using key labels) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7dccbb10 -rawin -in %s -digest %s -verify -sigfile %s" % (openssl_bin, provider, TO_SIGN, sha_type, SIGNATURE_0))
        log.info("#####################################################\n")

        log.info("Signature using host (1024 Bytes data) ")
        run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin,SIGNTURE_KEY_0,TO_SIGN_1024_Bytes,SIGNATURE_0,sha_type))
        log.info("#####################################################")
        log.info("Verify using openssl provider (Using key labels) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7dccbb10 -rawin -in %s -digest %s -verify -sigfile %s" % (openssl_bin, provider, TO_SIGN_1024_Bytes, sha_type, SIGNATURE_0))
        log.info("#####################################################\n")

        log.info("Signature using host")
        run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin,SIGNTURE_KEY_1,TO_SIGN,SIGNATURE_1,sha_type))
        log.info("#####################################################")
        log.info("Verify using openssl provider (Using key labels) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7DCCBB11 -rawin -in %s  -digest %s -verify -sigfile %s" % (openssl_bin, provider, TO_SIGN, sha_type, SIGNATURE_1))
        log.info("#####################################################\n")

        log.info("Signature using host (2048 Bytes data)")
        run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin,SIGNTURE_KEY_1,TO_SIGN_2048_Bytes,SIGNATURE_1,sha_type))
        log.info("#####################################################")
        log.info("Verify using openssl provider (Using key labels) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7DCCBB11 -rawin -in %s  -digest %s -verify -sigfile %s" % (openssl_bin, provider, TO_SIGN_2048_Bytes, sha_type, SIGNATURE_1))
        log.info("#####################################################\n")

        log.info("Signature using host")
        run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin,SIGNTURE_KEY_2,TO_SIGN,SIGNATURE_2,sha_type))
        log.info("#####################################################")
        log.info("Verify using openssl provider (Using key labels) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7DCCBB12 -rawin -in %s -digest %s -verify -sigfile %s" % (openssl_bin, provider, TO_SIGN, sha_type, SIGNATURE_2))
        log.info("#####################################################\n")

        log.info("Signature using host")
        run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin,SIGNTURE_KEY_3,TO_SIGN,SIGNATURE_3,sha_type))
        log.info("#####################################################")
        log.info("Verify using openssl provider (Using key labels) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7DCCBB13 -rawin -in %s -digest %s -verify -sigfile %s" % (openssl_bin, provider, TO_SIGN, sha_type, SIGNATURE_3))
        log.info("#####################################################\n")


        log.info("######### Positive Signature test cases by passing reference keys ##########")
        log.info("##################################################\n")

        log.info("Sign using Provider (Using reference keys) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey %s -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, SIGN_KEY_REF_0, TO_SIGN, SIGNATURE_0, sha_type))
        log.info("###################################################")
        log.info("Verify signature using host")
        run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin,VERIFY_KEY_0,SIGNATURE_0,TO_SIGN,sha_type))
        log.info("####################################################\n")

        log.info("Sign using Provider (Using reference keys) (1024 Bytes data)")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey %s -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, SIGN_KEY_REF_0, TO_SIGN_1024_Bytes, SIGNATURE_0, sha_type))
        log.info("###################################################")
        log.info("Verify signature using host")
        run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin,VERIFY_KEY_0,SIGNATURE_0,TO_SIGN_1024_Bytes,sha_type))
        log.info("####################################################\n")

        log.info("Sign using Provider (Using reference keys) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey %s -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, SIGN_KEY_REF_1, TO_SIGN, SIGNATURE_1, sha_type))
        log.info("###################################################")
        log.info("Verify signature using host")
        run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin,VERIFY_KEY_1,SIGNATURE_1,TO_SIGN,sha_type))
        log.info("####################################################\n")

        log.info("Sign using Provider (Using reference keys) (2048 Bytes data)")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey %s -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, SIGN_KEY_REF_1, TO_SIGN_2048_Bytes, SIGNATURE_1, sha_type))
        log.info("###################################################")
        log.info("Verify signature using host")
        run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin,VERIFY_KEY_1,SIGNATURE_1,TO_SIGN_2048_Bytes,sha_type))
        log.info("####################################################\n")

        log.info("Sign using Provider (Using reference keys) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey %s -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, SIGN_KEY_REF_2, TO_SIGN, SIGNATURE_2, sha_type))
        log.info("###################################################")
        log.info("Verify signature using host")
        run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin,VERIFY_KEY_2,SIGNATURE_2,TO_SIGN,sha_type))
        log.info("####################################################\n")

        log.info("Sign using Provider (Using reference keys) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey %s -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, SIGN_KEY_REF_3, TO_SIGN, SIGNATURE_3, sha_type))
        log.info("###################################################")
        log.info("Verify signature using host")
        run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin,VERIFY_KEY_3,SIGNATURE_3,TO_SIGN,sha_type))
        log.info("####################################################\n")


        log.info("####### Positive verification testcases by passing reference keys ##############")
        log.info("#######################################################\n")

        log.info("Signature using host")
        run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin,SIGNTURE_KEY_0,TO_SIGN,SIGNATURE_0,sha_type))
        log.info("#####################################################")
        log.info("Verify using openssl provider (Using reference keys) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey %s -rawin -in %s -digest %s -verify -sigfile %s" % (openssl_bin, provider, SIGN_KEY_REF_0, TO_SIGN, sha_type, SIGNATURE_0))
        log.info("#######################################################\n")

        log.info("Signature using host")
        run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin,SIGNTURE_KEY_0,TO_SIGN_1024_Bytes,SIGNATURE_0,sha_type))
        log.info("#####################################################")
        log.info("Verify using openssl provider (Using reference keys) (1024 Bytes data)")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey %s -rawin -in %s -digest %s -verify -sigfile %s" % (openssl_bin, provider, SIGN_KEY_REF_0, TO_SIGN_1024_Bytes, sha_type, SIGNATURE_0))
        log.info("#######################################################\n")

        log.info("Signature using host")
        run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin,SIGNTURE_KEY_1,TO_SIGN,SIGNATURE_1,sha_type))
        log.info("#####################################################")
        log.info("Verify using openssl provider (Using reference keys) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey %s -rawin -in %s -digest %s -verify -sigfile %s" % (openssl_bin, provider, SIGN_KEY_REF_1, TO_SIGN, sha_type, SIGNATURE_1))
        log.info("#######################################################\n")

        log.info("Signature using host")
        run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin,SIGNTURE_KEY_1,TO_SIGN_2048_Bytes,SIGNATURE_1,sha_type))
        log.info("#####################################################")
        log.info("Verify using openssl provider (Using reference keys) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey %s -rawin -in %s -digest %s -verify -sigfile %s" % (openssl_bin, provider, SIGN_KEY_REF_1, TO_SIGN_2048_Bytes, sha_type, SIGNATURE_1))
        log.info("#######################################################\n")

        log.info("Signature using host")
        run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin,SIGNTURE_KEY_2,TO_SIGN,SIGNATURE_2,sha_type))
        log.info("#####################################################")
        log.info("Verify using openssl provider (Using reference keys) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey %s -rawin -in %s -digest %s -verify -sigfile %s" % (openssl_bin, provider, SIGN_KEY_REF_2, TO_SIGN, sha_type, SIGNATURE_2))
        log.info("#######################################################\n")

        log.info("Signature using host")
        run("%s pkeyutl -sign -inkey %s -in %s -out %s -rawin -digest %s"%(openssl_bin,SIGNTURE_KEY_3,TO_SIGN,SIGNATURE_3,sha_type))
        log.info("#####################################################")
        log.info("Verify using openssl provider (Using reference keys) ")
        run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey %s -rawin -in %s -digest %s -verify -sigfile %s" % (openssl_bin, provider, SIGN_KEY_REF_3, TO_SIGN, sha_type, SIGNATURE_3))
        log.info("#######################################################\n")

    log.info("Sign using Provider (Using key labels) on hash data - 32 Bytes ")
    run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7dccbb10 -sign -in %s -out %s" % (openssl_bin, provider, TO_SIGN_32_Bytes, SIGNATURE_0))
    log.info("###################################################")
    log.info("Verify signature using host  ")
    run("%s pkeyutl -inkey %s -pubin -verify -in %s -sigfile %s" % (openssl_bin, VERIFY_KEY_0, TO_SIGN_32_Bytes, SIGNATURE_0))
    log.info("#################################################### \n")

    log.info("Sign using host on hash data - 32 Bytes ")
    run("%s pkeyutl -inkey %s -sign -in %s -out %s" % (openssl_bin, SIGNTURE_KEY_1, TO_SIGN_32_Bytes, SIGNATURE_1))
    log.info("###################################################")
    log.info("Verify using provider (Using key label) ")
    run("%s pkeyutl -propquery \"?nxp_prov.signature.ecdsa=yes,?nxp_prov.keymgmt.ec=yes\" --provider default --provider %s -inkey nxp:0x7DCCBB11 -verify -in %s -sigfile %s" % (openssl_bin, provider, TO_SIGN_32_Bytes, SIGNATURE_1))
    log.info("#################################################### \n")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
