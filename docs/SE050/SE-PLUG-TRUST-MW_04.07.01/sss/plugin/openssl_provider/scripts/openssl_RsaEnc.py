#
# Copyright 2024,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
import argparse

from openssl_util import *

log = logging.getLogger(__name__)

example_text = '''

Example invocation::

    python %s --key_type rsa1024
    python %s --key_type rsa2048 --connection_data 127.0.0.1:8050

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
        help='Supported key types => ``%s``' % ("``, ``".join(SUPPORTED_RSA_KEY_TYPES)),
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

    if args.key_type not in SUPPORTED_RSA_KEY_TYPES:
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

    keys_dir = os.path.join(cur_dir, '..', 'keys', args.key_type)
    if not os.path.exists(keys_dir):
        log.error("keys are not generated. Please run \"openssl_provisionRSA.py\" first.")

    output_dir = cur_dir + os.sep + "output"
    output_keys_dir = cur_dir + os.sep + "output" + os.sep + key_type

    if key_type == "rsa1024":
        key_type_bits = "1024"
    elif key_type == "rsa2048":
        key_type_bits = "2048"
    elif key_type == "rsa3072":
        key_type_bits = "3072"
    elif key_type == "rsa4096":
        key_type_bits = "4096"
    else:
        key_type_bits = "0"

    key_type_bits_keyid = key_type_bits+":0xEF000003"

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    if not os.path.exists(output_keys_dir):
        os.mkdir(output_keys_dir)

    rsa_pub_key  = keys_dir+os.sep+"rsa_1_pub.pem"
    rsa_priv_key = keys_dir+os.sep+"rsa_1_prv.pem"
    rsa_ref_priv = "nxp:" + keys_dir+os.sep+"rsa_ref_prv.pem"
    TO_ENCRYPT_0 = cur_dir + os.sep + "input_data" + os.sep + "input_data_32_bytes.txt"
    TO_ENCRYPT_1 = cur_dir + os.sep + "input_data" + os.sep + "input_data_100_bytes.txt"
    ENCRYPT_0 = output_dir + os.sep + "RSA_ENCRYPT_0.bin"
    DECRYPT_0 = output_dir + os.sep + "RSA_DECRYPT_0.bin"
    ENCRYPT_1 = output_dir + os.sep + "RSA_ENCRYPT_1.bin"
    DECRYPT_1 = output_dir + os.sep + "RSA_DECRYPT_1.bin"
    ENCRYPT_2 = output_dir + os.sep + "RSA_ENCRYPT_2.bin"
    DECRYPT_2 = output_dir + os.sep + "RSA_DECRYPT_2.bin"
    ENCRYPT_3 = output_dir + os.sep + "RSA_ENCRYPT_3.bin"
    DECRYPT_3 = output_dir + os.sep + "RSA_DECRYPT_3.bin"
    ENCRYPT_4 = output_dir + os.sep + "RSA_ENCRYPT_4.bin"
    DECRYPT_4 = output_dir + os.sep + "RSA_DECRYPT_4.bin"
    ENCRYPT_5 = output_dir + os.sep + "RSA_ENCRYPT_5.bin"
    DECRYPT_5 = output_dir + os.sep + "RSA_DECRYPT_5.bin"

    log.info("\n########### Encrypt data using Provider (Using key labels) ###############")
    run("%s pkeyutl -propquery \"?nxp_prov.asym_cipher=yes,?nxp_prov.keymgmt.rsa=yes\" --provider default --provider %s -encrypt -inkey nxp:0x6DCCBB11 -in %s -out %s -pkeyopt rsa_padding_mode:oaep" %(openssl_bin, provider,TO_ENCRYPT_0,ENCRYPT_0))

    log.info("\n########### Decrypt Data using Host ###############")
    run("%s pkeyutl -decrypt -inkey %s -in %s -out %s -pkeyopt rsa_padding_mode:oaep" %(openssl_bin,rsa_priv_key,ENCRYPT_0,DECRYPT_0))

    log.info("\n########### Encrypt data using Host ###############")
    run("%s pkeyutl -encrypt -inkey %s -in %s -out %s -pkeyopt rsa_padding_mode:pkcs1" %(openssl_bin, rsa_priv_key,TO_ENCRYPT_1,ENCRYPT_1))

    log.info("\n########### Decrypt Data using Provider (Using key labels) ###############")
    run("%s pkeyutl -propquery \"?nxp_prov.asym_cipher=yes,?nxp_prov.keymgmt.rsa=yes\" --provider default --provider %s -decrypt -inkey nxp:0x6DCCBB11 -in %s -out %s -pkeyopt rsa_padding_mode:pkcs1" %(openssl_bin, provider,ENCRYPT_1,DECRYPT_1))

    log.info("\n########### Encrypt data using Provider (Using reference keys)  ###############")
    run("%s pkeyutl -propquery \"?nxp_prov.asym_cipher=yes,?nxp_prov.keymgmt.rsa=yes\" --provider default --provider %s -encrypt -inkey %s -in %s -out %s -pkeyopt rsa_padding_mode:oaep" %(openssl_bin, provider,rsa_ref_priv,TO_ENCRYPT_0,ENCRYPT_2))

    log.info("\n########### Decrypt Data using Host ###############")
    run("%s pkeyutl -decrypt -inkey %s -in %s -out %s -pkeyopt rsa_padding_mode:oaep" %(openssl_bin, rsa_priv_key,ENCRYPT_2,DECRYPT_2))

    log.info("\n########### Encrypt data using Host ###############")
    run("%s pkeyutl -encrypt -inkey %s -in %s -out %s -pkeyopt rsa_padding_mode:oaep" %(openssl_bin, rsa_priv_key,TO_ENCRYPT_0,ENCRYPT_3))

    log.info("\n########### Decrypt Data using Provider (Using reference keys) ###############")
    run("%s pkeyutl -propquery \"?nxp_prov.asym_cipher=yes,?nxp_prov.keymgmt.rsa=yes\" --provider default --provider %s -decrypt -inkey %s -in %s -out %s -pkeyopt rsa_padding_mode:oaep" %(openssl_bin, provider,rsa_ref_priv,ENCRYPT_3,DECRYPT_3))

    log.info("\n########### Encrypt data using Provider host implementation ###############")
    run("%s pkeyutl -propquery \"?nxp_prov.asym_cipher=yes,?nxp_prov.keymgmt.rsa=yes\" --provider default --provider %s -encrypt -inkey %s -in %s -out %s -pkeyopt rsa_padding_mode:oaep" %(openssl_bin, provider,rsa_priv_key,TO_ENCRYPT_0,ENCRYPT_4))

    log.info("\n########### Decrypt data using host ###############")
    run("%s pkeyutl -decrypt -inkey %s -in %s -out %s -pkeyopt rsa_padding_mode:oaep" %(openssl_bin,rsa_priv_key,ENCRYPT_4,DECRYPT_4))

    log.info("\n########### Encrypt data using Host ###############")
    run("%s pkeyutl -encrypt -pubin -inkey %s -in %s -out %s -pkeyopt rsa_padding_mode:pkcs1" %(openssl_bin, rsa_pub_key,TO_ENCRYPT_1,ENCRYPT_5))

    log.info("\n########### Decrypt data using Provider host implementation ###############")
    run("%s pkeyutl -propquery \"?nxp_prov.asym_cipher=yes,?nxp_prov.keymgmt.rsa=yes\" --provider default --provider %s -decrypt -inkey %s -in %s -out %s -pkeyopt rsa_padding_mode:pkcs1" %(openssl_bin, provider,rsa_priv_key,ENCRYPT_5,DECRYPT_5))

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()

