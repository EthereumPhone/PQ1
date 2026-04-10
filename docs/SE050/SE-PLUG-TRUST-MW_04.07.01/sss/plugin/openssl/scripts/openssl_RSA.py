#
# Copyright 2019,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#


"""

Validation of OpenSSL Engine using RSA keys

This example showcases crypto operations and sign verify operations using RSA keys.

"""

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

    output_dir = cur_dir + os.sep + args.output_dirname
    if not os.path.exists(output_dir):
        log.info(" %s Folder does not exist. Creating it.")
        os.mkdir(output_dir)

    rsa_key_pair = keys_dir + os.sep + "rsa_" + key_size + "_1_prv.pem"
    rsa_ref_key_pair = keys_dir + os.sep + "rsa_" + key_size + "_ref_prv.pem"
    sha_types = ["-sha1", "-sha224", "-sha256", "-sha384", "-sha512"]
    input_data = cur_dir + os.sep + "inputData.txt"
    input_data_keysize = cur_dir + os.sep + "inputData_" + key_size + "bits.txt"
    input_data_sha = output_dir + os.sep + "inputData_sha256.txt"
    encrypt_data = output_dir + os.sep + "encrypt_data.txt"
    decrypt_data = output_dir + os.sep + "decrypt_data.txt"
    sign_data = output_dir + os.sep + "sign_data.txt"

    # Calculate SHA of input data - Used for sign/verify using pkeyutl
    for sha_type in sha_types:
        run("%s dgst %s -binary -out %s %s" % (openssl, sha_type, input_data_sha, input_data,))

    # USE SSS LAYER FOR CRYPTO OPERATIONS
    log.info(";")
    log.info(";")
    log.info(";")
    log.info("############ STARTING CRYPTO OPERATIONS USING SSS APIs ##################")
    log.info(";")
    log.info(";")
    log.info(";")
    log.info("### PUBLIC ENCRYPT USING SSS - PKCSV1.5")
    run("%s rsautl -engine %s -encrypt -inkey %s -out %s -in %s" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, input_data))
    log.info("### PRIVATE DECRYPT USING SSS - PKCSV1.5")
    run("%s rsautl -engine %s -decrypt -inkey %s -in %s -out %s" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, decrypt_data))
    compare(input_data, decrypt_data)

    log.info("### PUBLIC ENCRYPT USING SSS - OAEP")
    run("%s rsautl -engine %s -encrypt -inkey %s -out %s -in %s -oaep" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, input_data))
    log.info("### PRIVATE DECRYPT USING SSS - OAEP")
    run("%s rsautl -engine %s -decrypt -inkey %s -in %s -out %s -oaep" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, decrypt_data))
    compare(input_data, decrypt_data)

    # Expect to return error.
    log.info("### PUBLIC ENCRYPT USING SSS - SSL")
    run("%s rsautl -engine %s -encrypt -inkey %s -out %s -in %s -ssl" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, input_data), exp_retcode=1)
    log.info("### PRIVATE DECRYPT USING SSS - SSL")
    run("%s rsautl -engine %s -decrypt -inkey %s -in %s -out %s -ssl" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, decrypt_data), exp_retcode=1)

    log.info("### PUBLIC ENCRYPT USING SSS - No padding")
    run("%s rsautl -engine %s -encrypt -inkey %s -out %s -in %s -raw" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, input_data_keysize))
    log.info("### PRIVATE DECRYPT USING SSS - No padding")
    run("%s rsautl -engine %s -decrypt -inkey %s -in %s -out %s -raw" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, decrypt_data))
    compare(input_data_keysize, decrypt_data)

    for sha_type in sha_types:
        log.info("### SIGNING USING SSS - PKCSV1.5 %s" % sha_type)
        run("%s dgst -engine %s %s -sign %s -out %s %s" %
            (openssl, openssl_engine, sha_type, rsa_ref_key_pair, sign_data, input_data))
        log.info("### VERIFY USING SSS - PKCSV1.5 %s" % sha_type)
        run("%s dgst -engine %s %s -prverify %s -signature %s %s" %
            (openssl, openssl_engine, sha_type, rsa_ref_key_pair, sign_data, input_data))

    log.info("### RSAUTL SIGNING USING SSS - No padding")
    run("%s rsautl -engine %s -sign -inkey %s -out %s -in %s -raw" %
        (openssl, openssl_engine, rsa_ref_key_pair, sign_data, input_data_keysize))
    log.info("### RSAUTL VERIFY USING SSS - No padding")
    run("%s rsautl -engine %s -verify -inkey %s -out %s -in %s -raw" %
        (openssl, openssl_engine, rsa_ref_key_pair, decrypt_data, sign_data))
    compare(input_data_keysize, decrypt_data)

    # Expect to fail
    log.info("### RSAUTL SIGNING USING SSS - PKCSV1.5")
    run("%s rsautl -engine %s -sign -inkey %s -out %s -in %s" %
        (openssl, openssl_engine, rsa_ref_key_pair, sign_data, input_data_keysize), exp_retcode=1)
    log.info("### RSAUTL VERIFY USING SSS - PKCSV1.5")
    run("%s rsautl -engine %s -verify -inkey %s -out %s -in %s" %
        (openssl, openssl_engine, rsa_ref_key_pair, decrypt_data, sign_data), exp_retcode=1)

    # USE OPENSSL STACK FOR CRYPTO OPERATIONS
    log.info("############ STARTING CRYPTO OPERATIONS USING OPENSSL ##################")
    log.info(";")
    log.info(";")
    log.info(";")
    log.info("### PUBLIC ENCRYPT USING OPENSSL - PKCSV1.5")
    log.info(";")
    log.info(";")
    log.info(";")
    log.info("### PUBLIC ENCRYPT USING OPENSSL - PKCSV1.5")
    run("%s rsautl -encrypt -inkey %s -out %s -in %s" %
        (openssl, rsa_key_pair, encrypt_data, input_data))
    log.info("### PRIVATE DECRYPT USING OPENSSL - PKCSV1.5")
    run("%s rsautl -decrypt -inkey %s -in %s -out %s" %
        (openssl, rsa_key_pair, encrypt_data, decrypt_data))
    compare(input_data, decrypt_data)

    log.info("### PUBLIC ENCRYPT USING OPENSSL - OAEP")
    run("%s rsautl -encrypt -inkey %s -out %s -in %s  -oaep" %
        (openssl, rsa_key_pair, encrypt_data, input_data))
    log.info("### PRIVATE DECRYPT USING OPENSSL - OAEP")
    run("%s rsautl -decrypt -inkey %s -in %s -out %s -oaep" %
        (openssl, rsa_key_pair, encrypt_data, decrypt_data))
    compare(input_data, decrypt_data)

    log.info("### PUBLIC ENCRYPT USING OPENSSL - No padding")
    run("%s rsautl -encrypt -inkey %s -out %s -in %s -raw" %
        (openssl, rsa_key_pair, encrypt_data, input_data_keysize))
    log.info("### PRIVATE DECRYPT USING OPENSSL - No padding")
    run("%s rsautl -decrypt -inkey %s -in %s -out %s -raw" %
        (openssl, rsa_key_pair, encrypt_data, decrypt_data))
    compare(input_data_keysize, decrypt_data)

    for sha_type in sha_types:
        log.info("### SIGNING USING OPENSSL - PKCSV1.5 %s" % sha_type)
        run("%s dgst %s -sign %s -out %s %s" %
            (openssl, sha_type, rsa_key_pair, sign_data, input_data))
        log.info("### VERIFY USING OPENSSL - PKCSV1.5 %s" % sha_type)
        run("%s dgst %s -prverify %s -signature %s %s" %
            (openssl, sha_type, rsa_key_pair, sign_data, input_data))

    log.info("### RSAUTL SIGNING USING OPENSSL - No padding")
    run("%s rsautl -sign -inkey %s -out %s -in %s -raw" %
        (openssl, rsa_key_pair, sign_data, input_data_keysize))
    log.info("### RSAUTL VERIFY USING OPENSSL - No padding")
    run("%s rsautl -verify -inkey %s -out %s -in %s -raw" %
        (openssl, rsa_key_pair, decrypt_data, sign_data))
    compare(input_data_keysize, decrypt_data)

    # COUNTERPART TESTING FOT CRYPTO OPERATIONS
    log.info(";")
    log.info(";")
    log.info(";")
    log.info("############ STARTING COUNTERPART TESTING ##################")
    log.info(";")
    log.info(";")
    log.info(";")
    log.info("### PUBLIC ENCRYPT USING SSS - PKCSV1.5")
    run("%s rsautl -engine %s -encrypt -inkey %s -out %s -in %s" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, input_data))
    log.info("### PRIVATE DECRYPT USING OPENSSL - PKCSV1.5")
    run("%s rsautl -decrypt -inkey %s -in %s -out %s" %
        (openssl, rsa_key_pair, encrypt_data, decrypt_data))
    compare(input_data, decrypt_data)

    log.info("### PUBLIC ENCRYPT USING OPENSSL - PKCSV1.5")
    run("%s rsautl -encrypt -inkey %s -out %s -in %s" %
        (openssl, rsa_key_pair, encrypt_data, input_data))
    log.info("### PRIVATE DECRYPT USING SSS - PKCSV1.5")
    run("%s rsautl -engine %s -decrypt -inkey %s -in %s -out %s" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, decrypt_data))
    compare(input_data, decrypt_data)

    log.info("### PUBLIC ENCRYPT USING SSS - OAEP")
    run("%s rsautl -engine %s -encrypt -inkey %s -out %s -in %s  -oaep" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, input_data))
    log.info("### PRIVATE DECRYPT USING OPENSSL - OAEP")
    run("%s rsautl -decrypt -inkey %s -in %s -out %s -oaep" %
        (openssl, rsa_key_pair, encrypt_data, decrypt_data))
    compare(input_data, decrypt_data)

    log.info("### PUBLIC ENCRYPT USING OPENSSL - OAEP")
    run("%s rsautl -encrypt -inkey %s -out %s -in %s  -oaep" %
        (openssl, rsa_ref_key_pair, encrypt_data, input_data))
    log.info("### PRIVATE DECRYPT USING SSS - OAEP")
    run("%s rsautl -engine %s -decrypt -inkey %s -in %s -out %s -oaep" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, decrypt_data))
    compare(input_data, decrypt_data)

    log.info("### PUBLIC ENCRYPT USING SSS - No padding")
    run("%s rsautl -engine %s -encrypt -inkey %s -out %s -in %s  -raw" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, input_data_keysize))
    log.info("### PRIVATE DECRYPT USING OPENSSL - No padding")
    run("%s rsautl -decrypt -inkey %s -in %s -out %s -raw" %
        (openssl, rsa_key_pair, encrypt_data, decrypt_data))
    compare(input_data_keysize, decrypt_data)

    log.info("### PUBLIC ENCRYPT USING OPENSSL - No padding")
    run("%s rsautl -encrypt -inkey %s -out %s -in %s  -raw" %
        (openssl, rsa_ref_key_pair, encrypt_data, input_data_keysize))
    log.info("### PRIVATE DECRYPT USING SSS - No padding")
    run("%s rsautl -engine %s -decrypt -inkey %s -in %s -out %s -raw" %
        (openssl, openssl_engine, rsa_ref_key_pair, encrypt_data, decrypt_data))
    compare(input_data_keysize, decrypt_data)

    for sha_type in sha_types:
        log.info("### SIGNING USING SSS - PKCSV1.5 %s" % sha_type)
        run("%s dgst -engine %s %s -sign %s -out %s %s" %
            (openssl, openssl_engine, sha_type, rsa_ref_key_pair, sign_data, input_data))
        log.info("### VERIFY USING OPENSSL - PKCSV1.5 %s" % sha_type)
        run("%s dgst %s -prverify %s -signature %s %s" %
            (openssl, sha_type, rsa_key_pair, sign_data, input_data))

        log.info("### SIGNING USING OPENSSL - PKCSV1.5 %s" % sha_type)
        run("%s dgst %s -sign %s -out %s %s" %
            (openssl, sha_type, rsa_key_pair, sign_data, input_data))
        log.info("### VERIFY USING SSS - PKCSV1.5 %s" % sha_type)
        run("%s dgst -engine %s %s -prverify %s -signature %s %s" %
            (openssl, openssl_engine, sha_type, rsa_ref_key_pair, sign_data, input_data))

    log.info("### RSAUTL SIGNING USING SSS - No padding")
    run("%s rsautl -engine %s -sign -inkey %s -out %s -in %s -raw" %
        (openssl, openssl_engine, rsa_ref_key_pair, sign_data, input_data_keysize))
    log.info("### RSAUTL VERIFY USING OPENSSL - No padding")
    run("%s rsautl -verify -inkey %s -out %s -in %s -raw" %
        (openssl, rsa_key_pair, decrypt_data, sign_data))
    compare(input_data_keysize, decrypt_data)

    log.info("### RSAUTL SIGNING USING OPENSSL - No padding")
    run("%s rsautl -sign -inkey %s -out %s -in %s -raw" %
        (openssl, rsa_key_pair, sign_data, input_data_keysize))
    log.info("### RSAUTL VERIFY USING SSS - No padding")
    run("%s rsautl -engine %s -verify -inkey %s -out %s -in %s -raw" %
        (openssl, openssl_engine, rsa_ref_key_pair, decrypt_data, sign_data))
    compare(input_data_keysize, decrypt_data)


    # OPENSSL SOFTWARE FALLBACK TEST CASES
    log.info(";")
    log.info(";")
    log.info(";")
    log.info("############ OPENSSL SOFTWARE FALLBACK TEST CASES ##################")
    log.info(";")
    log.info(";")
    log.info(";")
    log.info("### PUBLIC ENCRYPT USING SSS - PKCSV1.5")
    run("%s rsautl -engine %s -encrypt -inkey %s -out %s -in %s" %
        (openssl, openssl_engine, rsa_key_pair, encrypt_data, input_data))
    log.info("### PRIVATE DECRYPT USING SSS - PKCSV1.5")
    run("%s rsautl -engine %s -decrypt -inkey %s -in %s -out %s" %
        (openssl, openssl_engine, rsa_key_pair, encrypt_data, decrypt_data))
    compare(input_data, decrypt_data)

    log.info("### PUBLIC ENCRYPT USING SSS - OAEP")
    run("%s rsautl -engine %s -encrypt -inkey %s -out %s -in %s -oaep" %
        (openssl, openssl_engine, rsa_key_pair, encrypt_data, input_data))
    log.info("### PRIVATE DECRYPT USING SSS - OAEP")
    run("%s rsautl -engine %s -decrypt -inkey %s -in %s -out %s -oaep" %
        (openssl, openssl_engine, rsa_key_pair, encrypt_data, decrypt_data))
    compare(input_data, decrypt_data)

    log.info("### PUBLIC ENCRYPT USING SSS - No padding")
    run("%s rsautl -engine %s -encrypt -inkey %s -out %s -in %s -raw" %
        (openssl, openssl_engine, rsa_key_pair, encrypt_data, input_data_keysize))
    log.info("### PRIVATE DECRYPT USING SSS - No padding")
    run("%s rsautl -engine %s -decrypt -inkey %s -in %s -out %s -raw" %
        (openssl, openssl_engine, rsa_key_pair, encrypt_data, decrypt_data))
    compare(input_data_keysize, decrypt_data)

    for sha_type in sha_types:
        log.info("### SIGNING USING SSS - PKCSV1.5 %s" % sha_type)
        run("%s dgst -engine %s %s -sign %s -out %s %s" %
            (openssl, openssl_engine, sha_type, rsa_key_pair, sign_data, input_data))
        log.info("### VERIFY USING SSS - PKCSV1.5 %s" % sha_type)
        run("%s dgst -engine %s %s -prverify %s -signature %s %s" %
            (openssl, openssl_engine, sha_type, rsa_key_pair, sign_data, input_data))

    log.info("### RSAUTL SIGNING USING SSS - No padding")
    run("%s rsautl -engine %s -sign -inkey %s -out %s -in %s -raw" %
        (openssl, openssl_engine, rsa_key_pair, sign_data, input_data_keysize))
    log.info("### RSAUTL VERIFY USING SSS - No padding")
    run("%s rsautl -engine %s -verify -inkey %s -out %s -in %s -raw" %
        (openssl, openssl_engine, rsa_key_pair, decrypt_data, sign_data))
    compare(input_data_keysize, decrypt_data)

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    main()
