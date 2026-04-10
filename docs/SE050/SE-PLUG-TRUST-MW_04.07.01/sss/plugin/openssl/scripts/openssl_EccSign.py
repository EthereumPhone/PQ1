#
# Copyright 2019,2020,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#

"""

Validation of Sign Verify with OpenSSL engine using EC Keys

This example showcases sign using reference key, then verify using openssl and vice versa.

Precondition:
    - Inject keys using ``openssl_provisionEC.py``.

"""

import argparse

from openssl_util import *

log = logging.getLogger(__name__)


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
        for (key, value) in key_type_hash_map.items():
            if value == 'sha1':
                key_type_hash_map.pop(key)
                break

    # HASH = key_type_hash_map.get(args.key_type, "sha256")
    keys_dir = os.path.join(cur_dir, '..', 'keys', args.key_type)

    output_dir = cur_dir + os.sep + args.output_dirname
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    SIGN_KEY_REF_0 = keys_dir + os.sep + "ecc_key_kp_0_ref.pem"
    VERIFY_KEY_0 = keys_dir + os.sep + "ecc_key_kp_0.pem"
    SIGN_KEY_REF_1 = keys_dir + os.sep + "ecc_key_kp_1_ref.pem"
    VERIFY_KEY_1 = keys_dir + os.sep + "ecc_key_kp_1.pem"
    SIGN_KEY_REF_2 = keys_dir + os.sep + "ecc_key_kp_2_ref.pem"
    VERIFY_KEY_2 = keys_dir + os.sep + "ecc_key_kp_2.pem"
    SIGN_KEY_REF_3 = keys_dir + os.sep + "ecc_key_kp_3_ref.pem"
    VERIFY_KEY_3 = keys_dir + os.sep + "ecc_key_kp_3.pem"

    SIGN_KEY_0 = keys_dir + os.sep + "ecc_key_pub_0.pem"
    VERIFY_KEY_REF_0 = keys_dir + os.sep + "ecc_key_pub_0_ref.pem"
    SIGN_KEY_1 = keys_dir + os.sep + "ecc_key_pub_1.pem"
    VERIFY_KEY_REF_1 = keys_dir + os.sep + "ecc_key_pub_1_ref.pem"
    SIGN_KEY_2 = keys_dir + os.sep + "ecc_key_pub_2.pem"
    VERIFY_KEY_REF_2 = keys_dir + os.sep + "ecc_key_pub_2_ref.pem"

    ECC_KEY_KP_A = keys_dir + os.sep + "ecc_key_kp_A.pem"
    ECC_KEY_KP_PUBONLY_A = keys_dir + os.sep + "ecc_key_kp_pubonly_A.pem"

    SIGNATURE_0 = output_dir + os.sep + "signature_hash_0.bin"
    SIGNATURE_1 = output_dir + os.sep + "signature_hash_1.bin"
    SIGNATURE_2 = output_dir + os.sep + "signature_hash_2.bin"
    SIGNATURE_3 = output_dir + os.sep + "signature_hash_3.bin"
    SIGNATURE_V_0 = output_dir + os.sep + "signature_v_hash_0.bin"
    SIGNATURE_V_1 = output_dir + os.sep + "signature_v_hash_1.bin"
    SIGNATURE_V_2 = output_dir + os.sep + "signature_v_hash_2.bin"
    SIGNATURE_A_0 = output_dir + os.sep + "signature_a_hash_0.bin"
    TO_SIGN = cur_dir + os.sep + "readme.rst"

    for HASH in key_type_hash_map.values():
        log.info("###########################################################")
        log.info("Positive signing tests (hash=%s)" % HASH)

        log.info("###########################################################")
        log.info("Sign the file %s with SE %s" % (TO_SIGN, SIGN_KEY_REF_0))
        log.info("###########################################################")
        run("%s dgst -engine %s -%s -sign %s -out %s %s" %
            (openssl, openssl_engine, HASH, SIGN_KEY_REF_0, SIGNATURE_0, TO_SIGN))
        log.info("###########################################################")
        log.info("Now verify the signature with Host")
        log.info("###########################################################")
        run("%s dgst -%s -prverify %s -signature %s %s" % (openssl, HASH, VERIFY_KEY_0, SIGNATURE_0, TO_SIGN))
        log.info("###########################################################")

        log.info("###########################################################")
        log.info("Sign the file %s with SE %s" % (TO_SIGN, SIGN_KEY_REF_1))
        log.info("###########################################################")
        run("%s dgst -engine %s -%s -sign %s -out %s %s" %
            (openssl, openssl_engine, HASH, SIGN_KEY_REF_1, SIGNATURE_1, TO_SIGN))
        log.info("###########################################################")
        log.info("Now verify the signature with Host")
        log.info("###########################################################")
        run("%s dgst -%s -prverify %s -signature %s %s" % (openssl, HASH, VERIFY_KEY_1, SIGNATURE_1, TO_SIGN))
        log.info("###########################################################")

        log.info("###########################################################")
        log.info("Sign the file %s with SE %s" % (TO_SIGN, SIGN_KEY_REF_2))
        log.info("###########################################################")
        run("%s dgst -engine %s -%s -sign %s -out %s %s" %
            (openssl, openssl_engine, HASH, SIGN_KEY_REF_2, SIGNATURE_2, TO_SIGN))
        log.info("###########################################################")
        log.info("Now verify the signature with Host")
        log.info("###########################################################")
        run("%s dgst -%s -prverify %s -signature %s %s" % (openssl, HASH, VERIFY_KEY_2, SIGNATURE_2, TO_SIGN))
        log.info("###########################################################")

        log.info("###########################################################")
        log.info("Sign the file %s with SE %s" % (TO_SIGN, SIGN_KEY_REF_3))
        log.info("###########################################################")
        run("%s dgst -engine %s -%s -sign %s -out %s %s" %
            (openssl, openssl_engine, HASH, SIGN_KEY_REF_3, SIGNATURE_3, TO_SIGN))
        log.info("###########################################################")
        log.info("Now verify the signature with Host")
        log.info("###########################################################")
        run("%s dgst -%s -prverify %s -signature %s %s" % (openssl, HASH, VERIFY_KEY_3, SIGNATURE_3, TO_SIGN))
        log.info("###########################################################")

        log.info("###########################################################")
        log.info("Positive verification tests (hash=%s)" % HASH)

        log.info("###########################################################")
        log.info("Sign the file %s with Host" % (TO_SIGN,))
        run("%s dgst -%s -sign %s -out %s %s" % (openssl, HASH, SIGN_KEY_0, SIGNATURE_V_0, TO_SIGN))
        log.info("###########################################################")
        log.info("Now verify the signature with SE (%s)" % (VERIFY_KEY_REF_0,))
        run("%s dgst -engine %s -%s -prverify %s -signature %s %s" %
            (openssl, openssl_engine, HASH, VERIFY_KEY_REF_0, SIGNATURE_V_0, TO_SIGN))

        log.info("###########################################################")
        log.info("Sign the file %s with Host" % (TO_SIGN,))
        run("%s dgst -%s -sign %s -out %s %s" % (openssl, HASH, SIGN_KEY_1, SIGNATURE_V_1, TO_SIGN))
        log.info("###########################################################")
        log.info("Now verify the signature with SE (%s)" % (VERIFY_KEY_REF_1,))
        run("%s dgst -engine %s -%s -prverify %s -signature %s %s" %
            (openssl, openssl_engine, HASH, VERIFY_KEY_REF_1, SIGNATURE_V_1, TO_SIGN))

        log.info("###########################################################")
        log.info("Sign the file %s with Host" % (TO_SIGN,))
        run("%s dgst -%s -sign %s -out %s %s" % (openssl, HASH, SIGN_KEY_2, SIGNATURE_V_2, TO_SIGN))
        log.info("###########################################################")
        log.info("Now verify the signature with SE (%s)" % (VERIFY_KEY_REF_2,))
        run("%s dgst -engine %s -%s -prverify %s -signature %s %s" %
            (openssl, openssl_engine, HASH, VERIFY_KEY_REF_2, SIGNATURE_V_2, TO_SIGN))

        log.info("###########################################################")
        log.info("Negative verification tests")
        log.info("Verify a signature with SE with a verification key (%s)" % (VERIFY_KEY_REF_0,))
        log.info("that does not match signer (%s)" % (SIGN_KEY_2,))
        log.info("###########################################################")

        ignore_result = 0
        exp_return_code = 1
        run("%s dgst -engine %s -%s -prverify %s -signature %s %s" %
            (openssl, openssl_engine, HASH, VERIFY_KEY_REF_0, SIGNATURE_V_2, TO_SIGN), ignore_result, exp_return_code)

        log.info("###########################################################")
        log.info("Validate Key Handover (hash=%s)" % HASH)
        log.info("###########################################################")
        log.info("Validate Key Handover from Engine to OpenSSL SW implementation")

        log.info("Sign the file %s with Host" % (TO_SIGN,))
        log.info("###########################################################")
        run("%s dgst -engine %s -%s -sign %s -out %s %s" %
            (openssl, openssl_engine, HASH, ECC_KEY_KP_A, SIGNATURE_A_0, TO_SIGN,))

        log.info("Now verify the signature with SE (%s)" % (SIGNATURE_A_0,))
        log.info("###########################################################")
        run("%s dgst -engine %s -%s -prverify %s -signature %s %s" %
            (openssl, openssl_engine, HASH, ECC_KEY_KP_A, SIGNATURE_A_0, TO_SIGN))
        log.info("###########################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
