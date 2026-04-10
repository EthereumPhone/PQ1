#
# Copyright 2023-2024 NXP
# SPDX-License-Identifier: Apache-2.0
#
"""

Utility functions for PKCS11 testing scripts

"""
import argparse
import logging
import os
import subprocess
import sys
import traceback
import binascii
import sys

logging.basicConfig(format='%(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)

example_text = '''
Example invocation::
    python3 %s --key_type EC:prime256v1
    python3 %s --key_type rsa:1024
''' % (__file__,__file__)

example_ec_text = '''
Example invocation::
    python3 %s --key_type EC:prime256v1
''' % (__file__)

example_rsa_text = '''
Example invocation::
    python3 %s --key_type rsa:1024
''' % (__file__)

cur_dir = os.path.abspath(os.path.dirname(__file__))

# Update the library name here
library_name="libsss_pkcs11.so"
module_path=os.path.join('..','bin',library_name)
pkcs11_tool="pkcs11-tool"
input_dir = cur_dir + os.sep + "input_data" + os.sep
output_dir = cur_dir + os.sep + "output" + os.sep
key_dir = cur_dir + os.sep + "keys" + os.sep
OPENSC = "opensc-tool"

SUPPORTED_KEY_TYPES = [
    "EC:prime192v1",
    "EC:prime256v1",
    "EC:secp224r1",
    "EC:secp521r1",
    "EC:secp192k1",
    "EC:secp256k1",
    "EC:secp384r1",
    "EC:brainpoolP192r1",
    "EC:brainpoolP256r1",
    "EC:brainpoolP224r1",
    "EC:brainpoolP320r1",
    "EC:brainpoolP384r1",
    "EC:brainpoolP512r1",
    "rsa:1024",
    "rsa:2048",
    "rsa:3072",
    "rsa:4096"
]

SUPPORTED_EC_KEY_TYPES = [
    "EC:prime192v1",
    "EC:prime256v1",
    "EC:secp192k1",
    "EC:secp256k1",
    "EC:secp224r1",
    "EC:secp521r1",
    "EC:secp384r1",
    "EC:brainpoolP192r1",
    "EC:brainpoolP256r1",
    "EC:brainpoolP224r1",
    "EC:brainpoolP320r1",
    "EC:brainpoolP384r1",
    "EC:brainpoolP512r1"
]

SUPPORTED_RSA_KEY_TYPES = [
    "rsa:1024",
    "rsa:2048",
    "rsa:3072",
    "rsa:4096"
]

def run(cmd_str, ignore_result=0, exp_retcode=0):
    log.info("Running command:")
    log.info("%s" % (cmd_str,))
    pipes = subprocess.Popen(
        cmd_str,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )
    std_out, std_err = pipes.communicate()
    std_out = std_out.strip()
    std_err = std_err.strip()
    log.info("%s" % std_out.decode())
    if not ignore_result:
        if pipes.returncode != exp_retcode:
            log.error("ERROR: Return code: %s, Expected return code: %s " % (pipes.returncode, exp_retcode))
            log.error("ERROR: std_err: %s" % std_err.decode())
        else:
            log.info("Command execution was successful.")
        assert pipes.returncode == exp_retcode

def parse_in_args():
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=example_text,
        formatter_class=argparse.RawTextHelpFormatter)
    required = parser.add_argument_group('required arguments')
    required.add_argument(
        '--key_type',
        default="",
        help='Supported key types => ``%s``' % ("``, ``".join(SUPPORTED_KEY_TYPES)),
        required=True)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return None

    args = parser.parse_args()

    if args.key_type not in SUPPORTED_KEY_TYPES:
        parser.print_help(sys.stderr)
        return None

    return args

def parse_in_rsa_args():
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=example_rsa_text,
        formatter_class=argparse.RawTextHelpFormatter)
    required = parser.add_argument_group('required arguments')
    required.add_argument(
        '--key_type',
        default="",
        help='Supported key types => ``%s``' % ("``, ``".join(SUPPORTED_RSA_KEY_TYPES)),
        required=True)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return None

    args = parser.parse_args()

    if args.key_type not in SUPPORTED_RSA_KEY_TYPES:
        parser.print_help(sys.stderr)
        return None

    return args

def parse_in_ec_args():
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=example_ec_text,
        formatter_class=argparse.RawTextHelpFormatter)
    required = parser.add_argument_group('required arguments')
    required.add_argument(
        '--key_type',
        default="",
        help='Supported key types => ``%s``' % ("``, ``".join(SUPPORTED_EC_KEY_TYPES)),
        required=True)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return None

    args = parser.parse_args()

    if args.key_type not in SUPPORTED_EC_KEY_TYPES:
        parser.print_help(sys.stderr)
        return None

    return args

def get_opensc_version() -> str:
    """
    Get the opensc-tool version
    """
    result = subprocess.run([OPENSC, "--info"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False)
    if result.returncode != 0:
        log.error("Could not get opensc version:", str(result.stderr, "utf-8"))
        return ""
    else:
        return str(result.stdout, "utf-8")

def read_from_file(filename, binary=False):

    if binary is True:
        with open(filename, 'rb') as f:
            data = f.read()
    else:
        with open(filename, 'rb') as f:
            data = bytes_to_hexstr(f.read())

    logging.info(f"Data read from [{filename}]")
    return data

def bytes_to_hexstr(bt):
    return binascii.hexlify(bt).decode('ascii')

def file_write(encoded_sign_file, sign_data):
    with open(encoded_sign_file, 'wb') as f:
        f.write(sign_data)

def int_to_bytes(i):

    # Converts an integer to bytes
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')

def der_encode_integer(value):

    # Encodes an integer in DER format

    integer_bytes = int_to_bytes(value)
    if integer_bytes[0] & 0x80:
        integer_bytes = b'\x00' + integer_bytes

    return b'\x02' + der_length_bytes(integer_bytes) + integer_bytes

def der_encode_sequence(values):

    # Encodes a sequence in DER format

    sequence = b''.join(values)
    return b'\x30' + der_length_bytes(sequence) + sequence

def der_length_bytes(data):

    # Encodes the length in DER format

    length = len(data)
    if length < 128:
        return bytes([length])
    else:
        len_bytes = int_to_bytes(length)
        return bytes([0x80 | len(len_bytes)]) + len_bytes

def convert_raw_to_asn1(raw_sign_file, encoded_sign):
    enc_sign = []
    raw_sign = read_from_file(raw_sign_file, binary=False)
    raw_sig = bytes.fromhex(raw_sign)

    half_len = len(raw_sig) // 2
    r = int.from_bytes(raw_sig[:half_len], byteorder='big')
    s = int.from_bytes(raw_sig[half_len:], byteorder='big')

    der_r = der_encode_integer(r)
    der_s = der_encode_integer(s)

    asn1_sign = der_encode_sequence([der_r, der_s])
    return file_write(encoded_sign, asn1_sign)

def parse_log_file(file_name):
    with open(file_name) as f:
        for line in f:
            if "Signature Verified Successfully" in line:
                log.info("Signature verified successfully !!!")
                return
            else:
                log.error("Verification failed !!")
                sys.exit()
