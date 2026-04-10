# Copyright 2018,2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Convert files that we get from OEF to header files

"""

import glob
import os
import sys
import time

LOCAL_TIME = time.localtime()
DATETIME_STR = time.strftime("%Y:%m:%d", LOCAL_TIME) + "_" + time.strftime("%H:%M", LOCAL_TIME)

AUTO_GEN_INFO = """This file is auto generated (%s) using:
             <simw-top>/scripts/parse_oef_keys.py""" % (DATETIME_STR,)

USAGE_INFO = """Usage info:
             python parse_oef_keys.py <directory_path> <header> <footer> <macro_prefix> <output_filename>

             directory_path  => Keys folder path.
             header          => header for the c file. Optional argument.
             footer          => footer for the c file. Optional argument.
             macro_prefix    => Prefix of the macro. Optional argument. default: SSS_AUTH_SE050_OEF.
             output_filename => Output file name for c and python file. Optional argument.
                                default: ex_sss_tp_scp03_keys.h, tp_scp03_keys.py"""

DEFAULT_MACRO_PREFIX = "SSS_AUTH_SE050_OEF"

LICENSE_TEXT = """ Copyright 2019,2020 NXP

 This software is owned or controlled by NXP and may only be used
 strictly in accordance with the applicable license terms.  By expressly
 accepting such terms or by downloading, installing, activating and/or
 otherwise using the software, you are agreeing that you have read, and
 that you agree to comply with and are bound by, such license terms.  If
 you do not agree to be bound by the applicable license terms, then you
 may not retain, install, activate or otherwise use the software."""

CLANG_OFF = """/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* clang-format off */"""

CLANG_ON = """/* clang-format on */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */"""

DEFAULT_OUTPUT_FILE_NAME = "tp_scp03_keys"


def read_data(filename):
    """
    Read key value from the file
    :param filename: file name to read key
    :return: Key value
    """
    f = open(filename, 'r')
    file_data = f.read()
    key_data = ""
    for i in range(0, len(file_data), 2):
        if i == 0:
            key_data += "0x"
        else:
            key_data += ", 0x"
        key_data += file_data[i:i + 2]
    f.close()
    return key_data


def write_data_to_c(key_data_dict, output_file):
    """
    Write ``output_file`` with keys.
    :param key_data_dict: Key values
    :param output_file: Destination c file to write key value
    :return: None
    """

    if len(sys.argv) >= 5:

        if os.path.isfile(sys.argv[2]):
            header_file = open(sys.argv[2], 'r')
            header_data = header_file.read()
            header_file.close()
        else:
            header_data = sys.argv[2]

        if os.path.isfile(sys.argv[3]):
            footer_file = open(sys.argv[3], 'r')
            footer_data = footer_file.read()
            footer_file.close()
        else:
            footer_data = sys.argv[3]
        macro = sys.argv[4]
    else:
        macro = DEFAULT_MACRO_PREFIX
        timestamp_str = time.strftime("_%Y%m%d_", LOCAL_TIME) + \
                        time.strftime("%H%M_", LOCAL_TIME)
        header_data = "#ifndef %s\n#define %s\n" % (macro + timestamp_str,
                                                    macro + timestamp_str,)
        footer_data = "#endif /* %s  */" % (macro + timestamp_str,)

    usage_info = AUTO_GEN_INFO.replace("\n", "\n * ")
    usage_info += "\n *\n * "
    usage_info += USAGE_INFO.replace("\n", "\n * ")
    license_info = "/*" + LICENSE_TEXT.replace("\n", "\n *") + "\n */"
    data_to_write = license_info + "\n\n\n/* " + usage_info + "\n */\n\n\n" \
                    + header_data + "\n" + CLANG_OFF + "\n\n"

    for key_data in key_data_dict:
        data_to_write += "#define " + macro + "_" + str(
            key_data) + " " * 5 + "\\\n" + " " * 4 + "{" + " " * 59 + "\\\n" + " " * 8
        key_data_len = len(key_data_dict[key_data])
        data_to_write += key_data_dict[key_data][
                         0:int(key_data_len / 2)] + " " * 9 + "\\\n" + " " * 8
        data_to_write += key_data_dict[key_data][(int(key_data_len / 2) + 1):] + " " * 8
        data_to_write += "  \\\n    }\n\n"

    data_to_write += CLANG_ON + "\n\n" + footer_data

    out_file = open(output_file, 'w')
    out_file.write(data_to_write)
    out_file.close()


def write_data_to_python(key_data_dict, output_file_name):
    """
    Append keys to the output file
    :param key_data_dict: Key values
    :param output_file_name: Destination python file to write key value
    :return: None
    """

    if len(sys.argv) >= 3:
        macro = sys.argv[2]
    else:
        macro = DEFAULT_MACRO_PREFIX

    license_info = "#" + LICENSE_TEXT.replace("\n", "\n#") + "\n#\n\n\n"
    data_to_write = license_info
    python_usage_info = "# " + AUTO_GEN_INFO.replace("\n", "\n# ")
    python_usage_info += "\n#\n# "
    python_usage_info += USAGE_INFO.replace("\n", "\n# ")
    data_to_write += python_usage_info + "\n\n\n"

    for key_data in key_data_dict:
        data_to_write += macro + "_" + str(key_data) + " = (\n    "
        key_data_len = len(key_data_dict[key_data])
        data_to_write += key_data_dict[key_data][0:int(key_data_len / 2)] + "\n    "
        data_to_write += key_data_dict[key_data][(int(key_data_len / 2) + 1):]
        data_to_write += ",\n    )\n\n"

    out_file = open(output_file_name, 'w')
    out_file.write(data_to_write)
    out_file.close()


def main():  # pylint: disable=too-many-locals
    """
    Parse keys from input directory and write in C and python files.
    :return: None
    """
    keys_dir = sys.argv[1]
    enc_keys_file_list = list()
    mac_keys_file_list = list()
    dec_keys_file_list = list()
    key_file_list = glob.glob(keys_dir + os.sep + "*.key")
    for key_file in key_file_list:
        if "_AuthKey_" in key_file:
            enc_keys_file_list.append(key_file)
        elif "_MacKey_" in key_file:
            mac_keys_file_list.append(key_file)
        elif "_EncKey_" in key_file:
            dec_keys_file_list.append(key_file)

    key_data = {}
    for enc_file in enc_keys_file_list:
        match_key = enc_file.split("_AuthKey_", 2)[1].split("_NXP", 2)[0]
        key_data[match_key + "_KEY_ENC"] = read_data(enc_file)
        for mac_file in [x for x in mac_keys_file_list if match_key in x]:
            key_data[match_key + "_KEY_MAC"] = read_data(mac_file)
        for dec_file in [x for x in dec_keys_file_list if match_key in x]:
            key_data[match_key + "_KEY_DEK"] = read_data(dec_file)

    c_output_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..",
                                "sss", "ex", "inc")
    python_output_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                     "..", "pycli", "src", "sss")

    if len(sys.argv) >= 6:
        output_file_name = sys.argv[5]
        if output_file_name[-2:] == ".h":
            c_output_file = output_file_name
            python_output_file = output_file_name[:-2] + ".py"
        elif output_file_name[-3:] == ".py":
            c_output_file = output_file_name[:-3] + ".h"
            python_output_file = output_file_name
        else:
            c_output_file = output_file_name + ".h"
            python_output_file = output_file_name + ".py"
    else:
        c_output_file = "ex_sss_" + DEFAULT_OUTPUT_FILE_NAME + ".h"
        python_output_file = DEFAULT_OUTPUT_FILE_NAME + ".py"

    write_data_to_c(key_data, c_output_dir + os.sep + c_output_file)
    write_data_to_python(key_data, python_output_dir + os.sep + python_output_file)


def usage():
    """
    Display usage information
    :return: None
    """
    print(USAGE_INFO)


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        main()
    else:
        usage()
