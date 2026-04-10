# Copyright 2020 NXP
#
# NXP Confidential. This software is owned or controlled by NXP and may only
# be used strictly in accordance with the applicable license terms.  By
# expressly accepting such terms or by downloading, installing, activating
# and/or otherwise using the software, you are agreeing that you have read,
# and that you agree to comply with and are bound by, such license terms.  If
# you do not agree to be bound by the applicable license terms, then you may
# not retain, install, activate or otherwise use the software.
#

import sys
import os

path = os.path.join(os.path.dirname(__file__), "sems-lite-generator")
sys.path.append(os.path.abspath(path))
import generate

USAGE_INFO = """Usage info:
             python %s <directory_path> [protoc_path]

             directory_path  => Mals folder path.
             protoc_path     => Path of protoc file. It's optional. By default, it would use tools/mw_onverter/protoc.exe.
""" % (__file__,)


def main():
    """
    walks through the directory and calls generate
    :return: None
    """
    mals_dir = sys.argv[1]
    if len(sys.argv) == 2:
        protoc_path=None
    else:
        protoc_path = sys.argv[2]

    files_dir_list = []
    for dir_path, dir_names, file_names in os.walk(mals_dir):
        for file_name in [f for f in file_names]:
            # erase .h .jcsh, .bin files
            if file_name.endswith(".h") or file_name.endswith(".bin") or file_name.endswith(".jcsh"):
                os.remove(os.path.join(dir_path, file_name))
            elif file_name.endswith(".json"):
                json_file_path = (dir_path, file_name)
                files_dir_list.append(json_file_path)

    for item in files_dir_list:
        generate.generate(os.path.join(item[0], item[1]), item[0], item[1][:-5], protoc_path)


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
