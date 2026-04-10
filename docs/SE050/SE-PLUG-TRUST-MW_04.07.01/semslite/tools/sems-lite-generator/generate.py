#! python3

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
import argparse
import json

from sems_lite_utils import setup
from sems_lite_utils.convert import Convert
import os
from sems_lite_utils.sems_lite_agent_version import SEMS_LITE_AGENT_MAJOR

Debug = False
sems_lite_agent_major_version = int(SEMS_LITE_AGENT_MAJOR)

def check_valid_sems_lite_agent_major_version(value):
    ivalue = int(value)
    if ivalue < 0:
        raise argparse.ArgumentTypeError("%s is an invalid sems lite agent major version, should be 32 bit integer value" % value)
    return ivalue

def get_json_file_version(json_file):
    with open(json_file, 'r') as f:
        json_data = f.read()
    json_obj = json.loads(json_data)
    f.close()
    return json_obj["MulticastPackageFormatVersion"]

def generate(input_json_file, output_path, name, protoc_path):
    json_file_version = get_json_file_version(input_json_file)
    schema_path = setup.schema_path(json_file_version)
    converter = Convert(schema_path, input_json_file, output_path, sems_lite_agent_major_version, name, protoc_path)
    converter.validate_input()
    converter.generate_proto()
    converter.generate_binary_and_header()


def main():
    if Debug is True:
        test()
    else:
        print('version ' + setup.VERSION)

        parser = argparse.ArgumentParser(description='Process sems-lite-generator arguments')
        parser.add_argument('-i, --input_json', required=True, dest='input_json', type=argparse.FileType('r'), help='input json file')
        parser.add_argument('-o, --output_path', required=True, dest='output_path', help='output folder path')
        parser.add_argument('-n, --name', required=False, dest='name', help='stem name of output files')
        parser.add_argument('-p, --protoc_path', required=False, dest='protoc_path', help='protoc file path. Use tools/mw_onverter/protoc.exe by default')
        pargs = parser.parse_args()

        if pargs.name is None:
            name = os.path.basename(pargs.input_json.name).rsplit('.', 1)[0]
        else:
            name = pargs.name

        generate(pargs.input_json.name, pargs.output_path, name, pargs.protoc_path)


def test():
    print('version ' + setup.VERSION)

    parser = argparse.ArgumentParser(description='Process sems-lite-generator arguments')
    parser.add_argument('-i, --input_json', required=True, dest='input_json', type=argparse.FileType('r'), help='input json file')
    parser.add_argument('-o, --output_path', required=True, dest='output_path', help='output folder path')

    pargs = parser.parse_args()
    print(pargs.input_json.name)
    print(pargs.output_path)
    print('testing')


if __name__ == "__main__":
    main()
