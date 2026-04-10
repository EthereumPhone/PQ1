#! python3

# Copyright 2020,2022 NXP
#
# NXP Confidential. This software is owned or controlled by NXP and may only
# be used strictly in accordance with the applicable license terms.  By
# expressly accepting such terms or by downloading, installing, activating
# and/or otherwise using the software, you are agreeing that you have read,
# and that you agree to comply with and are bound by, such license terms.  If
# you do not agree to be bound by the applicable license terms, then you may
# not retain, install, activate or otherwise use the software.
#

import jsonschema
import json
import base64
import io
import pathlib
import os
import subprocess
import string
from sems_lite_utils import cgtParser
from sems_lite_utils import setup
from sems_lite_utils.jsonToHeader import JsonToHeader
from sems_lite_utils.jsonToBerTlv import JsonToBerTlv


def add_licence(self):
    c_header = """/* Copyright 2021 NXP
 *
 * NXP Confidential. This software is owned or controlled by NXP and may only
 * be used strictly in accordance with the applicable license terms.  By
 * expressly accepting such terms or by downloading, installing, activating
 * and/or otherwise using the software, you are agreeing that you have read,
 * and that you agree to comply with and are bound by, such license terms.  If
 * you do not agree to be bound by the applicable license terms, then you may
 * not retain, install, activate or otherwise use the software.
 */

/* This is an auto generated file */

"""


class Convert(object):
    def __init__(self, schema_file: str, json_file: str, output_dir: str, sems_lite_agent_major_version: int, name: str, protoc_path: str):
        with open(schema_file, 'r') as f:
            schema_data = f.read()
        self.schema_obj = json.loads(schema_data)
        with open(json_file, 'r') as f:
            json_data = f.read()
        self.json_obj = json.loads(json_data)
        if not os.path.isdir(output_dir):
            os.mkdir(output_dir)
        self.output_base_path_and_name = output_dir + os.sep + name
        self.binary_data = None
        self.hex_c_file = None
        self.hex_bin_file = None
        self.json_fields = []
        self.sems_lite_agent_major_version = sems_lite_agent_major_version
        self.protoc_path = protoc_path
        pass

    def validate_input(self):
        validator = jsonschema.Draft7Validator(self.schema_obj)

        errors = validator.iter_errors(self.json_obj)  # get all validation errors
        found_validation_error = False
        for error in errors:
            found_validation_error = True
            print(error)
            print('------')

        if found_validation_error:
            raise SystemExit('json validation error')

    def generate_proto(self):
        print(self.output_base_path_and_name)
        multicast_commands = base64.b64decode(self.json_obj["MulticastCommands"]).decode("utf-8")
        parser = cgtParser.CGTParser(
            io.StringIO(multicast_commands),
            self.output_base_path_and_name + ".proto",
            self.output_base_path_and_name + ".jcsh",   # jcsh format is most likely not relevant for the customer

        )
        parser.run()
        pass

    def get_binary(self):
        if self.protoc_path is None:
            cmd = [str(setup.mw_proto_buf_converter_tool_path()), '--encode=nxp.iot.Requests',
                   '--proto_path=' + str(setup.mw_proto_buf_grammar_path()), str(setup.mw_proto_buf_grammar_path()) + '/Dispatcher.proto']
        else:
            cmd = [str(self.protoc_path), '--encode=nxp.iot.Requests',
                   '--proto_path=' + str(setup.mw_proto_buf_grammar_path()), str(setup.mw_proto_buf_grammar_path()) + '/Dispatcher.proto']
        with open(pathlib.Path(self.output_base_path_and_name + ".proto").absolute(), 'r') as proto_file:
            pro = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
            (stdout_data, stderr_data) = pro.communicate(input=proto_file.read().encode('utf-8'), timeout=55)
            if stderr_data is None and pro.returncode == 0:
                with open(self.output_base_path_and_name + ".tmpbin", 'bw') as bin_file:
                    bin_file.write(stdout_data)
                    bin_file.flush()
            else:
                raise SystemExit('Intermediate Binary file generation failed')

    def generate_binary(self):
        json2bertlv = JsonToBerTlv(self.output_base_path_and_name + ".tmpbin",
                                       self.output_base_path_and_name,
                                       self.json_obj,
                                       self.sems_lite_agent_major_version)

        json2bertlv.run()
        pass

    def generate_header(self):
        json2header = JsonToHeader(self.output_base_path_and_name + ".tmpbin",
                                   self.output_base_path_and_name,
                                   self.json_obj,
                                   self.sems_lite_agent_major_version)
        json2header.run()
        pass

    def generate_binary_and_header(self):
        print("OEF ID : " + str(hex(int(self.json_obj["TargetEntityID"][-5:]))[2:]).upper())
        self.get_binary()
        self.generate_binary()
        self.generate_header()
