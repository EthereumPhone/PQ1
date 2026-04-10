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

import pathlib
import os


VERSION = '0.1.0'


def base_dir():
    return pathlib.Path(os.path.dirname(os.path.realpath(__file__))).absolute().parent

def project_dir():
    return base_dir().parent.parent.parent

def ls_cgt_tool_path():
    return project_dir() /'sems_lite_sys_tools'/ 'tools' / 'nxp-ls-cgt-1.0.0' / 'LSCGT' / 'usage' / 'tools' / 'ls-cgt.jar'

def mw_proto_buf_converter_tool_path():
    return base_dir() / 'tools' / 'mw_converter' / 'protoc.exe'

def mw_proto_buf_grammar_path():
    return project_dir() / 'nxp_iot_agent' / 'doc' / 'protobuf'

def schema_path(json_file_version="1.2"):
    if json_file_version == "1.3":
        return base_dir() / 'schema' / 'MulticastPackage_1_3.jsonschema'
    else:
        return base_dir() / 'schema' / 'MulticastPackage_1_2.jsonschema'

def java_path():
    path = os.environ.get('JAVA_HOME')
    if path is None:
        raise SystemExit('JAVA_HOME not set')

    return pathlib.Path(path) / 'bin' / 'java'
