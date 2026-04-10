#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#


# This script is used to generate keys and CA certificates using openssl engine.
# The generated keys shall be available in azure directory
# These keys are used to provision to the secure element

import subprocess
import shlex
from .Provision_util import *
from . import cloud_credentials

def get_cmd(cmd_str):
    if 'nt' in os.name:
        return cmd_str
    else:
        return shlex.split(cmd_str)

def generateCredentials(cur_dir, simw_top_dir=None):
    # Session Open
    session_obj = session_open()
    if session_obj is None:
        return STATUS_FAIL

    # Read UID from the device
    SE_UID = get_unique_id(session_obj)

    # Session Close
    session_close(session_obj)

    if SE_UID is None:
        return STATUS_FAIL

    azure_dir = cur_dir + os.sep + "azure"
    if simw_top_dir is None:
        simw_top_dir = os.path.join(cur_dir, '..', '..')

    if not os.path.exists(azure_dir):
        try:
            os.makedirs(azure_dir)
        except OSError:
            print("Error! Failed to create 'azure' directory")
            return STATUS_FAIL

    OUTPUT_DIR = azure_dir + os.sep
    if "linux" in sys.platform:
        OPENSSL_EXE = 'openssl'
    else:
        OPENSSL_EXE = os.path.join(simw_top_dir, 'ext', 'openssl', 'bin', 'openssl.exe')
    OPENSSL_CONFIG = "-config \"%s\"" % (os.path.join(simw_top_dir, "ext", "openssl", "ssl", "openssl.cnf"))
    EXT_FILE = OUTPUT_DIR + "v3_ext.cnf"
    rootca = OUTPUT_DIR + "rootCA"
    ecc_param_pem = OUTPUT_DIR + "prime256v1.pem"
    ROOT_CA_CN = "NXP Semiconductors DEMO rootCA v Ek"
    CA_CERT_VALIDITY = 7300
    CLIENT_CERT_VALIDITY = 7300
    devType = "NXP-SE050-EC-D"

    credentials = cloud_credentials.create_credentials(SE_UID)

    deviceSerial = "0x01%d" % SE_UID
    uidKey = OUTPUT_DIR + credentials["DEVICE_KEY"]
    uidCsr = OUTPUT_DIR + "%d.csr" % SE_UID
    deviceCert = OUTPUT_DIR + credentials["DEVICE_CERT"]
    rootCAKey = OUTPUT_DIR + credentials["ROOT_CA_KEY"]
    rootCACert = OUTPUT_DIR + credentials["ROOT_CA_CERT_CER"]
    CN_val = "%s" % SE_UID
    GENERIC_val = "URI:NXP:%d" % SE_UID
    SAN_D_val = "email:d:%s:%d, %s" % (devType, SE_UID, GENERIC_val)

    error_file = cur_dir + os.sep + "error_log.txt"
    err_write = open(error_file, 'wb+')

    output_file = cur_dir + os.sep + "output_log.txt"
    output_write = open(output_file, 'wb+')

    # create EC parameters with the group 'prime256v1'
    cmd_str="\"%s\" ecparam -name prime256v1 -out \"%s\"" % (OPENSSL_EXE, ecc_param_pem)
    if not os.path.isfile(ecc_param_pem):
        a = subprocess.Popen(get_cmd(cmd_str), shell=False,stdout=output_write, stderr=err_write)
        a.wait()

    # rootca private Key generation and convert to DER format
    cmd_str="\"%s\" ecparam -in \"%s\" -genkey -out \"%s\"" % (OPENSSL_EXE, ecc_param_pem, rootCAKey)
    if not os.path.isfile(rootCAKey):
        a = subprocess.Popen(get_cmd(cmd_str),shell=False, stdout=output_write, stderr=err_write)
        a.wait()

    # create the rootca certificate
    cmd_str="\"%s\" req -x509 -new -nodes -key \"%s\" -sha256 -days %d -subj \"%s\" -out \"%s\" %s"% (OPENSSL_EXE, rootCAKey, CA_CERT_VALIDITY, "/CN=%s" % ROOT_CA_CN,rootCACert, OPENSSL_CONFIG)
    if not os.path.isfile(rootCACert):
        a = subprocess.Popen(get_cmd(cmd_str),shell=False, stdout=output_write, stderr=err_write)
        a.wait()
        cmd_str="\"%s\" x509 -in \"%s\" -text -noout" % (OPENSSL_EXE, rootCACert)
        a = subprocess.Popen(get_cmd(cmd_str), shell=False,stdout=output_write, stderr=err_write)
        a.wait()

    """
    UID Specific
    """
    # re-create EC parameters with the group 'prime256v1'
    cmd_str="\"%s\" ecparam -name prime256v1 -out \"%s\"" % (OPENSSL_EXE, ecc_param_pem)
    if not os.path.isfile(ecc_param_pem):
        a = subprocess.Popen(get_cmd(cmd_str),shell=False, stdout=output_write, stderr=err_write)
        a.wait()

    # Check if the rootca key and certificate is available
    if not os.path.isfile(rootCAKey):
        print("First create a RootCA key (%s) and matching RootCA certificate (%s)" % (rootCAKey, rootCACert))
        output_write.close()
        err_write.close()
        sys.exit()

    if not os.path.isfile(rootCACert):
        print("First create a RootCA certificate (%s)" % (rootCACert))
        output_write.close()
        err_write.close()
        sys.exit()

    # Generate device private Key
    cmd_str="\"%s\" ecparam -genkey -name prime256v1 -out \"%s\"" % (OPENSSL_EXE, uidKey)
    a = subprocess.Popen(get_cmd(cmd_str),shell=False, stdout=output_write, stderr=err_write)
    a.wait()
    # Create device certificate signing request
    cmd_str="\"%s\" req -new -key \"%s\" -out \"%s\" -subj \"%s\" %s" %(OPENSSL_EXE, uidKey, uidCsr, "/CN=%s" % CN_val, OPENSSL_CONFIG)
    a = subprocess.Popen(get_cmd(cmd_str),shell=False, stdout=output_write, stderr=err_write)
    a.wait()

    # Create a signed device certificate
    cmd_str="\"%s\" x509 -req -days %d -in \"%s\" -set_serial %s -CA \"%s\" -CAkey \"%s\" -extfile %s -extensions v3_req -out \"%s\""% (OPENSSL_EXE, CLIENT_CERT_VALIDITY, uidCsr, deviceSerial, rootCACert, rootCAKey, EXT_FILE,deviceCert)
    a = subprocess.Popen(get_cmd(cmd_str),shell=False, stdout=output_write, stderr=err_write)
    a.wait()

    os.remove(uidCsr)

    output_write.close()
    err_write.close()
    print("Generating Credentials Successfull")
    return STATUS_SUCCESS
