#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#


# This script is used to generate keys and CA certificates using openssl engine.
# The generated keys shall be available in aws directory
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

    if SE_UID is None or SE_UID == 0:
        return STATUS_FAIL

    aws_dir = cur_dir + os.sep + "aws"
    if not os.path.exists(aws_dir):
        try:
            os.makedirs(aws_dir)
        except OSError:
            print("Error! Failed to create 'aws' directory")
            return STATUS_FAIL

    OUTPUT_DIR = aws_dir + os.sep
    if simw_top_dir is None:
        simw_top_dir = os.path.join(cur_dir, '..', '..')
    if "linux" in sys.platform:
        OPENSSL_EXE = 'openssl'
    else:
        OPENSSL_EXE = os.path.join(simw_top_dir, 'ext', 'openssl', 'bin', 'openssl.exe')
    OPENSSL_CONFIG = "-config \"%s\"" % (os.path.join(simw_top_dir, "ext", "openssl", "ssl", "openssl.cnf"))
    EXT_FILE_DEVICE = OUTPUT_DIR + "v3_ext_device.cnf"
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
    deviceCertAscii = OUTPUT_DIR + "%d_device_ec_crt_ascii_dump.txt" % SE_UID
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

    """
    UID Specific
    """
    # re-create EC parameters with the group 'prime256v1'
    cmd_str="\"%s\" ecparam -name prime256v1 -out \"%s\"" % (OPENSSL_EXE, ecc_param_pem)
    if not os.path.isfile(ecc_param_pem):
        a = subprocess.Popen(get_cmd(cmd_str),shell=False, stdout=output_write, stderr=err_write)
        a.wait()

    # Check if the root ca key and certificate is available
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


    # Generate device key and create a signing request for the same
    cmd_str="\"%s\" ecparam -genkey -name prime256v1 -out \"%s\"" % (OPENSSL_EXE, uidKey)
    a = subprocess.Popen(get_cmd(cmd_str),shell=False, stdout=output_write, stderr=err_write)
    a.wait()
    cmd_str="\"%s\" req -new -key \"%s\" -out \"%s\" -subj \"%s\" %s" %(OPENSSL_EXE, uidKey, uidCsr, "/CN=%s" % CN_val, OPENSSL_CONFIG)
    a = subprocess.Popen(get_cmd(cmd_str),shell=False, stdout=output_write, stderr=err_write)
    a.wait()

    # create a device certificate
    cmd_str="\"%s\" x509 -req -days %d -in \"%s\" -CAserial intermca_srl.srl -CAcreateserial -CA \"%s\" -CAkey \"%s\" -extfile %s -extensions v3_req -out \"%s\""% (OPENSSL_EXE, CLIENT_CERT_VALIDITY, uidCsr, rootCACert, rootCAKey, EXT_FILE_DEVICE,deviceCert)
    a = subprocess.Popen(get_cmd(cmd_str),shell=False, stdout=output_write, stderr=err_write)
    a.wait()

    if os.path.isfile(uidCsr):
        os.remove(uidCsr)
    if os.path.isfile("intermca_srl.srl"):
        os.remove("intermca_srl.srl")
    if os.path.isfile("rootca_srl.srl"):
        os.remove("rootca_srl.srl")

    output_write.close()
    err_write.close()
    print("Generating Credentials Successfull")
    return STATUS_SUCCESS

