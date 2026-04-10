#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#


# This script is used to generate keys and certificates using openssl engine.
# The generated keys shall be available in gcp directory
# These keys are used to provision to the secure element

import subprocess
import os
import shlex
from .Provision_util import *
from . import cloud_credentials


def get_cmd(cmd_str):
    if 'nt' in os.name:
        return cmd_str
    else:
        return shlex.split(cmd_str)



def generateCredentials(cur_dir, simw_top_dir=None):
    ''' Generate Credential
    Input : Current Directory path
    '''
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

    # cur_dir = os.getcwd()
    if simw_top_dir is None:
        simw_top_dir = os.path.join(cur_dir, '..', '..')
    # path to openssl
    if "linux" in sys.platform:
        OPENSSL_EXE = 'openssl'
    else:
        OPENSSL_EXE = os.path.join(simw_top_dir, 'ext', 'openssl', 'bin', 'openssl.exe')

    # path to openssl config file
    OPENSSL_CONFIG = "-config \"%s\"" % (os.path.join(simw_top_dir, "ext", "openssl", "ssl", "openssl.cnf"))

    gcp_dir = cur_dir + os.sep + "gcp"
    if not os.path.exists(gcp_dir):
        try:
            os.makedirs(gcp_dir)
        except OSError:
            print("Error! Failed to create 'gcp' directory")
            return STATUS_FAIL
    # filename and path for the generated certificates and keys
    credentials = cloud_credentials.create_credentials(SE_UID)

    rootca = gcp_dir + os.sep + "rootCA"
    client_key = gcp_dir + os.sep + credentials["DEVICE_KEY"]
    client_csr = gcp_dir + os.sep + "%d_client.csr" % SE_UID
    client_cer = gcp_dir + os.sep + credentials["DEVICE_CERT"]
    rootCAKey = gcp_dir + os.sep+ credentials["ROOT_CA_KEY"]
    rootCACert = gcp_dir + os.sep + credentials["ROOT_CA_CERT_CER"]
    rootca_srl = rootca + ".srl"
    ecc_param_pem = gcp_dir + os.sep + "prime256v1.pem"

    # if the root ca exits, use it otherwise create it
    if os.path.isfile(rootca_srl):
        x509_serial = "-CAserial %s" % rootca_srl
    else:
        x509_serial = "-CAserial %s -CAcreateserial" % rootca_srl

    # if the gcp output directory exists, use it otherwise create it
    if not os.path.exists("gcp"):
        try:
            os.makedirs("gcp")
        except OSError:
            print("Error! Failed to create 'gcp' directory")
            return STATUS_FAIL

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
    cmd_str="\"%s\" req -x509 -new -nodes -key \"%s\" -subj \"%s\" -days 2800 -out \"%s\" %s" % (OPENSSL_EXE,
                                                                                                 rootCAKey,
                                                                                                 "/C=BE/ST=VlaamsBrabant/L=Leuven/O=NXP-Demo-CA/OU=Demo-Unit/CN=demoCA/emailAddress=demoCA@nxp",
                                                                                                 rootCACert,
                                                                                                 OPENSSL_CONFIG)
    if not os.path.isfile(rootCACert):
        a = subprocess.Popen(get_cmd(cmd_str),shell=False, stdout=output_write, stderr=err_write)
        a.wait()
        cmd_str="\"%s\" x509 -in \"%s\" -text -noout" % (OPENSSL_EXE, rootCACert)
        a = subprocess.Popen(get_cmd(cmd_str), shell=False,stdout=output_write, stderr=err_write)
        a.wait()

    # device private key generation
    cmd_str="\"%s\" ecparam -in \"%s\" -genkey -out \"%s\"" % (OPENSSL_EXE, ecc_param_pem, client_key)
    if not os.path.isfile(client_key):
        a = subprocess.Popen(get_cmd(cmd_str),shell=False,stdout=output_write, stderr=err_write)
        a.wait()
        cmd_str="\"%s\" ec -in \"%s\" -text -noout" % (OPENSSL_EXE, client_key)
        a = subprocess.Popen(get_cmd(cmd_str), shell=False,stdout=output_write,stderr=err_write)
        a.wait()

    # device CSR
    cmd_str="\"%s\" req -new -key \"%s\" -subj \"%s\" -out \"%s\" %s" % (OPENSSL_EXE, client_key, "/C=BE/O=NXPDemo/OU=Unit/CN=localhost", client_csr, OPENSSL_CONFIG)
    a = subprocess.Popen(get_cmd(cmd_str),shell=False, stdout=output_write, stderr=err_write)
    a.wait()
    cmd_str="\"%s\" req -in \"%s\" -text %s" % (OPENSSL_EXE, client_csr, OPENSSL_CONFIG)
    a = subprocess.Popen(get_cmd(cmd_str), shell=False,stdout=output_write, stderr=err_write)
    a.wait()

    # Device cerficate generation
    cmd_str="\"%s\" x509 -req -sha256 -days 2800 -in \"%s\" %s -CA \"%s\" -CAkey \"%s\" -out \"%s\"" % (OPENSSL_EXE, client_csr, x509_serial, rootCACert, rootCAKey, client_cer)
    a = subprocess.Popen(get_cmd(cmd_str),shell=False, stdout=output_write, stderr=err_write)
    a.wait()
    cmd_str="\"%s\" x509 -in \"%s\" -text -noout" % (OPENSSL_EXE, client_cer)
    a = subprocess.Popen(get_cmd(cmd_str), shell=False, stdout=output_write,stderr=err_write)
    a.wait()

    output_write.close()
    err_write.close()

    os.remove(client_csr)
    os.remove(rootca_srl)
    print("Generating Credentials Successfull")
    return STATUS_SUCCESS
