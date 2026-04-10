#
# Copyright 2019,2020,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#

import logging
import os
import sys
import traceback
from subprocess import Popen, PIPE, CalledProcessError

ecc_types = [
    "prime192v1",
    "secp224r1",
    "prime256v1",
    "secp384r1",
    "secp521r1",
    "brainpoolP256r1",
    "brainpoolP384r1",
    "brainpoolP512r1",
    "secp192k1",
    "secp224k1",
    "secp256k1",
]

ecc_types_cryptography_44 = [
    "prime192v1",
    "secp224r1",
    "prime256v1",
    "secp384r1",
    "secp521r1",
    "brainpoolP256r1",
    "brainpoolP384r1",
    "brainpoolP512r1",
    "secp256k1",
]

rsa_types = [
    "rsa2048",
    "rsa3072",
    "rsa4096",
]

auth_types = [
    "None",
    "PlatformSCP",
    "UserID",
    "ECKey",
    "AESKey"
]

connection_types = [
    "t1oi2c",
    "vcom",
    "jrcpv2",
]

logging.basicConfig(format='%(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)

def isValidKeyType(keyType):
    if keyType in ecc_types_cryptography_44 :
        return True
    if keyType in rsa_types :
        return True
    return False

def isValidECKeyType(keyType):
    if keyType in ecc_types_cryptography_44 :
        return True
    return False

def isValidRSAKeyType(keyType):
    if keyType in rsa_types :
        return True
    return False

def run(cmd_str, ignore_result=0, exp_retcode=0):
    print("Running command: %s" %cmd_str)
    with Popen(cmd_str, stdout=PIPE, bufsize=1, universal_newlines=True, shell=True) as p:
        for line in p.stdout:
            print(line, end='') # process line here
    if p.returncode != 0:
        raise CalledProcessError(p.returncode, p.args)

def session_open(subsystem, connection_data, connection_type, auth_type = "None", auth_key = "None"):
    ''' Open session based on IOT Secure Element selected. '''
    import sss.const as const
    import sss.connect as connect
    import sss.session as session

    log.info("###############################################################")
    log.info("#")
    log.info("#     SUBSYSTEM            : %s" % subsystem)
    log.info("#     CONNECTION_TYPE      : %s" % connection_type)
    log.info("#     CONNECTION_PARAMETER : %s" % connection_data)
    log.info("#     AUTH_TYPE            : %s" % auth_type)
    log.info("#")
    log.info("###############################################################")

    connect.do_open_session(const.SUBSYSTEM_TYPE[subsystem],
                          const.CONNECTION_TYPE[connection_type], connection_data,
                          auth_type=const.AUTH_TYPE_MAP[auth_type][0],
                          scpkey=auth_key)
    session_obj = session.Session()
    try:
        session_obj.session_open()
    except Exception as exc:
        error_log_file = os.path.abspath(os.path.dirname(__file__)) + os.sep + "error_log.txt"
        if not os.path.isfile(error_log_file):
            err_write = open(error_log_file, 'w+')
        else:
            err_write = open(error_log_file, 'a+')
        traceback.print_exc(None, err_write)
        err_write.close()
        return None
    return session_obj


def session_close(session):
    ''' Close opened session. '''
    import sss.connect as connect
    import sss.util as util

    if session:
        session.session_close()

    if os.path.isfile(util.get_session_pkl_path()):
        connect.do_close_session()


def reset(session):
    ''' Reset the Secure Module to the initial state. '''
    from sss.se05x import Se05x
    import sss.sss_api as apis
    if session.subsystem == apis.kType_SSS_SE_SE05x:
        se05x_obj = Se05x(session)
        se05x_obj.debug_reset()

def refpem_ecc_pair(session, keyid, file_name):
    ''' Creates reference PEM file for ECC Pair.
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        filename = File name to store reference key. Can be in PEM or DER or PKCS12 format based on file extension.
        By default filename with extension .pem in PEM format, .pfx or .p12 in PKCS12  format and others in DER format.
    '''
    from sss.refkey import RefPem
    import sss.sss_api as apis
    refpem_obj = RefPem(session)
    status = refpem_obj.do_ecc_refpem_pair(keyid, file_name)
    if status != apis.kStatus_SSS_Success:
        log.error("Refpem creation failed!")
        session_close(session)
        return status
    log.info("Successfully Created reference key.")
    return status


def refpem_ecc_pub(session, keyid, file_name):
    ''' Creates reference PEM file for ECC Public key.
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        filename = File name to store reference key. Can be in PEM or DER or PKCS12 format based on file extension.
        By default filename with extension .pem in PEM format, .pfx or .p12 in PKCS12  format and others in DER format.
    '''
    from sss.refkey import RefPem
    import sss.sss_api as apis
    refpem_obj = RefPem(session)
    status = refpem_obj.do_ecc_refpem_pub(keyid, file_name)
    if status != apis.kStatus_SSS_Success:
        log.error("Refpem creation failed!")
        session_close(session)
        return status
    log.info("Successfully Created reference key.")
    return status


def set_ecc_pair(session, keyid, client_key):
    ''' Set ECC Key pair to the Secure Module \n
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        key = Can be raw key (DER format) or in file.
        For file, by default filename with extension .pem considered as PEM format and others as DER format.\n
        '''
    import sss.setkey as setkey
    import sss.sss_api as apis
    log.info("client_key file: %s" % (client_key,))
    log.info("Injecting ECC key pair at key ID: 0x%x" % (keyid,))
    set_obj = setkey.Set(session)
    status = set_obj.do_set_ecc_key_pair(keyid, client_key, None)
    if status != apis.kStatus_SSS_Success:
        log.error("Injecting key pair failed!")
        session_close(session)
        return status
    log.info("Successfully Injected ECC key pair.")
    return status


def set_ecc_pub(session, keyid, client_key):
    ''' Set ECC Key public part to the Secure Module \n
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        key = Can be raw key (DER format) or in file.
        For file, by default filename with extension .pem considered as PEM format and others as DER format.\n
        '''
    import sss.setkey as setkey
    import sss.sss_api as apis
    log.info("client_key file: %s" % (client_key,))
    log.info("Injecting ECC public key at key ID: 0x%x" % (keyid,))
    set_obj = setkey.Set(session)
    status = set_obj.do_set_ecc_pub_key(keyid, client_key, None)
    if status != apis.kStatus_SSS_Success:
        log.error("Injecting ECC public key failed!")
        session_close(session)
        return status
    log.info("Successfully Injected ECC public key.")
    return status


def set_rsa_pair(session, keyid, client_key):
    ''' Set RSA Key pair to the Secure Module \n
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        key = Can be raw key (DER format) or in file.
        For file, by default filename with extension .pem considered as PEM format and others as DER format.\n
        '''
    import sss.setkey as setkey
    import sss.sss_api as apis
    log.info("client_key file: %s" % (client_key,))
    log.info("Injecting RSA key pair at key ID: 0x%x" % (keyid,))
    set_obj = setkey.Set(session)
    status = set_obj.do_set_rsa_key_pair(keyid, client_key, None)
    if status != apis.kStatus_SSS_Success:
        log.error("Injecting key pair failed..!")
        session_close(session)
        return status
    log.info("Successfully Injected RSA key pair.")
    return status

def set_rsa_pub(session, keyid, client_key):
    ''' Set RSA public key to the Secure Module \n
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        key = Can be raw key (DER format) or in file.
        For file, by default filename with extension .pem considered as PEM format and others as DER format.\n
        '''
    import sss.setkey as setkey
    import sss.sss_api as apis
    log.info("client_key file: %s" % (client_key,))
    log.info("Injecting RSA public key at key ID: 0x%x" % (keyid,))
    set_obj = setkey.Set(session)
    status = set_obj.do_set_rsa_pub_key(keyid, client_key, None)
    if status != apis.kStatus_SSS_Success:
        log.error("Injecting public key failed..!")
        session_close(session)
        return status
    log.info("Successfully Injected RSA public key.")
    return status


def refpem_rsa(session, keyid, file_name):
    ''' Creates reference PEM file for RSA Pair.
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        filename = File name to store reference key. Can be in PEM or DER or PKCS12 format based on file extension.
        By default filename with extension .pem in PEM format, .pfx or .p12 in PKCS12  format and others in DER format.
    '''
    from sss.refkey import RefPem
    import sss.sss_api as apis
    refpem_obj = RefPem(session)
    status = refpem_obj.do_rsa_refpem_pair(keyid, file_name)
    if status != apis.kStatus_SSS_Success:
        log.error("Refpem creation failed..!")
        session_close(session)
        return status
    log.info("Successfully Created reference key.")
    return status

def set_cert(session, keyid, cert):
    ''' Inject Certificate to the Secure Module
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        key = Can be raw certificate (DER format) or in file.
        For file, by default filename with extension .pem and .cer considered as PEM format and others as DER format.\n
    '''
    import sss.setkey as setkey
    import sss.sss_api as apis
    log.info("certificate file: %s" % (cert,))
    log.info("Injecting Certificate at key ID: 0x%x" % (keyid,))
    set_obj = setkey.Set(session)
    status = set_obj.do_set_cert(keyid, cert, None)
    if status != apis.kStatus_SSS_Success:
        log.error("Injecting certificate failed..!")
        session_close(session)
        return status
    log.info("Successfully Injected Certificate.")
    return status