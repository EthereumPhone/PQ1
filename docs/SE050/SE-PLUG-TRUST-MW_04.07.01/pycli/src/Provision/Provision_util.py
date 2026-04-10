#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#


import os
import sys
from . import Provision_config
import sss.sss_api as apis
import sss.const as const
import sss.connect as connect
import sss.session as session
import sss.util as util
import sss.setkey as setkey
from sss.refkey import RefPem
from sss.se05x import Se05x

import logging
log = logging.getLogger(__name__)
logging.basicConfig(format='%(message)s', level=logging.INFO)

STATUS_SUCCESS = 0
STATUS_FAIL = -1


def session_open():
    ''' Open session '''
    if Provision_config.CONNECTION_METHOD == 't1oi2c' or Provision_config.CONNECTION_METHOD == 'sci2c':
        port_data = "none"
    else:
        if len(sys.argv) >= 2:
            port_data = sys.argv[1]
        else:
            log.info('Please provide <COM_PORT>')
            log.info('Usage Example:\n               %s COM5' % sys.argv[0])
            return None

    log.info("###############################################################")
    log.info("#")
    log.info("#     SUBSYSTEM            : %s" % Provision_config.SUBSYSTEM)
    log.info("#     CONNECTION_TYPE      : %s" % Provision_config.CONNECTION_METHOD)
    log.info("#     CONNECTION_PARAMETER : %s" % port_data)
    log.info("#")
    log.info("###############################################################")

    if os.path.isfile(util.get_session_pkl_path()):
        connect.do_close_session()
    connect.do_open_session(const.SUBSYSTEM_TYPE[Provision_config.SUBSYSTEM],
                          const.CONNECTION_TYPE[Provision_config.CONNECTION_METHOD], port_data)
    session_obj = session.Session()
    session_obj.session_open()

    return session_obj


def session_close(session):
    ''' Close opened session. '''
    if session:
        session.session_close()

    if os.path.isfile(util.get_session_pkl_path()):
        connect.do_close_session()


def get_unique_id(session_obj):
    ''' get Device UID'''
    if session_obj.subsystem == apis.kType_SSS_SE_SE05x:
        se05x_obj = Se05x(session_obj)
        unique_id = se05x_obj.get_cert_unique_id()
    else:
        log.error("Unsupported Subsystem.!!")
        unique_id = 0
    return int(unique_id, 16)


def reset(session):
    ''' Reset the Secure Module to the initial state. '''
    if session.subsystem == apis.kType_SSS_SE_SE05x:
        se05x_obj = Se05x(session)
        se05x_obj.debug_reset()


def refpem_ecc(session, keyid, file_name):
    ''' Creates reference PEM file for ECC Pair.
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        filename = File name to store reference key. Can be in PEM or DER or PKCS12 format based on file extension.
        By default filename with extension .pem in PEM format, .pfx or .p12 in PKCS12  format and others in DER format.
    '''
    log.info("Creating ECC Reference key from key ID: 0x%x" % (keyid,))
    refpem_obj = RefPem(session)
    status = refpem_obj.do_ecc_refpem_pair(keyid, file_name)
    if status != apis.kStatus_SSS_Success:
        log.error("Refpem creation failed..!")
        session_close(session)
        return status
    log.info("Successfully Created reference key at: %s" % (file_name, ))
    return status


def set_ecc_pair(session, keyid, client_key):
    ''' Set ECC Key pair to the Secure Module \n
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        key = Can be raw key (DER format) or in file.
        For file, by default filename with extension .pem considered as PEM format and others as DER format.\n
        '''
    log.info("key pair file: %s" % (client_key,))
    log.info("Injecting ECC key pair at key ID: 0x%x" % (keyid,))
    set_obj = setkey.Set(session)
    status = set_obj.do_set_ecc_key_pair(keyid, client_key, None)
    if status != apis.kStatus_SSS_Success:
        log.error("Injecting ECC key pair failed..!")
        session_close(session)
        return status
    log.info("Successfully Injected ECC key pair.")
    return status


def set_cert(session, keyid, cert):
    ''' Inject Certificate to the Secure Module
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        key = Can be raw certificate (DER format) or in file.
        For file, by default filename with extension .pem and .cer considered as PEM format and others as DER format.\n
    '''
    log.info("certificate file: %s" % (cert,))
    log.info("Injecting certificate at key ID: 0x%x" % (keyid,))
    set_obj = setkey.Set(session)
    status = set_obj.do_set_cert(keyid, cert, None)
    if status != apis.kStatus_SSS_Success:
        log.error("Injecting certificate failed..!")
        session_close(session)
        return status
    log.info("Successfully Injected certificate.")
    return status
