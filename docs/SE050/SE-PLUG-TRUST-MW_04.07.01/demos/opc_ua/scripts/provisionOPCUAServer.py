#
# Copyright 2019,2020,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

# SE050 Key provisioning script for TLS demo
#
# Preconditions
# - SE050 or A71CH attached
# - Virtual environment should be activated (not for iMX platform).
# Refer ssscli installation steps: Plug & Trust MW, Section 9.3
#
# Postconditions
# - Key pair injected on id referred by KEYPAIR_INDEX_CLIENT_PRIVATE variable
# - Ref pem created
# - Client certificate injected on id referred by CERTIFICATE_INDEX variable.
#
# Usage example:
# To run using t1oi2c on iMX platform:
# ->python provisionTlsClient.py
#
# To run using jrcpv1:
# ->python provisionTlsClient.py 192.168.1.222:8050
#
# To run using vcom:
# ->python provisionTlsClient.py COM7
#
# To run using jrcpv2:
# ->python provisionTlsClient.py 127.0.0.1:8050 jrcpv2
#

import os
import sys
import subprocess
import logging
import traceback
logging.basicConfig(format='%(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)

# GLOBAL VARIABLES
# ----------------
SE050_PROVISIONING_SCRIPT = "0.1"
IOT_SE = "se05x"
KEYPAIR_INDEX_SERVER_PRIVATE = 0x7D000020
CERTIFICATE_INDEX = 0x7D000021


def session_open(IOT_SE, ip_addr_port_server, connection_type):
    ''' Open session based on IOT Secure Element selected. '''
    import sss.const as const
    import sss.connect as connect
    import sss.session as session
    if ip_addr_port_server == "":
        ip_addr_port_server = "None"
        if IOT_SE == "se05x":
            connection_type = "t1oi2c"
        else:
            log.error("Un supported subsystem. Must be \"se05x\" ")
            return None
    log.info("###############################################################")
    log.info("#")
    log.info("#     SUBSYSTEM            : %s" % IOT_SE)
    log.info("#     CONNECTION_TYPE      : %s" % connection_type)
    log.info("#     CONNECTION_PARAMETER : %s" % ip_addr_port_server)
    log.info("#")
    log.info("###############################################################")

    connect.do_open_session(const.SUBSYSTEM_TYPE[IOT_SE],
                          const.CONNECTION_TYPE[connection_type], ip_addr_port_server)
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
        usage(connection_type)
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


def set_rsa_pair(session, keyid, server_key):
    ''' Set RSA Key pair to the Secure Module \n
        keyid = 32bit Key ID. Should be in hex format. Example: 20E8A001 \n
        key = Can be raw key (DER format) or in file.
        For file, by default filename with extension .pem considered as PEM format and others as DER format.\n
        '''
    import sss.setkey as setkey
    import sss.sss_api as apis
    log.info("server_key file: %s" % (server_key,))
    log.info("Injecting RSA key pair at key ID: 0x%x" % (keyid,))
    set_obj = setkey.Set(session)
    status = set_obj.do_set_rsa_key_pair(keyid, server_key, None)
    if status != apis.kStatus_SSS_Success:
        log.error("Injecting key pair failed..!")
        session_close(session)
        return status
    log.info("Successfully Injected RSA key pair.")
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


def parse_in_args():
    # Check whether an ip_address:port of the socket server was passed as argument
    if len(sys.argv) >= 2:
        connection_data = sys.argv[1]
        if connection_data.find('COM') < 0:
            port_data = connection_data.split(':')
            JRCP_HOSTNAME = port_data[0]
            try:
                JRCP_PORT = port_data[1]
            except IndexError as exc:
                log.error("Please specify jrcp port.")
                log.info("Usage Example:")
                log.info("               python %s 127.0.0.1:8050" % (__file__,))
                return None, None

            os.environ['JRCP_HOSTNAME'] = JRCP_HOSTNAME
            os.environ['JRCP_PORT'] = JRCP_PORT

            log.info("JRCP_HOSTNAME: %s" % JRCP_HOSTNAME)
            log.info("JRCP_PORT: %s" % JRCP_PORT)

            if len(sys.argv) >= 3:
                connection_type = sys.argv[2]
            else:
                connection_type = "jrcpv1"
        else:
            connection_type = "vcom"
    else:
        connection_data = ""
        connection_type = ""
    return connection_type, connection_data


def usage(connection_type):
    if connection_type == "jrcpv1":
        log.info("")
        log.info("If you want to connect to the simulator, specify jrcpv2")
        log.info("Usage Example:")
        log.info("               python %s 127.0.0.1:8050 jrcpv2" % (__file__,))
        log.info("")
        log.info("If you want to connect to the jrcpv1 server, check your ip address and connection.")
    if connection_type in ["t1oi2c", "sci2c"]:
        log.info("")
        log.info("Please provide as first argument:  CONNECTION_PARAMETER. Default: \"None\"")
        log.info("Please provide as second argument: CONNECTION_TYPE - vcom, jrcpv1, jrcpv2. "
                 "Specify only for jrcpv2")
        log.info("Usage Example:")
        log.info("               python %s" % (__file__,))
        log.info("               python %s COM5" % (__file__,))
        log.info("               python %s 127.0.0.1:8050" % (__file__,))
        log.info("               python %s 127.0.0.1:8050 jrcpv2" % (__file__,))


def main():
    cur_dir = os.path.abspath(os.path.dirname(__file__))
    py_sss_dir = os.path.join(cur_dir, '..', '..', '..', 'pycli', 'src')
    sys.path.append(py_sss_dir)
    import sss.connect as connect
    import sss.sss_api as apis

    # --------------------------------------------------------------
    # Start of program - Ensure an A71CH is connected to your system.
    # --------------------------------------------------------------
    log.info("SE050 Key provisioning script for OPC UA (Rev.%s)." % SE050_PROVISIONING_SCRIPT)
    log.info("Executing this script will insert keys in the attached SE050 secure element.")

    # Check whether an vcom port or ip_address:port of the socket server was passed as argument
    connection_type, connection_data = parse_in_args()
    if None in [connection_type, connection_data]:
        return

    keys_dir = os.path.join(cur_dir, '..', 'credentials') + os.sep

    # RSA keys to be stored in A71CH
    # ------------------------------
    server_key = keys_dir + "open62541_server_key_pair.pem"
    server_key_ref = keys_dir + "open62541_server_key_pair_ref.pem"
    server_cert = keys_dir + "open62541_server_cert.der"

    # close old session
    session_close(None)

    # Open a new session
    session = session_open(IOT_SE, connection_data, connection_type)
    if session is None:
        return

    # NOTE: In case of A71CH always issue reset
    # When SE050 is lacking storage / has conflicting storage issue a reset of the Secure Element
    reset(session)

    # Inject rsa pair key to the Secure Element
    status = set_rsa_pair(session, KEYPAIR_INDEX_SERVER_PRIVATE, server_key)
    if status != apis.kStatus_SSS_Success:
        return

    # Generate Reference key from the key injected. Store it in file referred by "server_key_ref" variable.
    status = refpem_rsa(session, KEYPAIR_INDEX_SERVER_PRIVATE, server_key_ref)
    if status != apis.kStatus_SSS_Success:
        return

    # Inject certificate to the Secure Element
    status = set_cert(session, CERTIFICATE_INDEX, server_cert)
    if status != apis.kStatus_SSS_Success:
        return

    session_close(session)
    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program Completed Successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
