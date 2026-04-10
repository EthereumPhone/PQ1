#
# Copyright 2018-2020,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

"""

Provision attached secure element with ECC/RSA keys

Preconditions:
    - Secure element attached
    - Virtual environment should be activated (not for iMX platform.
      Refer ssscli installation steps: Plug & Trust MW, Section 8.3 :ref:`cli-doc-pre-steps`)

Postconditions:
    - Key pair injected on id referred by KEYPAIR_INDEX_CLIENT_PRIVATE variable
    - Ref pem created
    - Client certificate injected on id referred by CERTIFICATE_INDEX variable.

"""

import os
import sys
import logging
import traceback
import argparse
logging.basicConfig(format='%(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)

# GLOBAL VARIABLES
# ----------------
SE050_PROVISIONING_SCRIPT = "0.9"
EC_KEYPAIR_INDEX_CLIENT_PRIVATE = 0x7DCCBB10
EC_CERTIFICATE_INDEX = 0x7DCCBB11
RSA_KEYPAIR_INDEX_CLIENT_PRIVATE = 0x7DCCBB30
RSA_CERTIFICATE_INDEX = 0x7DCCBB31

example_text = '''
Example invocation::

    python %s --key_type ecc
    python %s --key_type ecc --connection_data 169.254.0.1:8050
    python %s --key_type rsa --connection_data 127.0.0.1:8050 --connection_type jrcpv2
    python %s --key_type rsa --connection_data COM3

''' % (__file__, __file__, __file__, __file__,)

SUPPORTED_CONNECTION_TYPES = [
    "t1oi2c",
    "sci2c",
    "vcom",
    "jrcpv1",
    "jrcpv2",
    "pcsc"
]


def session_open(subsystem, connection_data, connection_type, auth_type, scpkey):
    ''' Open session based on IOT Secure Element selected. '''
    import sss.const as const
    import sss.connect as connect
    import sss.session as session

    log.info("###############################################################")
    log.info("#")
    log.info("#     SUBSYSTEM            : %s" % subsystem)
    log.info("#     CONNECTION_TYPE      : %s" % connection_type)
    log.info("#     CONNECTION_PARAMETER : %s" % connection_data)
    log.info("#")
    log.info("###############################################################")

    connect.do_open_session(const.SUBSYSTEM_TYPE[subsystem],
                            const.CONNECTION_TYPE[connection_type], connection_data,
                            auth_type=const.AUTH_TYPE_MAP[auth_type][0],
                            scpkey=scpkey)
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


def refpem_ecc(session, keyid, file_name):
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
        log.error("Refpem creation failed..!")
        session_close(session)
        return status
    log.info("Successfully Created reference key.")
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
        log.error("Injecting key pair failed..!")
        session_close(session)
        return status
    log.info("Successfully Injected ECC key pair.")
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

    parser = argparse.ArgumentParser(description=__doc__,
                                     epilog=example_text,
                                     formatter_class=argparse.RawTextHelpFormatter)
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    required.add_argument('--key_type', default="",
                          help='Supported key types => ``ecc``, ``rsa``',
                          required=True)
    optional.add_argument('--connection_data', default="none",
                          help='Parameter to connect to SE => eg. ``COM3``, ``127.0.0.1:8050``, ``none``. '
                               'Default: ``none``')
    optional.add_argument('--connection_type', default="t1oi2c",
                          help='Supported connection types => ``%s``. Default: ``t1oi2c``' %
                               ("``, ``".join(SUPPORTED_CONNECTION_TYPES)))
    optional.add_argument('--subsystem', default="se05x",
                          help='Supported subsystem => ``se05x``. Default: ``se05x``')
    optional.add_argument('--auth_type', default="None",
                          help='Supported subsystem => ``None``, ``PlatformSCP``, ``UserID``, ``ECKey``, ``AESKey``. Default: ``None``')
    optional.add_argument('--scpkey', default="None",
                          help='')
    optional.add_argument('--no_reset', action="store_true", help="do not reset contents of attached secure element")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return None

    args = parser.parse_args()

    if args.key_type not in ["ecc", "rsa", ]:
        parser.print_help(sys.stderr)
        return None

    if args.subsystem not in ["se05x"]:
        parser.print_help(sys.stderr)
        return None

    if args.connection_data.find(':') >= 0:
        port_data = args.connection_data.split(':')
        jrcp_host_name = port_data[0]
        jrcp_port = port_data[1]
        os.environ['JRCP_HOSTNAME'] = jrcp_host_name
        os.environ['JRCP_PORT'] = jrcp_port
        log.info("JRCP_HOSTNAME: %s" % jrcp_host_name)
        log.info("JRCP_PORT: %s" % jrcp_port)
        if args.connection_type == "t1oi2c":
            args.connection_type = "jrcpv1"
    elif args.connection_data.find('COM') >= 0:
        if args.connection_type == "t1oi2c":
            args.connection_type = "vcom"

    if args.connection_type not in SUPPORTED_CONNECTION_TYPES:
        parser.print_help(sys.stderr)
        return None

    return args


def main():
    cur_dir = os.path.abspath(os.path.dirname(__file__))
    py_sss_dir = os.path.join(cur_dir, '..', '..', '..', '..', 'pycli', 'src')
    sys.path.append(py_sss_dir)
    import sss.sss_api as apis

    # check for input arguments
    args = parse_in_args()
    if args is None:
        return

    # --------------------------------------------------------------
    # Start of program - Ensure an SE is connected to your system.
    # --------------------------------------------------------------
    log.info("SE050 Key provisioning script (Rev.%s)." % SE050_PROVISIONING_SCRIPT)
    log.info("Executing this script will insert keys in the attached SE050 secure element.")

    if args.key_type == "ecc":
        key_type = "prime256v1"
    else:
        key_type = "RSA"
    keys_dir = os.path.join(cur_dir, '..', 'credentials', key_type) + os.sep

    # ECC keys to be stored in SE
    # ------------------------------
    client_key = keys_dir + "tls_client_key.pem"
    client_key_ref = keys_dir + "tls_client_key_ref.pem"
    client_key_pub = keys_dir + "tls_client_key_pub.pem"  # Contains public key only

    # Client certificate
    client_cer = keys_dir + "tls_client.cer"

    # close old session
    session_close(None)

    # Open a new session
    session = session_open(args.subsystem, args.connection_data, args.connection_type, args.auth_type, args.scpkey)
    if session is None:
        return

    # When SE050 is lacking storage / has conflicting storage issue a reset of the Secure Element
    if not args.no_reset:
        reset(session)

    if key_type == "prime256v1":
        # Inject ecc pair key to the Secure Element
        status = set_ecc_pair(session, EC_KEYPAIR_INDEX_CLIENT_PRIVATE, client_key)
        if status != apis.kStatus_SSS_Success:
            return

        # Generate Reference key from the key injected. Store it in file referred by "client_key_ref" variable.
        status = refpem_ecc(session, EC_KEYPAIR_INDEX_CLIENT_PRIVATE, client_key_ref)
        if status != apis.kStatus_SSS_Success:
            return

        key_id_cert = EC_CERTIFICATE_INDEX

    else:
        # Inject rsa key pair into the Secure Element
        status = set_rsa_pair(session, RSA_KEYPAIR_INDEX_CLIENT_PRIVATE, client_key)
        if status != apis.kStatus_SSS_Success:
            return

        # Generate Reference key from the key injected. Store it in file referred by "client_key_ref" variable.
        status = refpem_rsa(session, RSA_KEYPAIR_INDEX_CLIENT_PRIVATE, client_key_ref)
        if status != apis.kStatus_SSS_Success:
            return

        key_id_cert = RSA_CERTIFICATE_INDEX

    # Inject certificate to the Secure Element
    status = set_cert(session, key_id_cert, client_cer)
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


