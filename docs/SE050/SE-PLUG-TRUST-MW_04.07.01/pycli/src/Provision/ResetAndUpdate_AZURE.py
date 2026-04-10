#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#


# This script is used to provision key and certificate to secure element.
# These Provisioned keys and certificates are used in azure demo

from .Provision_util import *
from . import cloud_credentials


def reset_and_update(cur_dir, keypair_index_private, certificate_index):

    # Session Open
    session_obj = session_open()

    # Read UID from the device
    SE_UID = get_unique_id(session_obj)
    if SE_UID is None or SE_UID == 0:
        return STATUS_FAIL

    INPUT_DIR = cur_dir + os.sep + "azure" + os.sep

    credentials = cloud_credentials.create_credentials(SE_UID)

    ecc_key_pair_file = INPUT_DIR + credentials["DEVICE_KEY"]
    certificate_file = INPUT_DIR + credentials["DEVICE_CERT"]
    refpem_file = INPUT_DIR + credentials["DEVICE_REF_KEY"]

    if not os.path.isfile(certificate_file):
        log.info("Certificates not created\nRun GenerateAZURECredentials.py to create certificates")
        return STATUS_FAIL

    # Reset the Secure Element
    reset(session_obj)

    # Inject ECC key Pair
    status = set_ecc_pair(session_obj, keypair_index_private, ecc_key_pair_file)
    if status != apis.kStatus_SSS_Success:
        return STATUS_FAIL

    # Inject Certificate
    status = set_cert(session_obj, certificate_index, certificate_file)
    if status != apis.kStatus_SSS_Success:
        return STATUS_FAIL

    # Create Reference key
    status = refpem_ecc(session_obj, keypair_index_private, refpem_file)
    if status != apis.kStatus_SSS_Success:
        return STATUS_FAIL
    else:
        session_close(session_obj)
        log.info("##############################################################")
        log.info("#                                                            #")
        log.info("#     Program Completed Successfully                         #")
        log.info("#                                                            #")
        log.info("##############################################################")
        return STATUS_SUCCESS
