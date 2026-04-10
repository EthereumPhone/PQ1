#
# Copyright 2019,2020,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

import subprocess
import sys
import logging
import time

logging.basicConfig(format='%(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)

try:
    from subprocess import CREATE_NEW_CONSOLE
except:
    log.info("Test script is supported only on windows")
    sys.exit(1)

from util import *

cipher_types = [
    "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256",
    "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384",
    "TLS-ECDHE-ECDSA-WITH-AES-256-CCM",
    "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384",
    "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA",
    "TLS-ECDHE-ECDSA-WITH-AES-256-CCM",
    "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-GCM-SHA384",
    "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA384",
    "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256",
    "TLS-ECDHE-ECDSA-WITH-AES-128-CCM",
    "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256",
    "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA",
    "TLS-ECDHE-ECDSA-WITH-AES-128-CCM",
    "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-GCM-SHA256",
    "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256",
    #"TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA", #3DES ciphetsuites disabled in mbedtls 2.16
    "TLS-ECDH-ECDSA-WITH-AES-256-GCM-SHA384",
    "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA384",
    "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA",
    "TLS-ECDH-ECDSA-WITH-CAMELLIA-256-GCM-SHA384",
    "TLS-ECDH-ECDSA-WITH-CAMELLIA-256-CBC-SHA384",
    "TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256",
    "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256",
    "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA",
    "TLS-ECDH-ECDSA-WITH-CAMELLIA-128-GCM-SHA256",
    "TLS-ECDH-ECDSA-WITH-CAMELLIA-128-CBC-SHA256",
    #"TLS-ECDH-ECDSA-WITH-3DES-EDE-CBC-SHA", #3DES ciphetsuites disabled in mbedtls 2.16
]

error_cnt = {"prime192v1": 0, "secp224r1": 0, "prime256v1": 0, "secp384r1": 0, "secp521r1": 0, "brainpoolP256r1": 0,
             "brainpoolP384r1": 0, "brainpoolP512r1": 0, "secp192k1": 0, "secp224k1": 0, "secp256k1": 0}
success_cnt = {"prime192v1": 0, "secp224r1": 0, "prime256v1": 0, "secp384r1": 0, "secp521r1": 0, "brainpoolP256r1": 0,
               "brainpoolP384r1": 0, "brainpoolP512r1": 0, "secp192k1": 0, "secp224k1": 0, "secp256k1": 0}
na_cnt = {"prime192v1": 0, "secp224r1": 0, "prime256v1": 0, "secp384r1": 0, "secp521r1": 0, "brainpoolP256r1": 0,
          "brainpoolP384r1": 0, "brainpoolP512r1": 0, "secp192k1": 0, "secp224k1": 0, "secp256k1": 0}


def doTest(arguments, name, log_file_name=__file__):
    ecc_in_type = arguments[1]
    connection_type = arguments[2]
    connection_param = arguments[3]
    iot_se = arguments[4]
    auth_type = "None"
    if len(arguments) > 5:
        auth_type = arguments[5]
    auth_key = "None"
    if len(arguments) > 6:
        auth_key = arguments[6]

    ecc_type_found = 0
    for ecc_type in ecc_types_cryptography_44:
        if ecc_in_type == ecc_type:
            ecc_type_found = 1
            break

    if ecc_in_type == 'all':
        ecc_type_found = 1

    if ecc_type_found == 0:
        return 1

    if connection_type != "jrcpv2" and connection_type != "vcom":
        log.info("connection_type not supported in this script")
        return 1

    # Remove file extension
    if log_file_name[-3:] == ".py":
        log_file_name = log_file_name[:-3]

    logFile = open('%s_results.txt' % (log_file_name,), 'wb')

    for ec_type in ecc_types_cryptography_44:
        if ecc_in_type != "all":
            if ec_type != ecc_in_type:
                continue

        if ec_type == "all":
            continue

        log.info("PROVISION FOR ------ %s" % ec_type)

        #prov_cmd = "windowsProvisionEC.bat," + ec_type + " " + connection_type + " " + connection_param + " " + iot_se
        prov_cmd = "python create_and_provision_ecc_keys.py " + ec_type + " " + connection_type + " " + connection_param + " " + iot_se + " " + auth_type + " " + auth_key
        log.info("%s" % prov_cmd)
        p = subprocess.Popen(prov_cmd, shell=True, stdout=subprocess.PIPE)
        stdout, stderr = p.communicate()

        log.info("STARTING TEST FOR ------ %s" % ec_type)

        log.info("STARTING SERVER WITH %s" % ec_type)
        log.info("\n")
        #ser = subprocess.Popen(("start_%s_server.bat" % (name,), ec_type), creationflags=CREATE_NEW_CONSOLE)
        ser = subprocess.Popen(("python start_%s_server.py %s" % (name, ec_type)), creationflags=CREATE_NEW_CONSOLE)

        time.sleep(3)
        error_cnt[ec_type] = 0
        success_cnt[ec_type] = 0
        na_cnt[ec_type] = 0

        for cipher in cipher_types:
            is_rsa = 0
            str_res = cipher.find("RSA")
            if str_res != -1:
                result_msg = "TEST(" + ec_type + ", " + cipher + ") IGNORE"
                log.info(result_msg)
                logFile.write(str.encode(result_msg))
                logFile.write(str.encode("\n"))
                na_cnt[ec_type] = na_cnt[ec_type] + 1
                continue

            #output = subprocess.Popen(("start_%s_client.bat" % (name,), ec_type, cipher, connection_param),stdout=subprocess.PIPE).stdout
            output = subprocess.Popen(("python start_%s_client.py %s %s %s" % (name, ec_type, cipher, connection_param)),stdout=subprocess.PIPE).stdout

            substr_found = 0
            nvm_write = 0
            for line in output:
                #log.info("%s", line)
                str_res = line.find(str.encode("200 OK"))
                if str_res != -1:
                    substr_found = 1
                str_res = line.find(str.encode("NVM write not expected"))
                if str_res != -1:
                    nvm_write = 1

            if nvm_write == 1:
                substr_found = 0

            if substr_found == 1:
                result_msg = "TEST(" + ec_type + ", " + cipher + ") PASS"
                log.info(result_msg)
                success_cnt[ec_type] = success_cnt[ec_type] + 1
            else:
                result_msg = "TEST(" + ec_type + ", " + cipher + ") FAIL"
                log.info(result_msg)
                error_cnt[ec_type] = error_cnt[ec_type] + 1

            logFile.write(str.encode(result_msg))
            logFile.write(str.encode("\n"))

            output.close()
        log.info("Stop server ...")
        log.info("\n\n")
        temp = subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=ser.pid), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                shell=True,
                                )
        std_out, std_err = temp.communicate()
        std_out = std_out.strip()
        std_err = std_err.strip()
        log.info("INFO:  std_out: %s" % bytes.decode(std_out))
        log.error("ERROR: std_err: %s" % bytes.decode(std_err))

    logFile.close()

    log.info("*************** RESULT ****************")
    for ec_type in ecc_types_cryptography_44:
        log.info("RESULT for %s" % ec_type)
        log.info("%s : Not Applicable" % na_cnt[ec_type])
        log.info("%s : SUCCESS" % success_cnt[ec_type])
        log.info("%s : ERROR" % error_cnt[ec_type])
        log.info("\n\n")
    log.info("***************************************")
    return 0
