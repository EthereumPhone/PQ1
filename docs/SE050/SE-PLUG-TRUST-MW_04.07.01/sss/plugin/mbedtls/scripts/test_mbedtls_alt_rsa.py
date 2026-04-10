#
# Copyright 2019 NXP
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
    "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256",
    "TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256",
    "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384",
    "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384",
    "TLS-DHE-RSA-WITH-AES-256-CCM",
    "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384",
    "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256",
    "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA",
    "TLS-DHE-RSA-WITH-AES-256-CBC-SHA",
    "TLS-DHE-RSA-WITH-AES-256-CCM",
    "TLS-ECDHE-RSA-WITH-CAMELLIA-256-GCM-SHA384",
    "TLS-DHE-RSA-WITH-CAMELLIA-256-GCM-SHA384",
    "TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA384",
    "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256",
    "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA",
    "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256",
    "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256",
    "TLS-DHE-RSA-WITH-AES-128-CCM",
    "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256",
    "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256",
    "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA",
    "TLS-DHE-RSA-WITH-AES-128-CBC-SHA",
    "TLS-DHE-RSA-WITH-AES-128-CCM",
    "TLS-ECDHE-RSA-WITH-CAMELLIA-128-GCM-SHA256",
    "TLS-DHE-RSA-WITH-CAMELLIA-128-GCM-SHA256",
    "TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256",
    "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256",
    "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA",
    #"TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA", #3DES ciphetsuites disabled in mbedtls 2.16
    #"TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA", #3DES ciphetsuites disabled in mbedtls 2.16
    "TLS-RSA-WITH-AES-256-GCM-SHA384",
    "TLS-RSA-WITH-AES-256-CCM",
    "TLS-RSA-WITH-AES-256-CBC-SHA256",
    "TLS-RSA-WITH-AES-256-CBC-SHA",
    "TLS-RSA-WITH-AES-256-CCM",
    "TLS-RSA-WITH-CAMELLIA-256-GCM-SHA384",
    "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256",
    "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA",
    "TLS-RSA-WITH-AES-128-GCM-SHA256",
    "TLS-RSA-WITH-AES-128-CCM",
    "TLS-RSA-WITH-AES-128-CBC-SHA256",
    "TLS-RSA-WITH-AES-128-CBC-SHA",
    "TLS-RSA-WITH-AES-128-CCM",
    "TLS-RSA-WITH-CAMELLIA-128-GCM-SHA256",
    "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256",
    "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA",
    #"TLS-RSA-WITH-3DES-EDE-CBC-SHA", #3DES ciphetsuites disabled in mbedtls 2.16
]


error_cnt = {"rsa2048": 0, "rsa3072": 0, "rsa4096": 0, }
success_cnt = {"rsa2048": 0, "rsa3072": 0, "rsa4096": 0, }
na_cnt = {"rsa2048": 0, "rsa3072": 0, "rsa4096": 0, }


def doTest(arguments, name, log_file_name=__file__):
    rsa_in_type = arguments[1]
    connection_type = arguments[2]
    connection_param = arguments[3]
    auth_type = "None"
    if len(arguments) > 4:
        auth_type = arguments[4]
    auth_key = "None"
    if len(arguments) > 5:
        auth_key = arguments[5]

    rsa_type_found = 0
    for rsa_type in rsa_types:
        if rsa_in_type == rsa_type:
            rsa_type_found = 1
            break

    if rsa_in_type == "all":
        rsa_type_found = 1

    if rsa_type_found == 0:
        return 1

    if connection_type != "jrcpv2" and connection_type != "vcom":
        return 1

    # Remove file extension
    if log_file_name[-3:] == ".py":
        log_file_name = log_file_name[:-3]

    logFile = open("%s_results.txt" % (log_file_name,), 'wb')

    for rsa_type in rsa_types:
        if rsa_in_type != "all":
            if rsa_type != rsa_in_type:
                continue

        if rsa_type == "all":
            continue

        log.info("PROVISION FOR ------ %s" % rsa_type)
        #prov_cmd = 'windowsProvisionRSA.bat,' + rsa_type + ' ' + connection_type + ' ' + connection_param
        prov_cmd = 'python create_and_provision_rsa_keys.py ' + rsa_type + ' ' + connection_type + ' ' + connection_param + ' ' + auth_type + ' ' + auth_key
        p = subprocess.Popen(prov_cmd, shell=True, stdout=subprocess.PIPE)
        stdout, stderr = p.communicate()

        log.info("STARTING TEST FOR ------ %s" % rsa_type)

        log.info("STARTING SERVER WITH %s" % rsa_type)
        log.info("\n")
        #ser = subprocess.Popen( ("start_%s_server.bat" % (name,), rsa_type), creationflags=CREATE_NEW_CONSOLE)
        ser = subprocess.Popen( ("python start_%s_server.py %s" %(name, rsa_type)), creationflags=CREATE_NEW_CONSOLE)
        time.sleep(3)

        error_cnt[rsa_type] = 0
        success_cnt[rsa_type] = 0
        na_cnt[rsa_type] = 0

        for cipher in cipher_types:
            is_rsa = 0
            str_res = cipher.find("ECDSA")
            if str_res != -1:
                result_msg = "TEST(" + rsa_type + ", " + cipher + ") IGNORE"
                log.info(result_msg)
                logFile.write(result_msg)
                logFile.write(str.encode("\n"))
                na_cnt[rsa_type] = na_cnt[rsa_type] + 1
                continue

            #output = subprocess.Popen(("start_%s_client.bat" % (name,), rsa_type, cipher, connection_param),stdout=subprocess.PIPE).stdout
            output = subprocess.Popen(("python start_%s_client.py %s %s %s" % (name, rsa_type, cipher, connection_param)),stdout=subprocess.PIPE).stdout

            substr_found = 0
            nvm_write = 0
            for line in output:
                str_res = line.find(str.encode("200 OK"))
                if str_res != -1:
                    substr_found = 1
                str_res = line.find(str.encode("NVM write not expected"))
                if str_res != -1:
                    nvm_write = 1

            if nvm_write == 1:
                substr_found = 0

            if substr_found == 1:
                result_msg = "TEST(" + rsa_type + ", " + cipher + ") PASS"
                log.info(result_msg)
                success_cnt[rsa_type] = success_cnt[rsa_type] + 1
            else:
                result_msg = "TEST(" + rsa_type + ", " + cipher + ") FAIL"
                log.info(result_msg)
                error_cnt[rsa_type] = error_cnt[rsa_type] + 1

            logFile.write(str.encode(result_msg))
            logFile.write(str.encode("\n"))

            output.close()
        log.info("Stop server ...")
        log.info("\n\n")
        temp = subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=ser.pid), stdout=subprocess.PIPE).stdout
        temp.close()

    log.info("*************** RESULT ****************")
    for rsa_type in rsa_types:
        log.info("RESULT for %s" % rsa_type)
        log.info("%s : Not Applicable" % na_cnt[rsa_type])
        log.info("%s : SUCCESS" % success_cnt[rsa_type])
        log.info("%s : ERROR" % error_cnt[rsa_type])
        log.info("\n\n")
    log.info("***************************************")
    return 0
