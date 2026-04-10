#
# Copyright 2019,2020 NXP
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


def doTest(arguments):
    connection_type = arguments[1]
    connection_param = arguments[2]
    root_ca = arguments[3]


    logFile = open('opcua_results.txt', 'wb')
    opcua_with_rootca = "NOT TESTED"
    opcua_without_rootca = "NOT TESTED"

    log.info("******* CREATE CREDENTIALS *******" )
    create_cert = "python3 createOPCUACredentials_Optional.py "
    log.info("%s" % create_cert)
    p = subprocess.Popen(create_cert, shell=True, stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()

    time.sleep(3)
    log.info("\n")
    log.info("******* OPCUA PROVISION *******" )
    prov_cmd = "python3 provisionOPCUAServer.py " + connection_param + " " + connection_type
    log.info("%s" % prov_cmd)
    p = subprocess.Popen(prov_cmd, shell=True, stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()


    # TEST OPC UA WITH ROOT CA
    time.sleep(3)
    log.info("\n")
    srv_cmd = "python3 open62541Server.py " + connection_type + " " + connection_param + " " + root_ca
    log.info("%s" % srv_cmd)
    ser = subprocess.Popen(("python3 open62541Server.py %s %s %s" % (connection_type, connection_param, root_ca)), creationflags=CREATE_NEW_CONSOLE)

    log.info("Starting Client")
    time.sleep(3)
    log.info("\n")
    output = subprocess.Popen(("python3 open62541Client.py opc.tcp://127.0.0.1:4840"),stdout=subprocess.PIPE).stdout
    time.sleep(3)
    log.info("\n")

    substr_found = 0
    for line in output:
        log.info("%s", line)
        str_res = line.find(str.encode("Connected!"))
        if str_res != -1:
            substr_found = 1

    if substr_found == 1:
        result_msg = "TEST(OPCUA, open62541_with_root_ca) PASS"
        log.info(result_msg)
        opcua_with_rootca = "PASS"
    else:
        result_msg = "TEST(OPCUA, open62541_with_root_ca) FAIL"
        log.info(result_msg)
        opcua_with_rootca = "FAIL"

    logFile.write(str.encode(result_msg))
    logFile.write(str.encode("\n"))

    output.close()
    log.info("Stop server ...")
    log.info("\n\n")
    temp = subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=ser.pid), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True,
                            )
    #std_out, std_err = temp.communicate()
    #std_out = std_out.strip()
    #std_err = std_err.strip()
    #log.info("INFO:  std_out: %s" % bytes.decode(std_out))
    #log.error("ERROR: std_err: %s" % bytes.decode(std_err))
    time.sleep(3)
    log.info("\n")



    # TEST OPC UA WITHOUT ROOT CA
    time.sleep(3)
    log.info("\n")
    srv_cmd = "python3 open62541Server.py " + connection_type + " " + connection_param
    log.info("%s" % srv_cmd)
    ser = subprocess.Popen(("python3 open62541Server.py %s %s %s" % (connection_type, connection_param, root_ca)), creationflags=CREATE_NEW_CONSOLE)

    log.info("Starting Client")
    time.sleep(3)
    log.info("\n")
    output = subprocess.Popen(("python3 open62541Client.py opc.tcp://127.0.0.1:4840"),stdout=subprocess.PIPE).stdout
    time.sleep(3)
    log.info("\n")

    substr_found = 0
    for line in output:
        log.info("%s", line)
        str_res = line.find(str.encode("Connected!"))
        if str_res != -1:
            substr_found = 1

    if substr_found == 1:
        result_msg = "TEST(OPCUA, open62541_without_root_ca) PASS"
        log.info(result_msg)
        opcua_without_rootca = "PASS"
    else:
        result_msg = "TEST(OPCUA, open62541_without_root_ca) FAIL"
        log.info(result_msg)
        opcua_without_rootca = "FAIL"

    logFile.write(str.encode(result_msg))
    logFile.write(str.encode("\n"))

    output.close()
    log.info("Stop server ...")
    log.info("\n\n")
    temp = subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=ser.pid), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True,
                            )
    #std_out, std_err = temp.communicate()
    #std_out = std_out.strip()
    #std_err = std_err.strip()
    #log.info("INFO:  std_out: %s" % bytes.decode(std_out))
    #log.error("ERROR: std_err: %s" % bytes.decode(std_err))


    logFile.close()


    log.info("*************** RESULT ****************")
    log.info("OPC UA WITH ROOT CA ------- %s" %opcua_with_rootca)
    log.info("OPC UA WITHOUT ROOT CA ---- %s" %opcua_without_rootca)
    log.info("***************************************")
    return 0


def printUsage():
    print('Invalid input argument')
    print('Run as -  test_opcua.py <jrcpv2|vcom> <ip_address|port_name> <root_ca>')
    print('Example invocation - test_opcua.py jrcpv2 127.0.0.1:8050 ..\\credentials\\open62541_client_cert.der')
    sys.exit()


if len(sys.argv) != 4:
    printUsage()
else:
    if doTest(sys.argv) != 0:
        printUsage()
