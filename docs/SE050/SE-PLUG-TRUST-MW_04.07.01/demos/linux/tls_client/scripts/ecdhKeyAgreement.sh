#!/bin/bash
# Copyright 2019 NXP
#
# NXP Confidential. This software is owned or controlled by NXP and may only
# be used strictly in accordance with the applicable license terms.  By
# expressly accepting such terms or by downloading, installing, activating
# and/or otherwise using the software, you are agreeing that you have read,
# and that you agree to comply with and are bound by, such license terms.  If
# you do not agree to be bound by the applicable license terms, then you may
# not retain, install, activate or otherwise use the software.
#
# NXP Internal test script
#
# Preconditions
# - SE050 attached (further details to be worked out)
# - ../build/ecdhKeyAgreement available
#
# Postconditions (to be updated)
# -
#

# GLOBAL VARIABLES
# ----------------
SE050_TLS_EXTENDED_SE_SCRIPT="0.9"
IOT_SE=se050

# UTILITY FUNCTIONS
# -----------------
# execCommand will stop script execution when the program executed did not return OK (i.e. 0) to the shell
execCommand () {
	local command="$*"
	echo ">> ${command}"
	${command}
	local nRetProc="$?"
	if [ ${nRetProc} -ne 0 ]
	then
		echo "\"${command}\" failed to run successfully, returned ${nRetProc}"
		exit 2
	fi
	echo ""
}

OPENSSL="openssl"
CLIENT_APP="../build/ecdhKeyAgreement"
# Check whether an ip_address:port of the socket server was passed as argument
if [ -z "$2" ]; then
    ip_addr_port_server=""
else
    ip_addr_port_server="$2"
    export JRCP_SERVER_SOCKET=${ip_addr_port_server}
    export JRCP_HOSTNAME=${ip_addr_port_server%:*} # Back delete
    export JRCP_PORT=${ip_addr_port_server#*:} # Front delete
fi

echo ${JRCP_HOSTNAME}
echo ${JRCP_PORT}

# Cd to directory where script is stored
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo ${SCRIPT_DIR}
cd ${SCRIPT_DIR}

OPENSSL_CONF_SE050=../../common/openssl_sss_se050.cnf
# Halt execution if file does not exist
if [ ! -f ${OPENSSL_CONF_SE050} ]; then
    echo "Cannot open ${OPENSSL_CONF_SE050}: fatal error"
    exit -1
fi

EC_KEY_TYPE=prime256v1
se050_ec_curve=NIST_P256

KEY_DIR=../credentials/${EC_KEY_TYPE}
rootca_cer="${KEY_DIR}/tls_rootca.cer"
client_cer="${KEY_DIR}/tls_client.cer"
client_key="${KEY_DIR}/tls_client_key_ref.pem"

# if [ $# -lt 1 ]; then
    # echo "Usage: ${0} <ip-address>"
	# echo "Provide the ip address of the server you want to connect to as first argument!"
	# exit 1
# fi

echo "Connecting to ${1}:8080"

# ./tlsSe050Client <ipAddress:port> <caCert.pem> <clientKey.pem|clientKeyRef.pem> [<clientCert.pem>]


echo "Configure to use embSeEngine"
export OPENSSL_CONF=${OPENSSL_CONF_SE050}
echo "OPENSSL_CONF=${OPENSSL_CONF}"
# Client certificate filename is passed as argument
# execCommand "${CLIENT_APP} ${1}:8080 ${rootca_cer} ${client_key} ${client_cer}"
# Retrieve client certificate from SE
execCommand "${CLIENT_APP}"

