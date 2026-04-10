#!/bin/bash
#
# Copyright 2019,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
#
# SE050 Extended TLS Client Example
#
# Preconditions
# - SE050 attached (further details to be worked out)
# - ../build/tlsSe050Client available
# - s_server up and running
#
# Postconditions (to be updated)
# -
#

# History
#
# 2019-09-11: Environment variable REQ_SE can be set to overrule default se050 (choose either se050 or a71ch)
#

# GLOBAL VARIABLES
# ----------------
SE050_TLS_EXTENDED_SE_SCRIPT="0.9"
IOT_SE=se050
USE_KEY_LABEL=0

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
CLIENT_APP="../build/tlsSe050Client"
# Check whether an ip_address:port of the socket server was passed as argument
if [ -z "$3" ]; then
    ip_addr_port_server=""
else
    ip_addr_port_server="$3"
    export JRCP_SERVER_SOCKET=${ip_addr_port_server}
    export JRCP_HOSTNAME=${ip_addr_port_server%:*} # Back delete
    export JRCP_PORT=${ip_addr_port_server#*:} # Front delete
    export EX_SSS_BOOT_SSS_PORT=${ip_addr_port_server}
fi

echo ${JRCP_HOSTNAME}
echo ${JRCP_PORT}

# Cd to directory where script is stored
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo ${SCRIPT_DIR}
cd ${SCRIPT_DIR}

# The Secure Element used by the OpenSSL engine can be overruled by setting
# environment variable REQ_SE.
# By default se050 is assumed
if [[ -z "${REQ_SE}" ]]; then
  IOT_SE="se050"
else
  IOT_SE="${REQ_SE}"
fi

# Catch IOT_SE values we don't know about
case ${IOT_SE} in
    se050)
        echo "IOT_SE=${IOT_SE}"
        ;;
    *)
        echo "Unknown/unsupported secure element: ${IOT_SE}"
        exit 3
        ;;
esac


# Select config file based on OpenSSL version and Secure Element
openssl_version="$(openssl version | grep -o "OpenSSL [0-9].[0-9]" | head -1)"
if [ "${openssl_version}" == "OpenSSL 1.0" ]; then
    echo "Using config file prepared for ${openssl_version}"
    OPENSSL_CONF_SE=../../common/openssl_sss_${IOT_SE}.cnf
elif [ "${openssl_version}" == "OpenSSL 1.1" ]; then
    echo "Using config file prepared for OpenSSL 1.1.1c"
    OPENSSL_CONF_SE=../../common/openssl11_sss_${IOT_SE}.cnf
elif [ "${openssl_version}" == "OpenSSL 3.0" ]; then
    echo "Config file is loaded in C example"
else
    echo "Don't recognise OpenSSL version ${openssl_version}. Using config file prepared for OpenSSL 1.1.1"
    OPENSSL_CONF_SE=../../common/openssl11_sss_${IOT_SE}.cnf
fi

# Halt execution if config file does not exist
if [ ! -f ${OPENSSL_CONF_SE} ]; then
    echo "Cannot open ${OPENSSL_CONF_SE}: fatal error"
    exit -1
fi

EC_KEY_TYPE=prime256v1

if [ $# -lt 2 ]; then
    echo "Usage: tlsExtendedSeClient.sh <ip-address> <EC|RSA>"
    echo "Provide the ip address of the server you want to connect to as first argument!"
    echo "Additional argument selects between EC or RSA prepared credentials"
    echo "   Eg. tlsExtendedSeClient.sh 192.168.1.42 EC"
    echo "   Eg. tlsExtendedSeClient.sh 192.168.1.60 RSA"
    exit 1
elif [ "${2}" == "EC" ]; then
    KEY_TYPE=${EC_KEY_TYPE}
    KEY_CLASS=${2}
elif [ "${2}" == "RSA" ]; then
    sel_cipher="-cipher ECDHE-ECDSA-AES128-SHA256"
    KEY_TYPE=RSA
    KEY_CLASS=${2}
else
    echo "Usage: tlsExtendedSeClient.sh <ip-address> <EC|RSA>"
    exit 4
fi


KEY_DIR=../credentials/${KEY_TYPE}
rootca_cer="${KEY_DIR}/tls_rootca.cer"
client_cer="${KEY_DIR}/tls_client.cer"

if [ "${openssl_version}" != "OpenSSL 3.0" ]; then
    client_key="${KEY_DIR}/tls_client_key_ref.pem"
else
    if [ "${USE_KEY_LABEL}" == "1" ]; then
        if [ "${2}" == "RSA" ]; then
            echo "Using key label"
            client_key="nxp:0x7DCCBB30"
        else
            echo "Using key label"
            client_key="nxp:0x7DCCBB10"
        fi
    else
        echo "Using reference key"
        client_key="nxp:${KEY_DIR}/tls_client_key_ref.pem"
    fi
fi

echo "Connecting to ${1}:8080"

# ./tlsSe050Client <ipAddress:port> <EC|RSA> <caCert.pem> <clientKey.pem|clientKeyRef.pem> [<clientCert.pem>]

if [ "${openssl_version}" != "OpenSSL 3.0" ]; then
    echo "Configure to use embSeEngine"
    export OPENSSL_CONF=${OPENSSL_CONF_SE}
    echo "OPENSSL_CONF=${OPENSSL_CONF}"
fi
# Client certificate filename is passed as argument
# execCommand "${CLIENT_APP} ${1}:8080 ${KEY_CLASS} ${rootca_cer} ${client_key} ${client_cer}"
# Retrieve client certificate from SE
execCommand "${CLIENT_APP} ${1}:8080 ${KEY_CLASS} ${rootca_cer} ${client_key}"

