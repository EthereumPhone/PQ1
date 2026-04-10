#!/bin/bash
#
# Copyright 2023,2024 NXP
# SPDX-License-Identifier: Apache-2.0
#
 
OPENSSL="openssl"
USE_KEY_LABEL=0
# Note: Tested with openssl version 3.0.8

# Check whether an ip_address:port of the socket server was passed as argument
if [ -z "$3" ]; then
    ip_addr_port_server=""
else
    ip_addr_port_server="$3"
    # export JRCP_SERVER_SOCKET=${ip_addr_port_server}
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


# Select config file based on OpenSSL version and Secure Element
openssl_version="$(openssl version | grep -o "OpenSSL [0-9].[0-9]")"
if [ "${openssl_version}" == "OpenSSL 1.0" ]; then
    echo "Error: Use openssl 3.0"
    exit 1
elif [ "${openssl_version}" == "OpenSSL 1.1" ]; then
    echo "Error: Use openssl 3.0"
    exit 1
elif [ "${openssl_version}" == "OpenSSL 3.0" ]; then
    echo "Error: Use openssl 3.0"
    OPENSSL_CONF_SE=../../common/openssl30_sss_se050.cnf
else
    echo "Don't recognise OpenSSL version ${openssl_version}. Using config file prepared for OpenSSL 3.0"
    OPENSSL_CONF_SE=../../common/openssl30_sss_se050.cnf
fi

# Halt execution if config file does not exist
if [ ! -f ${OPENSSL_CONF_SE} ]; then
    echo "Cannot open ${OPENSSL_CONF_SE}: fatal error"
    exit -1
fi

# The TLS version requested by the client can be overruled by setting
# environment variable REQ_TLS
if [[ -z "${REQ_TLS}" ]]; then
  TLS_OPTION="tls1_2"
else
  TLS_OPTION="${REQ_TLS}"
fi


EC_KEY_TYPE=prime256v1

if [ $# -lt 2 ]; then
    echo "Usage: tlsSeClient.sh <ip-address> <ECDHE|ECDHE_256|RSA>"
    echo "Provide the ip address of the server you want to connect to as first argument!"
    echo "Additional argument enforces ciphersuite and/or server key type pair"
    echo "   Eg. tlsSeClient.sh 192.168.1.42 ECDHE"
    echo "   Eg. tlsSeClient.sh 192.168.1.60 RSA"
    exit 1
elif [ "${2}" == "ECDHE" ]; then
    sel_cipher="-cipher ECDHE-ECDSA-AES128-SHA"
    KEY_TYPE=${EC_KEY_TYPE}
elif [ "${2}" == "ECDHE_256" ]; then
    sel_cipher="-cipher ECDHE-ECDSA-AES128-SHA256"
    KEY_TYPE=${EC_KEY_TYPE}
elif [ "${2}" == "RSA" ]; then
    sel_cipher=""
    KEY_TYPE=RSA
else
    echo "Usage: tlsSeClient.sh <ip-address> <ECDHE|ECDHE_256|RSA>"
    exit 4
fi

KEY_DIR=../credentials/${KEY_TYPE}

if [ "${KEY_TYPE}" == "${EC_KEY_TYPE}" ]; then
    if [ "${USE_KEY_LABEL}" == "1" ]; then
        echo "Using key label for EC_KEY_TYPE"
        client_key="nxp:0x7DCCBB10"
    else
        echo "Using reference key for EC_KEY_TYPE"
        client_key="nxp:${KEY_DIR}/tls_client_key_ref.pem"
    fi
    echo "Request ${sel_cipher}"
elif [ "${KEY_TYPE}" == "RSA" ]; then
    if [ "${USE_KEY_LABEL}" == "1" ]; then
        echo "Using key label for RSA"
        client_key="nxp:0x7DCCBB30"
    else
        echo "Using custom key for RSA"
        client_key="nxp:${KEY_DIR}/tls_client_key_ref.pem"
    fi
    echo "Request ${sel_cipher}"
else
    echo "Inspect value of KEY_TYPE: ${KEY_TYPE}"
    exit 6
fi

rootca_cer="${KEY_DIR}/tls_rootca.cer"
client_cer="${KEY_DIR}/tls_client.cer"

echo "Connecting to ${1}:8080... using client key pair of type ${KEY_TYPE}"
if [ "${KEY_TYPE}" == "${EC_KEY_TYPE}" ]; then
    echo "requesting cipher ${sel_cipher}"
fi

echo "    Requesting TLS of type ${TLS_OPTION}"

echo "Configure to use SSS based OpenSSL Engine"
export OPENSSL_CONF=${OPENSSL_CONF_SE}
echo "    OPENSSL_CONF=${OPENSSL_CONF}"

cmd="${OPENSSL} s_client -connect ${1}:8080 -${TLS_OPTION} \
 -CAfile ${rootca_cer} \
 -cert ${client_cer} -key ${client_key} \
 ${sel_cipher} -state -msg"
echo "${cmd}"
echo "****************************************************"

sleep 2
${cmd}
