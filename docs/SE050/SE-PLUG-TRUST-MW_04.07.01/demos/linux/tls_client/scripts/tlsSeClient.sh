#!/bin/bash
#
# Copyright 2019,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#

# History
#
# 2019-09-11: Environment variable REQ_SE can be set to overrule default se050 (choose either se050 or a71ch)
# 2019-09-10: Environment variable REQ_TLS can be set to overrule default tls1_2 (choose either tls1_2 or tls1_3)
# 2019-09-05: Removed ECDH cipher request as this is no longer supported by OpenSSL 1.1.1
# 2019-09-04: Added RSA capability
# 

OPENSSL="openssl"
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
openssl_version="$(openssl version | grep -o "OpenSSL [0-9].[0-9]")"
if [ "${openssl_version}" == "OpenSSL 1.0" ]; then
    echo "Using config file prepared for ${openssl_version}"
    OPENSSL_CONF_SE=../../common/openssl_sss_${IOT_SE}.cnf
elif [ "${openssl_version}" == "OpenSSL 1.1" ]; then
    echo "Using config file prepared for OpenSSL 1.1.1c"
    OPENSSL_CONF_SE=../../common/openssl11_sss_${IOT_SE}.cnf
else
    echo "Don't recognise OpenSSL version ${openssl_version}. Using config file prepared for OpenSSL 1.1.1"
    OPENSSL_CONF_SE=../../common/openssl11_sss_${IOT_SE}.cnf
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

# Check whether available openssl supports TLS 1.3
openssl_version_x_x_x="$(openssl version | grep -o "OpenSSL [0-9].[0-9].[0-9]")"
if [ "${openssl_version_x_x_x}" != "OpenSSL 1.1.1" ]; then
    if [[ ${TLS_OPTION} == "tls1_3" ]]; then
        echo "TLS_OPTION: ${TLS_OPTION} is not support for this version of OpenSSL (${openssl_version_x_x_x})"
        exit 6
    fi
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

if [ "${KEY_TYPE}" == "${EC_KEY_TYPE}" ]; then
    echo "Client key pair = EC ${KEY_TYPE}"
    echo "Request ${sel_cipher}"
elif [ "${KEY_TYPE}" == "RSA" ]; then
    echo "Client key pair = ${KEY_TYPE}"
else
    echo "Inspect value of KEY_TYPE: ${KEY_TYPE}"
    exit 6
fi

KEY_DIR=../credentials/${KEY_TYPE}
rootca_cer="${KEY_DIR}/tls_rootca.cer"
client_cer="${KEY_DIR}/tls_client.cer"
client_key="${KEY_DIR}/tls_client_key_ref.pem"

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
