#!/bin/bash
#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#

# History
# 
# 2019-09-05: Removed ECDH cipher request as this is no longer supported by OpenSSL 1.1.1
# 2019-09-04: Added RSA capability
# 

# Cd to directory where script is stored
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo ${SCRIPT_DIR}
cd ${SCRIPT_DIR}

EC_KEY_TYPE=prime256v1

if [ $# -ne 1 ]; then
    # Provide one and only one argument
    echo 'Usage: tlsServer.sh [ECDHE|ECDHE_SHA256|max|RSA]'
    exit 5
elif [ "${1}" == "ECDHE" ]; then
    sel_cipher="-cipher ECDHE-ECDSA-AES128-SHA"
    KEY_TYPE=${EC_KEY_TYPE}
elif [ "${1}" == "ECDHE_SHA256" ]; then
    sel_cipher="-cipher ECDHE-ECDSA-AES128-SHA256"
    KEY_TYPE=${EC_KEY_TYPE}
elif [ "${1}" == "max" ]; then
    sel_cipher="-cipher ECDHE-ECDSA-AES128-SHA,ECDHE-ECDSA-AES128-SHA256"
    KEY_TYPE=${EC_KEY_TYPE}
elif [ "${1}" == "RSA" ]; then
    sel_cipher=""
    KEY_TYPE=RSA
else
    echo 'Usage: tlsServer.sh [ECDHE|ECDHE_SHA256|max|RSA]'
    exit 5
fi

if [ "${KEY_TYPE}" == "${EC_KEY_TYPE}" ]; then
    echo "Server key pair = EC ${KEY_TYPE}"
    echo "Only support ${sel_cipher}"
    named_curve="-named_curve ${EC_KEY_TYPE}"
elif [ "${KEY_TYPE}" == "RSA" ]; then
    echo "Server key pair = ${KEY_TYPE}"
    echo "Do not restrict ciphers"
    named_curve=""
else
    echo "Inspect value of KEY_TYPE: ${KEY_TYPE}"
    exit 6
fi

KEY_DIR=../credentials/${KEY_TYPE}

rootca_key="${KEY_DIR}/tls_rootca_key.pem"
rootca_cer="${KEY_DIR}/tls_rootca.cer"

client_key="${KEY_DIR}/tls_client_key.pem"
client_key_pub="${KEY_DIR}/tls_client_key_pub.pem" # Contains public key only
client_csr="${KEY_DIR}/tls_client.csr"
client_cer="${KEY_DIR}/tls_client.cer"

server_key="${KEY_DIR}/tls_server_key.pem"
server_csr="${KEY_DIR}/tls_server.csr"
server_cer="${KEY_DIR}/tls_server.cer"


echo "Ensure OPENSSL_CONF is not set to use OpenSSL engine"
echo "    OPENSSL_CONF=${OPENSSL_CONF}"
echo "****************************************************"

#
# Invoke openssl s_server with additional parameters for more info
# -msg   : show all protocol messages with hex dump
# -debug : print extensive debugging information including a hex dump of all traffic
#

cmd="openssl s_server -accept 8080 -no_ssl3 ${named_curve} \
 -CAfile ${rootca_cer} \
 -cert ${server_cer} -key ${server_key} \
 ${sel_cipher} -Verify 2 -state -msg"
echo "${cmd}"
${cmd}

exit 0
