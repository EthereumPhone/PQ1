#!/bin/bash
#
# Copyright 2019,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#

OPENSSL="openssl"

echo "Not using secure element"

# Cd to directory where script is stored
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo ${SCRIPT_DIR}
cd ${SCRIPT_DIR}

EC_KEY_TYPE=prime256v1
se050_ec_curve=NIST_P256

KEY_DIR=../credentials/${EC_KEY_TYPE}
rootca_cer="${KEY_DIR}/tls_rootca.cer"
client_cer="${KEY_DIR}/tls_client.cer"
client_key="${KEY_DIR}/tls_client_key.pem"

if [ $# -lt 2 ]; then
    echo "Usage: tlsSwClient.sh <ip-address> <ECDH|ECDHE|ECDHE_256>"
	echo "Provide the ip address of the server you want to connect to as first argument!"
	echo "Additional argument enforces ciphersuite"
	echo "   Eg. tlsSwClient.sh 192.168.1.42 ECDHE"
	echo "   Eg. tlsSwClient.sh 192.168.1.60 ECDHE"	
	exit 1
fi 

sel_cipher="none"
if [ "${2}" == "ECDHE" ]; then		
	sel_cipher="ECDHE-ECDSA-AES128-SHA"
	echo "Request cipher ${sel_cipher}"
elif [ "${2}" == "ECDH" ]; then		
	sel_cipher="ECDH-ECDSA-AES128-SHA"
	echo "Request cipher ${sel_cipher}"
elif [ "${2}" == "ECDHE_256" ]; then		
	sel_cipher="ECDHE-ECDSA-AES128-SHA256"
	echo "Request cipher ${sel_cipher}"
else
	echo "Usage: tlsSeClient.sh <ip-address> <ECDH|ECDHE|ECDHE_256>"
	exit 4
fi

echo "Connecting to ${1}:8080... requesting cipher ${sel_cipher}"

echo "Configure to use embSeEngine"
cmd="${OPENSSL} s_client -connect ${1}:8080 -tls1_2 \
	-CAfile ${rootca_cer} \
	-cert ${client_cer} -key ${client_key} \
	-cipher ${sel_cipher} -state -msg"
echo "${cmd}"
${cmd}
