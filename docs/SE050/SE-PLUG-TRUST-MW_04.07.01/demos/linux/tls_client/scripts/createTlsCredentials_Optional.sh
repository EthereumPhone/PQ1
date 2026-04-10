#!/bin/bash
#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

#

ORG_UNIT="NXP Plug Trust CA"


CERT_VALIDITY=4380  # 12 years

# Create either EC or RSA based credential
if [ "$#" -eq 1 ]; then
	if [ "$1" == "RSA" ]; then
		CA_TYPE="RSA"
	elif [ "$1" == "ECC" ]; then
		CA_TYPE="ECC"
	else
		echo "  first argument to script must be ECC or RSA"
		echo "Exiting ..."
		exit 21
	fi
else
	echo "Usage createTlsCredentials_Optional [ECC|RSA]"
	echo "Exiting ..."
	exit 4
fi

################################################
# Set Global variables according to ECC/RSA mode
################################################
# Root CA Files
if [ "${CA_TYPE}" == "RSA" ]; then
	ROOT_CA_CN="NXP RootCAvRxxx"
	DEVICE_CN="NXP_SE050_TLS_CLIENT_RSA"
	SERVER_CN="NXP_SE050_TLS_SERVER_RSA"
	CA_RSA_BITS=4096
	CERT_RSA_BITS=2048
	KEY_DIR=../credentials/RSA
else
	ROOT_CA_CN="NXP RootCAvExxx"
	DEVICE_CN="NXP_SE050_TLS_CLIENT_ECC"
	SERVER_CN="NXP_SE050_TLS_SERVER_ECC"
	EC_KEY_TYPE=prime256v1
	KEY_DIR=../credentials/${EC_KEY_TYPE}
fi

# Cd to directory where script is stored
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo ${SCRIPT_DIR}
cd ${SCRIPT_DIR}

if [ ! -d ${KEY_DIR} ]; then
	mkdir -p ${KEY_DIR}
fi


rootca_key="${KEY_DIR}/tls_rootca_key.pem"
rootca_cer="${KEY_DIR}/tls_rootca.cer"
rootca_srl="tls_rootca.srl"

client_key="${KEY_DIR}/tls_client_key.pem"
client_key_pub="${KEY_DIR}/tls_client_key_pub.pem" # Contains public key only
client_csr="${KEY_DIR}/tls_client.csr"
client_cer="${KEY_DIR}/tls_client.cer"

server_key="${KEY_DIR}/tls_server_key.pem"
server_csr="${KEY_DIR}/tls_server.csr"
server_cer="${KEY_DIR}/tls_server.cer"


echo "Create or Re-use RootCA"
echo "***********************"
if [ ! -e ${rootca_key} ]; then
	if [ "${CA_TYPE}" == "RSA" ]; then
		echo ">> Create RSA Root CA Key with ${CA_RSA_BITS} bits: (${rootca_key})"
		openssl genrsa -out ${rootca_key} ${CA_RSA_BITS}
    else
		ecc_param_pem="${KEY_DIR}/${EC_KEY_TYPE}.pem"
		if [ ! -e ${ecc_param_pem} ]; then
			# echo "Creating ECC parameter file: ${ecc_param_pem} for ${EC_KEY_TYPE}"
			openssl ecparam -name ${EC_KEY_TYPE} -out ${ecc_param_pem}
		fi
		echo ">> Create EC Root CA key (${rootca_key})"
		openssl ecparam -in ${ecc_param_pem} -genkey -noout -out ${rootca_key}
		# openssl ec -in ${rootca_key} -text -noout
	fi
	echo ">> Create RootCA certificate (${rootca_cer})"
	openssl req -x509 -new -nodes -key ${rootca_key} \
	  -subj "/OU=${ORG_UNIT}/CN=${ROOT_CA_CN}" \
	  -days ${CERT_VALIDITY} -out ${rootca_cer}
	# openssl x509 -in ${rootca_cer} -text -noout
else
	if [ ! -e ${rootca_cer} ]; then
		echo ">> Create RootCA (${rootca_cer}) certificate"
		openssl req -x509 -new -nodes -key ${rootca_key} \
			-subj "/OU=${ORG_UNIT}/CN=${ROOT_CA_CN}" \
			-days ${CERT_VALIDITY} -out ${rootca_cer}
		# openssl x509 -in ${rootca_cer} -text -noout
	else
		echo ">> RootCA key (${rootca_key}) already exists"
		echo ">> RootCA certificate (${rootca_cer}) already exist"
	fi
fi


echo "Prepare Client Side TLS credentials"
echo "***********************************"
# Conditionally create client key
if [ ! -e ${client_key}  ]; then
	echo ">> Create client key (${client_key})"
	if [ "${CA_TYPE}" == "RSA" ]; then
		openssl genrsa -out ${client_key} ${CERT_RSA_BITS}
	else
		openssl ecparam -in ${ecc_param_pem} -genkey -noout -out ${client_key}
	fi
	# openssl ec -in ${client_key} -text -noout
else
	echo ">> Client key (${client_key}) already exists"
fi

# Create a client key pem file containing ONLY the public key
echo ">> Extract public key from client keypair: ${client_key_pub}"
if [ "${CA_TYPE}" == "RSA" ]; then
	openssl rsa -in ${client_key} -pubout -out ${client_key_pub}
else
	openssl ec -in ${client_key} -pubout -out ${client_key_pub}
fi

# echo ">> Create Client CSR"
openssl req -new -key ${client_key} -subj "/CN=${DEVICE_CN}" -out ${client_csr}
# openssl req -in ${client_csr} -text -noout

# Always create a CA signed client certificate
if [ -e ${rootca_key} ] && [ -e ${rootca_cer} ]; then
	# echo "CA cert and key present"
	if [ -e ${rootca_srl} ]; then
		# echo ">> ${rootca_srl} already exists, use it"
		x509_serial="-CAserial ${rootca_srl}"
	else
		# echo ">> no ${rootca_srl} found, create it"
		x509_serial="-CAcreateserial"
	fi
	echo ">> Create Client Certificate (${client_cer})"
	openssl x509 -req -sha256 -days ${CERT_VALIDITY} -in ${client_csr} ${x509_serial} -CA ${rootca_cer} -CAkey ${rootca_key} -out ${client_cer}
	openssl x509 -in ${client_cer} -text -noout
else
	echo "Did not find CA cert and/or CA key pair: Fatal error"
	exit -1
fi

echo "Prepare Server Side TLS credentials"
echo "***********************************"
# Conditionally create server key
if [ ! -e ${server_key} ]; then
	echo ">> Create server key (${server_key})"
	if [ "${CA_TYPE}" == "RSA" ]; then
		openssl genrsa -out ${server_key} ${CERT_RSA_BITS}
	else
		openssl ecparam -in ${ecc_param_pem} -genkey -noout -out ${server_key}
	fi
	# openssl ec -in ${server_key} -text -noout
else
	echo ">> Server key (${server_key}) already exists"
fi

# echo ">> Create Server CSR"
openssl req -new -key ${server_key} -subj "/CN=${SERVER_CN}" -out ${server_csr}
# openssl req -in ${server_csr} -text -noout

# Always create a CA signed server certificate
if [ -e ${rootca_key} ] && [ -e ${rootca_cer} ]; then
	# echo "CA cert and key present"
	if [ -e ${rootca_srl} ]; then
		# echo ">> ${rootca_srl} already exists, use it"
		x509_serial="-CAserial ${rootca_srl}"
	else
		# echo ">> no ${rootca_srl} found, create it"
		x509_serial="-CAcreateserial"
	fi
	echo ">> Create Server Certificate (${server_cer})"
	openssl x509 -req -sha256 -days ${CERT_VALIDITY} -in ${server_csr} ${x509_serial} -CA ${rootca_cer} -CAkey ${rootca_key} -out ${server_cer}
	openssl x509 -in ${server_cer} -text -noout
else
	echo "Did not find CA cert and/or CA key pair: Fatal error"
	exit -1
fi

echo ">> Server and Client credentials available for use"
echo ">> ***********************************************"
