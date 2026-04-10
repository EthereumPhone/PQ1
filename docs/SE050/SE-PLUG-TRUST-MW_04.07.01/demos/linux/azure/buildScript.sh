#!/bin/sh
#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

# Determine directory where script is stored
DEMO_DIR="$( cd "$(dirname "$0")" ; pwd -P )"
echo ${DEMO_DIR}
cd ${DEMO_DIR}

COMMON_DIR=${DEMO_DIR}/../common/
cd ${COMMON_DIR}
# building jansson
if [ ! -d jansson ]; then
	git clone https://github.com/akheron/jansson.git
	cd jansson
	autoreconf -i
	./configure
	make
	sudo make install
	cd ..
fi

sudo ldconfig /usr/local/lib

# building libjwt
if [ ! -d libjwt ]; then
	export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
	git clone https://github.com/benmcollins/libjwt.git
	cd libjwt
	autoreconf -i
	./configure
	make all
	sudo make install
	cd ..
fi

sudo ldconfig /usr/local/lib

# building paho c client
# NOTE: Building the paho c client requires a filesystem
# that supports symbolic links
# There is an alignment issue with the packaged version of paho.mqtt
# Hence we clone and build it to usr/local_azure/  folder
#
if [ ! -d paho.mqtt.c ]; then
	git clone https://github.com/eclipse/paho.mqtt.c.git
fi
	cd paho.mqtt.c
	openssl_version=$(openssl version | awk '{print $2}')
	openssl_major_version=$(echo "$openssl_version" | cut -d. -f1)
	if [ "${openssl_major_version}" = "3" ]; then
		patch -p1 < ../../azure/sssProvider_Updates.patch
	fi
	sudo mkdir -p /usr/local_azure/lib
	sudo mkdir -p /usr/local_azure/bin
	sudo make prefix=/usr/local_azure
	sudo make install prefix=/usr/local_azure
	sudo ldconfig /usr/local/lib
	cd ..


sudo ldconfig /usr/local_azure/lib /usr/local/lib
# export LD_RUN_PATH=/usr/local/lib
#building the app
cd ${DEMO_DIR}

make all
