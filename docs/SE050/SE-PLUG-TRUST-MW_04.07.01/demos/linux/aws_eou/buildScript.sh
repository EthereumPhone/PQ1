#!/bin/sh
#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

# Determine directory where script is stored
AWS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo ${AWS_DIR}

git clone https://github.com/aws/aws-iot-device-sdk-embedded-C.git
cd aws-iot-device-sdk-embedded-C
git checkout v4_beta_deprecated
git submodule update --init --recursive
mkdir build
cp ../aws_c_sdk_eou.patch .
git apply aws_c_sdk_eou.patch
cd  build
cmake ../.
cmake -DIOT_NETWORK_USE_OPENSSL:BOOL=ON .
make iot_demo_mqtt -j
cp ../../AmazonRootCA1.pem output/bin/
