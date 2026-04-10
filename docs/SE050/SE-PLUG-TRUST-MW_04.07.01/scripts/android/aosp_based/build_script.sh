#!/bin/bash
# Copyright 2019,2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# First configured target board
CONFIG_BOARD=${CONFIG_BOARD}

ANDROID_BUILD_DIR=${ANDROID_ROOT}

die (){

    printf "**********ERROR********** $1\n"
    exit 1
}


if [[ "$CONFIG_BOARD" != "hikey960"  &&  "$CONFIG_BOARD" != "evk_8mq" ]]; then

    echo "Invalid input please select target board"
    echo "1. hikey960"
    echo "2. iMx8M"
    read CONFIG_BOARD
fi

if [[ "$CONFIG_BOARD" = "hikey960" || "$CONFIG_BOARD" = "1" ]]; then

   echo "Target board configured as : hikey960 "
   CONFIG_BOARD="hikey960"
elif [[ "$CONFIG_BOARD" = "evk_8mq" ||"$CONFIG_BOARD" = "2" ]]; then

   echo "Target board configured as : iMx8M "
   CONFIG_BOARD="evk_8mq"

fi

#lunch $CONFIG_BOARD-userdebug
cd ${ANDROID_BUILD_DIR}

source build/envsetup.sh
lunch ${CONFIG_BOARD}-userdebug

cd ${ANDROID_BUILD_DIR}/vendor/nxp/simw-top
mm -j || die "Failed to build Se05x based keymaster"

cd ${ANDROID_BUILD_DIR}/hardware/interfaces/keymaster/3.0/default
mm -j || die "Failed to build keymaster interface"

cd ${ANDROID_BUILD_DIR}/hardware/interfaces/keymaster/3.0/vts/functional
mm -j || die "Failed to build Keymaster VTS"

cp ${KEYMASTER_FLASH_SCRIPT} ${ANDROID_PRODUCT_OUT}/keymaster_flash.bat
cp ${KEYMASTER_TEST_SCRIPT} ${ANDROID_PRODUCT_OUT}
