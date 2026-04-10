#
# Copyright 2019,2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
#Source this file from this directory.
#
#Pre-requisite: source envsetup.sh for AOSP
#               export ANDROID_ROOT as AOSP Top directory
#Give argument as board name: hikey960 or iMx8M
#

BOARD=$1
SCRIPTS_DIR=`pwd`
echo ${SCRIPTS_DIR}
SIMW_TOP_DIR=${SCRIPTS_DIR}/../../../
#ANDROID_ROOT=${ANDROID_BUILD_TOP}
INTERFACE_KEYMASTER_PATCH=interface_keymaster3.0.patch
VTS_FIPS_PATCH=vts_fips.patch
#Interface keymaster patch is applied in this directory
INTERFACE_KEYMASTER_DIRECTORY=${ANDROID_ROOT}/hardware/interfaces/
IMAGES_FLASH_SCRIPT=${SCRIPTS_DIR}/images_flash.bat
KEYMASTER_FLASH_SCRIPT=${SCRIPTS_DIR}/keymaster_flash.bat
#Testing script
KEYMASTER_TEST_SCRIPT=${SCRIPTS_DIR}/vts_testing.bat
#Setup Script should build keymaster
BUILD_SCRIPT=build_script.sh

if [[ "$BOARD" = "hikey960" ]]; then

    CONFIG_BOARD="hikey960"

fi

if [[ "$BOARD" = "iMx8M" ]]; then

    CONFIG_BOARD="evk_8mq"
fi

export ANDROID_ROOT SIMW_TOP_DIR CONFIG_BOARD BUILD_SCRIPT IMAGES_FLASH_SCRIPT KEYMASTER_FLASH_SCRIPT
export INTERFACE_KEYMASTER_PATCH INTERFACE_KEYMASTER_DIRECTORY KEYMASTER_TEST_SCRIPT VTS_FIPS_PATCH
