#!/bin/bash
# Copyright 2019,2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cd ${SIMW_TOP_DIR}/../
dos2unix ${SIMW_TOP_DIR}/scripts/android/cmake_based/${BUILD_SCRIPT}

if [ -e ${BUILD_SCRIPT} ]; then
    rm ${BUILD_SCRIPT}
fi

# ln -s ${SIMW_TOP_DIR}/scripts/android/${BUILD_SCRIPT}
# chmod +x ${BUILD_SCRIPT}
cd ${SIMW_TOP_DIR}/scripts/
dos2unix env_setup.sh
source env_setup.sh
source cmake_options.sh
python create_cmake_projects.py

cd ${SIMW_TOP_DIR}/../
rm -rf ${SE050_KEYMASTER_DIR}
cp -r ${SIMW_TOP_DIR}/akm/ ${SE050_KEYMASTER_DIR}
cp ${SIMW_TOP_DIR}/akm/src/interface_keymaster/patch/cmake/${INTERFACE_KEYMASTER_PATCH} ${INTERFACE_KEYMASTER_DIRECTORY}
cp ${SIMW_TOP_DIR}/scripts/android/aosp_based/${VTS_FIPS_PATCH} ${INTERFACE_KEYMASTER_DIRECTORY}

cd ${INTERFACE_KEYMASTER_DIRECTORY}
git checkout -- keymaster/3.0/default/Android.mk
git checkout -- keymaster/3.0/default/KeymasterDevice.cpp
git checkout -- keymaster/3.0/vts/functional/keymaster_hidl_hal_test.cpp
rm -rf keymaster/3.0/Android.mk
rm -rf keymaster/3.0/libs/
patch -p1 < ${INTERFACE_KEYMASTER_PATCH}
patch -p1 < ${VTS_FIPS_PATCH}

cd ${SIMW_TOP_DIR}/scripts/android/cmake_based
chmod +x ${BUILD_SCRIPT}
./${BUILD_SCRIPT}
