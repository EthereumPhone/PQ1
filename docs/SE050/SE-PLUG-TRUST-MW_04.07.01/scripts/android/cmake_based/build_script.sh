#!/bin/bash
# Copyright 2019,2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

echo -e "Android build root dir : $ANDROID_ROOT"
echo -e "Android build target board out dir : $ANDROID_PRODUCT_OUT"
mkdir -p ${ANDROID_ROOT}/hardware/interfaces/keymaster/3.0/libs

# First configured target board
CONFIG_BOARD=${CONFIG_BOARD}

ANDROID_KEYMASTER_DIR=${ANDROID_ROOT}/hardware/interfaces/keymaster/3.0/libs
ANDROID_BUILD_DIR=${ANDROID_ROOT}
TARGET_ARCH64=arm64
TARGET_ARCH=arm
LIB64_DIR=${ANDROID_KEYMASTER_DIR}/${TARGET_ARCH64}
LIB32_DIR=${ANDROID_KEYMASTER_DIR}/${TARGET_ARCH}
THE_TOP_DIR=${SIMW_TOP_DIR}/../

die (){

    printf "**********ERROR********** $1\n"
    exit 1
}


if [[ "$CONFIG_BOARD" != "hikey960"  &&  "$CONFIG_BOARD" != "iMx8M" ]]; then

    echo "Invalid input please select target board"
    echo "1. hikey960"
    echo "2. iMx8M"
    read CONFIG_BOARD
fi

if [[ "$CONFIG_BOARD" = "hikey960" || "$CONFIG_BOARD" = "1" ]]; then

   echo "Target board configured as : hikey960 "
   CONFIG_BOARD="hikey960"
elif [[ "$CONFIG_BOARD" = "iMx8M" ||"$CONFIG_BOARD" = "2" ]]; then

   echo "Target board configured as : iMx8M "
   CONFIG_BOARD="evk_8mq"

fi

#lunch $CONFIG_BOARD-userdebug

cd ${ANDROID_BUILD_DIR}
for f in  \
   libSSS_APIs.so \
   liba7x_utils.so \
   libmbedtls.so ;
do
	find . -iname ${f} -print -exec rm {} \;
   rm -rf ${ANDROID_BUILD_DIR}/out/target/product/hikey960/obj_arm/SHARED_LIBRARIES/${f}_intermediates
   rm -rf ${ANDROID_BUILD_DIR}/out/target/product/hikey960/obj/SHARED_LIBRARIES/${f}_intermediates
done

cd ${ANDROID_BUILD_DIR}
for f in  \
   libSSS_APIs.so.toc \
   liba7x_utils.so.toc \
   libmbedtls.so.toc ;
do
  find . -iname ${f} -print -exec rm {} \;
   rm -rf ${ANDROID_BUILD_DIR}/out/target/product/${CONFIG_BOARD}/obj_arm/lib/${f}.so.toc
   rm -rf ${ANDROID_BUILD_DIR}/out/target/product/${CONFIG_BOARD}/obj/lib/${f}.so.toc
done

cd ${ANDROID_BUILD_DIR}
for f in  \
   libsmCom.a \
   libmwlog.a \
   libse05x.a \
   libex_common.a ;
do
  find . -iname ${f} -print -exec rm {} \;
   rm -rf ${ANDROID_BUILD_DIR}/out/target/product/${CONFIG_BOARD}/obj_arm/STATIC_LIBRARIES/${f}_intermediates
   rm -rf ${ANDROID_BUILD_DIR}/out/target/product/${CONFIG_BOARD}/obj/STATIC_LIBRARIES/${f}_intermediates
done

cd ${THE_TOP_DIR}/simw-top_build/android_${TARGET_ARCH}
rm sss/libSSS_APIs.so
rm hostlib/hostLib/liba7x_utils.so
rm hostlib/hostLib/libCommon/libsmCom.a
rm hostlib/hostLib/libCommon/log/libmwlog.a
rm ext/libmbedtls.so
rm hostlib/hostLib/se05x/libse05x.a
rm sss/ex/src/libex_common.a

cd ${THE_TOP_DIR}/simw-top_build/android_${TARGET_ARCH64}
rm sss/libSSS_APIs.so
rm hostlib/hostLib/liba7x_utils.so
rm hostlib/hostLib/libCommon/libsmCom.a
rm hostlib/hostLib/libCommon/log/libmwlog.a
rm ext/libmbedtls.so
rm hostlib/hostLib/se05x/libse05x.a
rm sss/ex/src/libex_common.a

cd ${THE_TOP_DIR}/simw-top_build/android_${TARGET_ARCH}
source ${THE_TOP_DIR}/simw-top/scripts/cmake_options.sh

set -u
cmake ${doPTMW_SCP_SCP03_SSS_ON} ${doPTMW_SE05X_Auth_PlatfSCP03_ON} ${doPTMW_FIPS_SE050_ON} ${doPTMW_SE05X_Ver_03_XX_ON} ${doPTMW_Applet_SE05X_C_ON} .
set +u

make all -j || die "Failed to build ${TARGET_ARCH} based shared objects"
cd ${THE_TOP_DIR}/simw-top_build/android_${TARGET_ARCH64}

set -u
cmake ${doPTMW_SCP_SCP03_SSS_ON} ${doPTMW_SE05X_Auth_PlatfSCP03_ON} ${doPTMW_FIPS_SE050_ON} ${doPTMW_SE05X_Ver_03_XX_ON} ${doPTMW_Applet_SE05X_C_ON} .
set +u
make all -j || die "Failed to build ${TARGET_ARCH64} based shared objects"


cd ${THE_TOP_DIR}
mkdir -p ${ANDROID_KEYMASTER_DIR}/${TARGET_ARCH64}
mkdir -p ${ANDROID_KEYMASTER_DIR}/${TARGET_ARCH}

cd ${ANDROID_BUILD_DIR}/system/keymaster/simw-akm/src/interface_keymaster/patch/cmake/libs/
#cd ${THE_TOP_DIR}/simw-top/akm/src/interface_keymaster/patch/libs/
cp -f Android.mk ${ANDROID_KEYMASTER_DIR}/

cd ${ANDROID_BUILD_DIR}/system/keymaster/simw-akm/src/interface_keymaster/patch/cmake/
cp -f Android.mk ${ANDROID_KEYMASTER_DIR}/../

cd ${THE_TOP_DIR}/simw-top_build/android_${TARGET_ARCH}
cp -f sss/libSSS_APIs.so  ${LIB32_DIR}/libSSS_APIs.so
cp -f hostlib/hostLib/liba7x_utils.so  ${LIB32_DIR}/liba7x_utils.so
cp -f hostlib/hostLib/libCommon/libsmCom.a  ${LIB32_DIR}/libsmCom.a
cp -f hostlib/hostLib/libCommon/log/libmwlog.a    ${LIB32_DIR}/libmwlog.a
cp -f ext/libmbedtls.so  ${LIB32_DIR}/libmbedtls.so
cp -f hostlib/hostLib/se05x/libse05x.a   ${LIB32_DIR}/libse05x.a
cp -f sss/ex/src/libex_common.a    ${LIB32_DIR}/libex_common.a
cp -f bin/test_LoopBack ${LIB32_DIR}/test_LoopBack
cp -f bin/test_session ${LIB32_DIR}/test_session
cp -f bin/test_keyobject ${LIB32_DIR}/test_keyobject
cp -f bin/test_keystore ${LIB32_DIR}/test_keystore
cp -f bin/test_asymmetric ${LIB32_DIR}/test_asymmetric

cd ${THE_TOP_DIR}/simw-top_build/android_${TARGET_ARCH64}
cp -f sss/libSSS_APIs.so  ${LIB64_DIR}/libSSS_APIs.so
cp -f hostlib/hostLib/liba7x_utils.so  ${LIB64_DIR}/liba7x_utils.so
cp -f hostlib/hostLib/libCommon/libsmCom.a  ${LIB64_DIR}/libsmCom.a
cp -f hostlib/hostLib/libCommon/log/libmwlog.a    ${LIB64_DIR}/libmwlog.a
cp -f ext/libmbedtls.so  ${LIB64_DIR}/libmbedtls.so
cp -f hostlib/hostLib/se05x/libse05x.a   ${LIB64_DIR}/libse05x.a
cp -f sss/ex/src/libex_common.a    ${LIB64_DIR}/libex_common.a
cp -f bin/test_LoopBack ${LIB64_DIR}/test_LoopBack
cp -f bin/test_session ${LIB64_DIR}/test_session
cp -f bin/test_keyobject ${LIB64_DIR}/test_keyobject
cp -f bin/test_keystore ${LIB64_DIR}/test_keystore
cp -f bin/test_asymmetric ${LIB64_DIR}/test_asymmetric

cd ${ANDROID_BUILD_DIR}
for f in  \
   libSSS_APIs.so \
   liba7x_utils.so \
   libsmCom.a \
   libmwlog.a \
   libmbedtls.so \
   libse05x.a \
   libex_common.a ;
do
	cp -f ${LIB32_DIR}/${f} ./out/target/product/${CONFIG_BOARD}/obj_arm/lib/${f}
	cp -f ${LIB64_DIR}/${f} ./out/target/product/${CONFIG_BOARD}/obj/lib/${f}
done

cd ${ANDROID_BUILD_DIR}
    cp -f  ${LIB64_DIR}/test_LoopBack   ./out/target/product/${CONFIG_BOARD}/vendor/bin/test_LoopBack
    cp -f  ${LIB64_DIR}/test_session   ./out/target/product/${CONFIG_BOARD}/vendor/bin/test_session
    cp -f  ${LIB64_DIR}/test_keyobject   ./out/target/product/${CONFIG_BOARD}/vendor/bin/test_keyobject
    cp -f  ${LIB64_DIR}/test_keystore   ./out/target/product/${CONFIG_BOARD}/vendor/bin/test_keystore
    cp -f  ${LIB64_DIR}/test_asymmetric   ./out/target/product/${CONFIG_BOARD}/vendor/bin/test_asymmetric
cd ${ANDROID_BUILD_DIR}

source build/envsetup.sh
lunch ${CONFIG_BOARD}-userdebug

cd ${ANDROID_BUILD_DIR}/hardware/interfaces/keymaster/3.0/libs
mm -j || die "Failed to build prebuild libraries"

# build keymaster code  and vts
cd ${ANDROID_BUILD_DIR}

for f in  \
   libSSS_APIs \
   liba7x_utils \
   libmbedtls ;
do
  cp -f ${ANDROID_PRODUCT_OUT}/obj_arm/SHARED_LIBRARIES/${f}_intermediates/${f}.so.toc ./out/target/product/${CONFIG_BOARD}/obj_arm/lib/${f}.so.toc
  cp -f ${ANDROID_PRODUCT_OUT}/obj/SHARED_LIBRARIES/${f}_intermediates/${f}.so.toc  ./out/target/product/${CONFIG_BOARD}/obj/lib/${f}.so.toc

done

cd ${ANDROID_BUILD_DIR}
for f in  \
   libsmCom \
   libmwlog \
   libse05x \
   libex_common;
do
  cp -f ${ANDROID_PRODUCT_OUT}/obj_arm/SHARED_LIBRARIES/libSSS_APIs_intermediates/export_includes ${ANDROID_PRODUCT_OUT}/obj_arm/STATIC_LIBRARIES/${f}_intermediates/export_includes
  cp -f ${ANDROID_PRODUCT_OUT}/obj/SHARED_LIBRARIES/libSSS_APIs_intermediates/export_includes  ${ANDROID_PRODUCT_OUT}/obj/STATIC_LIBRARIES/${f}_intermediates/export_includes

done


cd ${ANDROID_BUILD_DIR}/system/keymaster
mm -j || die "Failed to build system keymaster"

cd ${ANDROID_BUILD_DIR}/system/keymaster/simw-akm
# copy board specific Android.mk files
cp -f BuildType/cmake/Android-${CONFIG_BOARD}.mk Android.mk
mm -j || die "Failed to buile SE050 based system keymaster"

cd ${ANDROID_BUILD_DIR}/hardware/interfaces/keymaster/3.0/default
mm -j || die "Failed to build keymaster interface"

cd ${ANDROID_BUILD_DIR}/hardware/interfaces/keymaster/3.0/vts/functional
mm -j || die "Failed to build Keymaster VTS"

cp ${KEYMASTER_FLASH_SCRIPT} ${ANDROID_PRODUCT_OUT}/keymaster_flash.bat
cp ${KEYMASTER_TEST_SCRIPT} ${ANDROID_PRODUCT_OUT}
