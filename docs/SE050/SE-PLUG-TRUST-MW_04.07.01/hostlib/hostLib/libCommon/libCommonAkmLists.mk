#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

#This file is required for ANDROID to compile all libcommon realted  source files.
#Android Keymaster is having dependancies on below source files.

LIBCOMMON_SRC_FILES_LIST := \
            hostlib/hostLib/platform/imx/se05x_reset.c \
            hostlib/hostLib/platform/generic/sm_timer.c \
            hostlib/hostLib/tstUtil/tst_sm_time.c \
            hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEse_Api.c \
            hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEsePal_i2c.c \
            hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEseProto7816_3.c \
            hostlib/hostLib/libCommon/smCom/smComT1oI2C.c \
            hostlib/hostLib/libCommon/infra/sm_app_boot.c \
            hostlib/hostLib/libCommon/infra/app_boot_nfc.c \
            hostlib/hostLib/libCommon/infra/global_platf.c \
            hostlib/hostLib/libCommon/infra/sm_apdu.c \
            hostlib/hostLib/libCommon/infra/sm_connect.c \
            hostlib/hostLib/libCommon/infra/sm_errors.c \
            hostlib/hostLib/libCommon/infra/sm_printf.c \
            hostlib/hostLib/libCommon/smCom/smCom.c \
            hostlib/hostLib/libCommon/scp/scp.c \
            hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c\
            hostlib/hostLib/libCommon/log/nxLog_Android.c


I2C_DRV_SRC_FILES_LIST := \
            hostlib/hostLib/platform/linux/i2c_a7.c

