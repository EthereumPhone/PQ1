# Copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

#This file is required for ANDROID to compile SE050 based Android Keymaster

LOCAL_PATH:= $(call my-dir)
SIMW_TOP_PATH= $(LOCAL_PATH)
include $(CLEAR_VARS)

$(info SIMW_TOP_PATH = $(SIMW_TOP_PATH))

ANDROID_TOP_BUILD_DIR:=../../..

include $(SIMW_TOP_PATH)/ext/mbedtlsAkmLists.mk
include $(SIMW_TOP_PATH)/hostlib/hostLib/se05x/se05xAkmLists.mk
include $(SIMW_TOP_PATH)/hostlib/hostLib/libCommon/libCommonAkmLists.mk
include $(SIMW_TOP_PATH)/sss/sssAkmLists.mk
include $(SIMW_TOP_PATH)/akm/BuildType/aosp/akmLists.mk

LOCAL_MODULE := libse050keymasterdevice
LOCAL_SRC_FILES := \
    $(MBEDTLS_SRC_FILES_LIST:$(SIMW_TOP_PATH)/%=%) \
    $(SE05X_SRC_FILES_LIST:$(SIMW_TOP_PATH)/%=%) \
    $(I2C_DRV_SRC_FILES_LIST:$(SIMW_TOP_PATH)/%=%) \
    $(LIBCOMMON_SRC_FILES_LIST:$(SIMW_TOP_PATH)/%=%) \
    $(SSS_SRC_FILES_LIST:$(SIMW_TOP_PATH)/%=%) \
    $(SSS_BOOT_SRC_FILES_LIST:$(SIMW_TOP_PATH)/%=%) \
    $(AKM_SRC_FILES_LIST:$(SIMW_TOP_PATH)/%=%) \

# Applet based source file list
# For Applet 3.0 APPLET_03_00_SRC_FILES_LIST & APPLET_03_00_C_INCLUDES is required
# For Applet 2.2 APPLET_02_02_SRC_FILES_LIST & APPLET_02_02_C_INCLUDES is required
LOCAL_SRC_FILES += \
    $(APPLET_03_00_SRC_FILES_LIST:$(SIMW_TOP_PATH)/%=%)

LOCAL_C_INCLUDES += \
    $(SIMW_TOP_PATH)/$(APPLET_03_00_C_INCLUDES)

#LOCAL_SRC_FILES := \
#    $(APPLET_02_02_SRC_FILES_LIST:$(SIMW_TOP_PATH)/%=%)
#
#LOCAL_C_INCLUDES := \
#    $(SIMW_TOP_PATH)/$(APPLET_02_02_C_INCLUDES)

LOCAL_C_INCLUDES += \
    $(SIMW_TOP_PATH)/$(ANDROID_TOP_BUILD_DIR)/system/security/keystore \
    $(SIMW_TOP_PATH)/$(ANDROID_TOP_BUILD_DIR)/system/keymaster \
    $(SIMW_TOP_PATH)/$(ANDROID_TOP_BUILD_DIR)/system/keymaster/include \
    $(SIMW_TOP_PATH)/hostlib/hostLib/platform/inc \
    $(SIMW_TOP_PATH)/hostlib/hostLib/platform/android \
    $(SIMW_TOP_PATH)/akm \
    $(SIMW_TOP_PATH)/akm/include \
    $(SIMW_TOP_PATH)/sss/inc \
    $(SIMW_TOP_PATH)/sss/ex/inc \
    $(SIMW_TOP_PATH)/sss/ex/src \
    $(SIMW_TOP_PATH)/sss/port/default/ \
    $(SIMW_TOP_PATH)/hostlib/hostLib/libCommon/infra \
    $(SIMW_TOP_PATH)/hostlib/hostLib/libCommon/log \
    $(SIMW_TOP_PATH)/hostlib/hostLib/inc \
    $(SIMW_TOP_PATH)/ext/mbedtls/library \
    $(SIMW_TOP_PATH)/ext/mbedtls/include \
    $(SIMW_TOP_PATH)/hostlib/hostLib/libCommon/smCom \
    $(SIMW_TOP_PATH)/hostlib/hostLib/libCommon/smCom/T1oI2C \
    $(SIMW_TOP_PATH)/hostlib/hostLib/api/inc \
    $(SIMW_TOP_PATH)/hostlib/hostLib/libCommon/scp \
    $(SIMW_TOP_PATH)/hostlib/hostLib/tstUtil \

LOCAL_CFLAGS = -Wall -Werror -Wno-unused-parameter -Wno-unused-variable -Wno-missing-braces -Wno-missing-field-initializers\
        -DSSS_USE_FTR_FILE -DT1oI2C -DT1oI2C_UM11225 -DFTR_FILE_SYSTEM \
        -DNO_SECURE_CHANNEL_SUPPORT -DSCP_MODE=NO_C_MAC_NO_C_ENC_NO_R_MAC_NO_R_ENC \
        -DMBEDTLS_USER_CONFIG_FILE=\"sss_x86_mbedtls_config.h\"


LOCAL_CLANG_CFLAGS += -Wno-error=unused-const-variable -Wno-error=unused-private-field -Wno-error=date-time -Wno-error=pointer-sign -Wno-error=format
LOCAL_CLANG_CFLAGS += -fno-sanitize-coverage=edge,indirect-calls,8bit-counters,trace-cmp
LOCAL_SHARED_LIBRARIES := \
    libkeymaster_messages \
        libkeymaster_portable \
        libkeymaster_staging \
        liblog \
        libcrypto \
        libcutils

LOCAL_MODULE_TAGS :=optional
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
include $(BUILD_SHARED_LIBRARY)

# SE050 BASED TESTS
# Unit tests for libkeymaster
include $(CLEAR_VARS)

LOCAL_MODULE := se050keymaster_tests
LOCAL_SRC_FILES := \
    $(AKM_TEST_SRC_FILES:$(SIMW_TOP_PATH)/%=%)

LOCAL_C_INCLUDES := \
    $(SIMW_TOP_PATH)/$(ANDROID_TOP_BUILD_DIR)/system/security/keystore \
    $(SIMW_TOP_PATH)/$(ANDROID_TOP_BUILD_DIR)/system/keymaster \
    $(SIMW_TOP_PATH)/$(ANDROID_TOP_BUILD_DIR)/system/keymaster/include \
    $(SIMW_TOP_PATH)/akm/include \
    $(SIMW_TOP_PATH)/akm \
    $(SIMW_TOP_PATH)/sss/inc \
    $(SIMW_TOP_PATH)/sss/ex/inc \
    $(SIMW_TOP_PATH)/sss/port/default/ \
    $(SIMW_TOP_PATH)/hostlib/hostLib/inc \
    $(SIMW_TOP_PATH)/ext/mbedtls/include \
    $(SIMW_TOP_PATH)/hostlib/hostLib/libCommon/infra \
    $(SIMW_TOP_PATH)/hostlib/hostLib/libCommon/log \

LOCAL_C_INCLUDES += \
    $(SIMW_TOP_PATH)/$(APPLET_03_00_C_INCLUDES)

#LOCAL_C_INCLUDES += \
#    $(SIMW_TOP_PATH)/$(APPLET_02_02_C_INCLUDES)

LOCAL_CFLAGS = -Wall -Werror -Wunused -DKEYMASTER_NAME_TAGS -DSSS_USE_FTR_FILE
ifeq ($(TARGET_PRODUCT),evk_8mq)
    LOCAL_CFLAGS += -DPLATFORM_IMX
endif
LOCAL_CLANG := true
LOCAL_CLANG_CFLAGS += -Wno-error=unused-const-variable -Wno-error=unused-private-field
LOCAL_CLANG_CFLAGS += -fno-sanitize-coverage=edge,indirect-calls,8bit-counters,trace-cmp
LOCAL_MODULE_TAGS := tests

LOCAL_SHARED_LIBRARIES := \
    libse050keymasterdevice \
    libkeymaster_messages \
    libkeymaster_portable \
    libkeymaster_staging \
    libcrypto \
    libsoftkeymaster

include $(BUILD_NATIVE_TEST)

# SE050 BASED DEMO Application
include $(SIMW_TOP_PATH)/demos/se05x/Android.mk
# SE050 Communication Interface
include $(SIMW_TOP_PATH)/hostlib/hostLib/Android.mk


