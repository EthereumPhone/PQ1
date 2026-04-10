# Copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

#This File is required to rebuild the prebuild objects necessary for aosp build system
LOCAL_PATH := $(call my-dir)
LOCAL_CFLAGS +=-DSSS_USE_FTR_FILE \
			-I $(ANDROID_ROOT)/../simw-top_build/android_arm/

include $(CLEAR_VARS)
LOCAL_MODULE := libSSS_APIs
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_MODULE_SUFFIX := .so
LOCAL_SRC_FILES_arm := arm/libSSS_APIs.so
LOCAL_SRC_FILES_arm64 := arm64/libSSS_APIs.so
LOCAL_MODULE_TARGET_ARCH := arm arm64
LOCAL_MULTILIB := both
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := libex_common
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_MODULE_SUFFIX := .a
LOCAL_SRC_FILES_arm := arm/libex_common.a
LOCAL_SRC_FILES_arm64 := arm64/libex_common.a
LOCAL_MODULE_TARGET_ARCH := arm arm64
LOCAL_MULTILIB := both
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := libse05x
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_MODULE_SUFFIX := .a
LOCAL_SRC_FILES_arm := arm/libse05x.a
LOCAL_SRC_FILES_arm64 := arm64/libse05x.a
LOCAL_MODULE_TARGET_ARCH := arm arm64
LOCAL_MULTILIB := both
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := liba7x_utils
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_MODULE_SUFFIX := .so
LOCAL_SRC_FILES_arm := arm/liba7x_utils.so
LOCAL_SRC_FILES_arm64 := arm64/liba7x_utils.so
LOCAL_MODULE_TARGET_ARCH := arm arm64
LOCAL_MULTILIB := both
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := libmbedtls
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_MODULE_SUFFIX := .so
LOCAL_SRC_FILES_arm := arm/libmbedtls.so
LOCAL_SRC_FILES_arm64 :=arm64/libmbedtls.so
LOCAL_MODULE_TARGET_ARCH := arm arm64
LOCAL_MULTILIB := both
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := libsmCom
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_MODULE_SUFFIX := .a
LOCAL_SRC_FILES_arm := arm/libsmCom.a
LOCAL_SRC_FILES_arm64 := arm64/libsmCom.a
LOCAL_MODULE_TARGET_ARCH := arm arm64
LOCAL_MULTILIB := both
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := libmwlog
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_MODULE_SUFFIX := .a
LOCAL_SRC_FILES_arm := arm/libmwlog.a
LOCAL_SRC_FILES_arm64 := arm64/libmwlog.a
LOCAL_MODULE_TARGET_ARCH := arm arm64
LOCAL_MULTILIB := both
include $(BUILD_PREBUILT)

