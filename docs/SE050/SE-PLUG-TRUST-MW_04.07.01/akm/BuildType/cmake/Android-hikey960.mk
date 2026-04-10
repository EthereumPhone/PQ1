# Copyright (C) 2014 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LOCAL_PATH := $(call my-dir)

###
# libse050keymaster provides a software-based keymaster HAL implementation.
# # This is used by keystore as a fallback for when the hardware keymaster does
# # not support the request.
# ###
include $(CLEAR_VARS)
LOCAL_MODULE := libse050keymasterdevice
LOCAL_SRC_FILES := \
    ../ec_keymaster0_key.cpp \
    ../ec_keymaster1_key.cpp \
    ../ecdsa_keymaster1_operation.cpp \
    ../keymaster0_engine.cpp \
    ../keymaster1_engine.cpp \
    ../keymaster_configuration.cpp \
    ../rsa_keymaster0_key.cpp \
    ../rsa_keymaster1_key.cpp \
    ../rsa_keymaster1_operation.cpp \
    ../soft_keymaster_context.cpp \
    src/system_keymaster/se050_keymaster_device.cpp \
    src/system_keymaster/se050_keymaster_utils.cpp \
    src/system_keymaster/se050_keymaster_attestation_record.cpp \
    ../soft_keymaster_logger.cpp

LOCAL_C_INCLUDES := \
	system/security/keystore \
    $(LOCAL_PATH)/../include \
	$(LOCAL_PATH)/include \
	$(LOCAL_PATH)/../
LOCAL_CFLAGS = -Wall -Werror -Wunused
LOCAL_CFLAGS +=-DSSS_USE_FTR_FILE \
    -I $(ANDROID_ROOT)/../simw-top_build/android_arm64/  \
    -I $(ANDROID_ROOT)/../simw-top/hostlib/hostLib/libCommon/infra/ \
    -I $(ANDROID_ROOT)/../simw-top/hostlib/hostLib/libCommon/log/ \
    -I $(ANDROID_ROOT)/../simw-top/sss/inc/ \
    -I $(ANDROID_ROOT)/../simw-top/sss/port/default/ \
    -I $(ANDROID_ROOT)/../simw-top/ext/mbedtls/include/ \
    -I $(ANDROID_ROOT)/../simw-top/hostlib/hostLib/inc/ \
    -I $(ANDROID_ROOT)/../simw-top/hostlib/hostLib/se05x_03_xx_xx/ \
    -I $(ANDROID_ROOT)/../simw-top/sss/ex/inc/

LOCAL_CLANG_CFLAGS += -Wno-error=unused-const-variable -Wno-error=unused-private-field
LOCAL_CLANG_CFLAGS += -fno-sanitize-coverage=edge,indirect-calls,8bit-counters,trace-cmp
LOCAL_SHARED_LIBRARIES := \
	libkeymaster_messages \
        libkeymaster_portable \
        libkeymaster_staging \
        liblog \
        libcrypto \
        libcutils

LOCAL_LDLIBS += -lSSS_APIs -lmbedtls -la7x_utils

LOCAL_STATIC_LIBRARIES := libex_common \
	libsmCom \
	libse05x \
	libmwlog
LOCAL_MODULE_TAGS :=optional
LOCAL_ADDITIONAL_DEPENDENCIES:= $(LOCAL_PATH)/Android.mk
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
include $(BUILD_SHARED_LIBRARY)

# SE050 BASED TESTS
# Unit tests for libkeymaster
include $(CLEAR_VARS)
LOCAL_MODULE := se050keymaster_tests
LOCAL_SRC_FILES := \
  src/system_keymaster/se050_keymaster_tests.cpp

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/../include \
    $(LOCAL_PATH)/include \
    $(LOCAL_PATH)/../
LOCAL_CFLAGS = -Wall -Werror -Wunused -DKEYMASTER_NAME_TAGS
LOCAL_CFLAGS +=-DSSS_USE_FTR_FILE \
    -I $(ANDROID_ROOT)/../simw-top_build/android_arm64/ \
    -I $(ANDROID_ROOT)/../simw-top/sss/inc/ \
    -I $(ANDROID_ROOT)/../simw-top/sss/port/default/ \
    -I $(ANDROID_ROOT)/../simw-top/ext/mbedtls/include/ \
    -I $(ANDROID_ROOT)/../simw-top/hostlib/hostLib/libCommon/infra/ \
    -I $(ANDROID_ROOT)/../simw-top/hostlib/hostLib/libCommon/log/ \
    -I $(ANDROID_ROOT)/../simw-top/hostlib/hostLib/inc/ \
    -I $(ANDROID_ROOT)/../simw-top/hostlib/hostLib/se05x_03_xx_xx/ \
    -I $(ANDROID_ROOT)/../simw-top/sss/ex/inc/

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
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_NATIVE_TEST)

