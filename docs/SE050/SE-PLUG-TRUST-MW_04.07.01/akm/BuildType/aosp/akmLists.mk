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

#This file is required to compile all akm realted  source files

AKM_SRC_FILES_LIST := \
    $(ANDROID_TOP_BUILD_DIR)/system/keymaster/ec_keymaster0_key.cpp \
    $(ANDROID_TOP_BUILD_DIR)/system/keymaster/ec_keymaster1_key.cpp \
    $(ANDROID_TOP_BUILD_DIR)/system/keymaster/ecdsa_keymaster1_operation.cpp \
    $(ANDROID_TOP_BUILD_DIR)/system/keymaster/keymaster0_engine.cpp \
    $(ANDROID_TOP_BUILD_DIR)/system/keymaster/keymaster1_engine.cpp \
    $(ANDROID_TOP_BUILD_DIR)/system/keymaster/keymaster_configuration.cpp \
    $(ANDROID_TOP_BUILD_DIR)/system/keymaster/rsa_keymaster0_key.cpp \
    $(ANDROID_TOP_BUILD_DIR)/system/keymaster/rsa_keymaster1_key.cpp \
    $(ANDROID_TOP_BUILD_DIR)/system/keymaster/rsa_keymaster1_operation.cpp \
    $(ANDROID_TOP_BUILD_DIR)/system/keymaster/soft_keymaster_context.cpp \
    akm/src/system_keymaster/se050_keymaster_device.cpp \
    akm/src/system_keymaster/se050_keymaster_utils.cpp \
    akm/src/system_keymaster/se050_keymaster_attestation_record.cpp \
    $(ANDROID_TOP_BUILD_DIR)/system/keymaster/soft_keymaster_logger.cpp

AKM_TEST_SRC_FILES := \
    akm/src/system_keymaster/se050_keymaster_tests.cpp
