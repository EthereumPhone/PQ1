# copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

#This file is required for ANDROID to create binaries for SE05X
#Android Keymaster does not have  dependancies on below source files, but these binaries can be useful
#to verify Communication between Host and SE05X

include $(CLEAR_VARS)

LOCAL_MODULE := jrcpv1_server
LOCAL_SRC_FILES := \
    hostlib/hostLib/rjct/src/mainRjct.c \
    hostlib/hostLib/rjct/src/rjct.c \
    hostlib/hostLib/rjct/src/rjct_com.c \

LOCAL_C_INCLUDES := \
    $(SIMW_TOP_PATH)/hostlib/hostLib/rjct/inc/ \
    $(SIMW_TOP_PATH)/akm/ \
    $(SIMW_TOP_PATH)/sss/ex/inc \
    $(SIMW_TOP_PATH)/sss/inc \
    $(SIMW_TOP_PATH)/sss/port/default \
    $(SIMW_TOP_PATH)/ext/mbedtls/include \
    $(SIMW_TOP_PATH)/hostlib/hostLib/se05x_03_xx_xx \
    $(SIMW_TOP_PATH)/hostlib/hostLib/inc \
    $(SIMW_TOP_PATH)/hostlib/hostLib/libCommon/smCom \
    $(SIMW_TOP_PATH)/hostlib/hostLib/libCommon/infra \
    $(SIMW_TOP_PATH)/hostlib/hostLib/libCommon/log \

LOCAL_CFLAGS = -Wall -Werror -Wunused -Wno-missing-field-initializers -DKEYMASTER_NAME_TAGS -DSSS_USE_FTR_FILE -DT1oI2C
LOCAL_CLANG := true
LOCAL_CLANG_CFLAGS += -Wno-error=unused-const-variable -Wno-error=unused-private-field -Wno-error-unused-parameter
LOCAL_CLANG_CFLAGS += -fno-sanitize-coverage=edge,indirect-calls,8bit-counters,trace-cmp
LOCAL_MODULE_TAGS := tests

LOCAL_SHARED_LIBRARIES := \
    libse050keymasterdevice \

include $(BUILD_NATIVE_TEST)
