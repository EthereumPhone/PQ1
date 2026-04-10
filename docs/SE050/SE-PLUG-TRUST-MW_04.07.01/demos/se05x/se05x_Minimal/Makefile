#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

INCLUDE_FLAGS := -I/usr/local/include/se05x
DEFINES := -DSSS_USE_FTR_FILE
LIBRARY_PATH := -L/usr/local/lib

# Auto generated and copied by make install.
-include /usr/local/share/se05x/cmake_options.mak

SIMW_LIBRARIES := \
  -lex_common \
  -lSSS_APIs \
  -lse05x \
  -la7x_utils \
  -lsmCom

ifeq (1,$(SSS_HAVE_SMCOM_JRCP_V2))
  SIMW_LIBRARIES := $(SIMW_LIBRARIES) -ljrcplib
endif

OPENSSL_LIBRARIES := -lcrypto

# Inluding libraries twice for cyclic-depdendencies across libraries.
CFLAGS += -MD -MMD $(INCLUDE_FLAGS) \
 $(DEFINES) \
 $(LIBRARY_PATH) \
 $(SIMW_LIBRARIES) \
 $(SIMW_LIBRARIES) \
 $(OPENSSL_LIBRARIES) \
 $(LOCAL_LIBRARIES)

all:
	c++   -fPIC -g se05x_Minimal.c $(CFLAGS) -o se05x_Minimal

clean:
	-rm *.d
	-rm se05x_Minimal

-include se05x_Minimal.d
