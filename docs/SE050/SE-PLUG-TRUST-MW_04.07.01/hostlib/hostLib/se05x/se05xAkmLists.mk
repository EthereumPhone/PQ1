#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

#This file is required for ANDROID to compile all se05x and Applet version based source files.
#Android Keymaster is having dependancies on below source files.

SE05X_SRC_FILES_LIST := \
		hostlib/hostLib/se05x/src/se05x_tlv.c \
		hostlib/hostLib/se05x/src/se05x_mw.c \
		hostlib/hostLib/se05x/src/se05x_ECC_curves.c \

APPLET_03_00_SRC_FILES_LIST := hostlib/hostLib/se05x_03_xx_xx/se05x_APDU.c
APPLET_03_00_C_INCLUDES := hostlib/hostLib/se05x_03_xx_xx

