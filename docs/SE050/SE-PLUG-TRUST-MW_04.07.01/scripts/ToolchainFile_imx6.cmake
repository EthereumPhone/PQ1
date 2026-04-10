# Copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
# Run cmake & the subsequent makes from a shell where the cross compilation environment has been set.
# > E.g. "source /opt/fsl-imx-fb/4.9.11-1.0.0/environment-setup-cortexa7hf-neon-poky-linux-gnueabi"

# General CMAKE cross compile settings
SET(CMAKE_SYSTEM_NAME Linux)
SET(CMAKE_SYSTEM_VERSION 1)

# where is the target environment
#SET(CMAKE_FIND_ROOT_PATH  /opt/fsl-imx-fb/4.9.11-1.0.0/sysroots/cortexa7hf-neon-poky-linux-gnueabi)
#SET(CMAKE_FIND_ROOT_PATH  /opt/fsl-imx-fb/4.9.88-2.0.0/sysroots/cortexa7hf-neon-poky-linux-gnueabi)
SET(CMAKE_FIND_ROOT_PATH $ENV{OECORE_TARGET_SYSROOT})

# search for programs in the build host directories
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
