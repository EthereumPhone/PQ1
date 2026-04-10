#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(lpc55s_veneer)
ADD_LIBRARY(lpc55s_veneer INTERFACE)

TARGET_INCLUDE_DIRECTORIES(
    lpc55s_veneer
    INTERFACE .
)
