# Copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(openssl LANGUAGES C)

FILE(
    GLOB
    openssl_sources
    include/openssl/*.h
)

ADD_LIBRARY(openssl INTERFACE)
