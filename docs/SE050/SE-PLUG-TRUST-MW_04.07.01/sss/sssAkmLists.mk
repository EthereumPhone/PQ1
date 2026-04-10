# Copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

#This file is required for ANDROID to compile all sss api's and sss booting realted  source files.
#Android Keymaster is having dependancies on below source files.

SSS_SRC_FILES_LIST := \
		sss/src/fsl_sss_util_asn1_der.c\
		sss/src/fsl_sss_apis.c\
		sss/src/fsl_sss_util_rsa_sign_utils.c\
		sss/src/se05x/fsl_sss_se05x_scp03.c \
		sss/src/se05x/fsl_sss_se05x_apis.c \
		sss/src/se05x/fsl_sss_se05x_eckey.c \
		sss/src/se05x/fsl_sss_se05x_policy.c \
		sss/src/se05x/fsl_sss_se05x_mw.c \
		sss/src/mbedtls/fsl_sss_mbedtls_apis.c \
		sss/src/openssl/fsl_sss_openssl_apis.c \
		sss/src/keystore/keystore_cmn.c \
		sss/src/keystore/keystore_openssl.c \
		sss/src/keystore/keystore_pc.c \

SSS_BOOT_SRC_FILES_LIST := \
		sss/ex/src/ex_sss_boot_connectstring.c \
        sss/ex/src/ex_sss_boot.c \
        sss/ex/src/ex_sss_se05x.c \
        sss/ex/src/ex_sss_se05x_auth.c \
        sss/ex/src/ex_sss_scp03_auth.c \
        sss/ex/src/ex_sss_boot_sw.c \

