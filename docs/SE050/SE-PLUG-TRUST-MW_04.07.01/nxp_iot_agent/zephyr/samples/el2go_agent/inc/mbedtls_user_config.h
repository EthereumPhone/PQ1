/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __MBEDTLS_USER_CONFIG_H__
#define __MBEDTLS_USER_CONFIG_H__

// Defines which cannot be specified in prj.conf
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE

#endif /* __MBEDTLS_USER_CONFIG_H__ */
