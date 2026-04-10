/**
 * @file snw_util.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description:
 * Wrappers for basic network functionality
 *
 */

#ifndef SNW_COMMON_H_
#define SNW_COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>

#define SSS_USE_FTR_FILE
#define FTR_FILE_SYSTEM

#include <se05x/fsl_sss_ftr.h>
#include <se05x/sm_types.h>
#include <se05x/fsl_sss_api.h>
#include <se05x/ex_sss_boot.h>

#if SSS_HAVE_APPLET_SE05X_IOT
#include <se05x/fsl_sss_se05x_types.h>
#endif


#define SE_TLS_CLIENT_OK                          0
#define SE_TLS_CLIENT_CMDLINE_ARGS                1
#define SE_TLS_CLIENT_BUFFER_TOO_SMALL            2
#define SE_TLS_CLIENT_ILLEGAL_PORT_NR             3

#define SE_TLS_CLIENT_TCP_SETUP_ERROR           100
#define SE_TLS_CLIENT_TCP_CONNECT_ERROR         101

#define SE_TLS_CLIENT_SSL_LIB_INIT_ERROR        200
#define SE_TLS_CLIENT_SSL_INIT_ERROR            201
#define SE_TLS_CLIENT_SSL_CERT_ERROR            202
#define SE_TLS_CLIENT_SSL_KEY_ERROR             203
#define SE_TLS_CLIENT_SSL_CONNECT_ERROR         204
#define SE_TLS_CLIENT_SSL_CONNECT_TIMEOUT_ERROR 205
#define SE_TLS_CLIENT_SSL_WRITE_TIMEOUT_ERROR   206
#define SE_TLS_CLIENT_SSL_WRITE_ERROR           207

#define SE_ERR_SE_GP_ACCESS                  300
#define SE_ERR_SE_GP_NO_CERT                 301
#define SE_ERR_SE_LOADING_ENGINE_ERR         302

// The certificate must be provisioned on this Object ID
#define OBJID_DEMO_EC_TLS_CLIENT_CERT  0x7DCCBB11 // EC
#define OBJID_DEMO_RSA_TLS_CLIENT_CERT 0X7DCCBB31 // RSA

#define OK_STATUS      0
#define FAILURE_STATUS 1

#define SSL_CONNECTED    1
#define SELECT_TIMEOUT   0
#define SELECT_ERROR    -1

#if defined(__cplusplus)
extern "C" {
#endif

int snwTcpConnect(int socket_fd, char *pURLString, int port);
int snwSetSocketNonBlocking(int server_fd);
int snwSslConnect(SSL *pSSL, int server_fd, int timeout_ms);
int snwSslWrite(SSL *pSSL, int server_fd, unsigned char *msg, int *totalLen, int timeout_ms);

int wrapConnectToSe(ex_sss_boot_ctx_t *pSeBootCtx);
void wrapDisconnectFromSe(ex_sss_boot_ctx_t *pSeBootCtx);
int seGetClientCertificate(sss_key_store_t *keyStore, int certId, U8 *clientCertDer, size_t *clientCertDerLen);

void snwPrintDataAsHex(U8* data, U16 dataLen);

#if defined(__cplusplus)
}
#endif

#endif /* SNW_COMMON_H_ */
