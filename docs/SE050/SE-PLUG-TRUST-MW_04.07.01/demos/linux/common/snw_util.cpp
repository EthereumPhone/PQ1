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

#include "snw_common.h"

int snwTcpConnect(int socket_fd, char *pURLString, int port)
{
    int nRet = SE_TLS_CLIENT_TCP_CONNECT_ERROR;
    int connect_status = -1;
    struct hostent *host;
    struct sockaddr_in dest_addr;

    host = gethostbyname(pURLString);

    if (NULL != host) {
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        dest_addr.sin_addr.s_addr = *(long*) (host->h_addr);
        memset(&(dest_addr.sin_zero), '\0', 8);

        connect_status = connect(socket_fd, (struct sockaddr *) &dest_addr,
                sizeof(struct sockaddr));
        if (connect_status != -1) {
            nRet = SE_TLS_CLIENT_OK;
        }
    }
    return nRet;
}

int snwSetSocketNonBlocking(int server_fd)
{
    int flags, status;
    int nRet = SE_TLS_CLIENT_OK;

    flags = fcntl(server_fd, F_GETFL, 0);
    // set underlying socket to non blocking
    if (flags < 0) {
        nRet = SE_TLS_CLIENT_TCP_CONNECT_ERROR;
    }

    status = fcntl(server_fd, F_SETFL, flags | O_NONBLOCK);
    if (status < 0) {
        printf("fcntl - %s", strerror(errno));
        nRet = SE_TLS_CLIENT_TCP_CONNECT_ERROR;
    }

    return nRet;
}

int snwSslConnect(SSL *pSSL, int server_fd, int timeout_ms)
{
    int nRet = SE_TLS_CLIENT_OK;
    int rc = 0;
    fd_set readFds;
    fd_set writeFds;
    struct timeval timeout = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    int errorCode = 0;
    int nSelect = SELECT_TIMEOUT;

    do {
        printf("Invoke SSL_connect()...\n");
        rc = SSL_connect(pSSL);

        if (SSL_CONNECTED == rc) {
            nRet = SE_TLS_CLIENT_OK;
            break;
        }

        errorCode = SSL_get_error(pSSL, rc);

        if (errorCode == SSL_ERROR_WANT_READ) {
            FD_ZERO(&readFds);
            FD_SET(server_fd, &readFds);
            nSelect = select(server_fd + 1, (fd_set *) &readFds, NULL, NULL, &timeout);
            if (SELECT_TIMEOUT == nSelect) {
                printf("sslConnectWrapper: time out while waiting for read.\n");
                nRet = SE_TLS_CLIENT_SSL_CONNECT_TIMEOUT_ERROR;
            }
            else if (SELECT_ERROR == nSelect) {
                printf("sslConnectWrapper: select error for read %d.\n", nSelect);
                nRet = SE_TLS_CLIENT_SSL_CONNECT_ERROR;
            }
        }
        else if (errorCode == SSL_ERROR_WANT_WRITE) {
            FD_ZERO(&writeFds);
            FD_SET(server_fd, &writeFds);
            nSelect = select(server_fd + 1, NULL, (fd_set *) &writeFds, NULL, &timeout);
            if (SELECT_TIMEOUT == nSelect) {
                printf("sslConnectWrapper: time out while waiting for write.\n");
                nRet = SE_TLS_CLIENT_SSL_CONNECT_TIMEOUT_ERROR;
            }
            else if (SELECT_ERROR == nSelect) {
                printf("sslConnectWrapper: select error for write %d.\n", nSelect);
                nRet = SE_TLS_CLIENT_SSL_CONNECT_ERROR;
            }
        }
        else {
            nRet = SE_TLS_CLIENT_SSL_CONNECT_ERROR;
        }

    } while ( (SE_TLS_CLIENT_SSL_CONNECT_ERROR != nRet) &&
              (SE_TLS_CLIENT_SSL_CONNECT_TIMEOUT_ERROR != nRet) );

    return nRet;
}

int snwSslWrite(SSL *pSSL, int server_fd, unsigned char *msg, int *totalLen, int timeout_ms)
{
    int nRet = SE_TLS_CLIENT_OK;
    fd_set writeFds;
    int errorCode = 0;
    int nSelect;
    int writtenLen = 0;
    int rc = 0;
    struct timeval timeout = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };

    do {
        rc = SSL_write(pSSL, msg, *totalLen);

        errorCode = SSL_get_error(pSSL, rc);

        if (0 < rc) {
            writtenLen += rc;
        }
        else if (errorCode == SSL_ERROR_WANT_WRITE) {
            FD_ZERO(&writeFds);
            FD_SET(server_fd, &writeFds);
            nSelect = select(server_fd + 1, NULL, (fd_set *) &writeFds, NULL, &timeout);
            if (SELECT_TIMEOUT == nSelect) {
                nRet = SE_TLS_CLIENT_SSL_WRITE_TIMEOUT_ERROR;
            }
            else if (SELECT_ERROR == nSelect) {
                nRet = SE_TLS_CLIENT_SSL_WRITE_ERROR;
            }
        }
        else {
            nRet = SE_TLS_CLIENT_SSL_WRITE_ERROR;
        }

    } while ( (SE_TLS_CLIENT_SSL_WRITE_ERROR != nRet) &&
              (SE_TLS_CLIENT_SSL_WRITE_TIMEOUT_ERROR != nRet) &&
              (writtenLen < *totalLen) );

    *totalLen = writtenLen;
    return nRet;
}

/* Print a hex array utility */
void snwPrintDataAsHex(U8* data, U16 dataLen)
{
    int i;
    for (i=0; i<(int)dataLen; i++)
    {
        if ( (i%16 == 0) && (i != 0) ) { printf("\n"); }
        printf("%02x:", data[i]);
    }
    printf("\n");
}
