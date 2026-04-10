/*
 *  TCP/IP or UDP/IP networking functions
 *  modified for LWIP support on ESP8266
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Additions Copyright (C) 2015 Angus Gratton
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/* Copyright 2021 NXP
 */
#if defined(USE_RTOS) && USE_RTOS == 1

#include <sys/types.h>

#include "FreeRTOS.h"
#include "task.h"

#include "board.h"
#include "ksdk_mbedtls.h"
#include "nxLog_App.h"

#include "fsl_device_registers.h"
#include "pin_mux.h"
#include "clock_config.h"

/* Disabling for LPC_WIFI to fix build as
 * porting to new shield needs to be done.
 * Once porting is done, this should be enabled
 */
#if defined(LPC_WIFI)
#include "iot_wifi.h"
#include "wifi_config.h"
#include "serial_mwm.h"
#endif // defined(LPC_WIFI)
#include "mbedtls/net.h"



/*
 * Initialize a context
 */
void mbedtls_net_init( mbedtls_net_context *ctx )
{
    ctx->fd = -1;
}

/*
 * Initiate a TCP connection with host:port and the given protocol
 */
int mbedtls_net_connect( mbedtls_net_context *ctx, const char *host, const char *port, int proto )
{
#if defined(LPC_WIFI)
    int ret = 0;
    mwm_sockaddr_t http_srv_addr = {0};

    strcpy(http_srv_addr.host, host);
    http_srv_addr.port = atoi(port);

    ret = mwm_wlan_status();
    if (ret != MWM_CONNECTED)
    {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }

    ctx->fd = mwm_socket(MWM_TCP);
    if (ctx->fd < 0)
    {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }

    ret = mwm_connect(ctx->fd, &http_srv_addr, sizeof(http_srv_addr));
    if (ret != 0)
    {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }

	return 0;
#else
    return -1;
#endif // LPC_WIFI
}

/*
 * Set the socket blocking or non-blocking
 */
int mbedtls_net_set_block( mbedtls_net_context *ctx )
{
	return -1;
}

int mbedtls_net_set_nonblock( mbedtls_net_context *ctx )
{
	return -1;
}

/* Read at most 'len' characters */
int mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len)
{
#if defined(LPC_WIFI)
	int ret = 0;
	int fd = ((mbedtls_net_context*)ctx)->fd;

	ret = mwm_recv_timeout(fd, (void*)buf, len, 15000);

    if (ret <= 0)
    {
        return( MBEDTLS_ERR_NET_RECV_FAILED );
    }

    return ret;
#else
    return -1;
#endif // LPC_WIFI
}

/*
 * Read at most 'len' characters, blocking for at most 'timeout' ms
 */
int mbedtls_net_recv_timeout( void *ctx, unsigned char *buf, size_t len,
                      uint32_t timeout )
{
	return mbedtls_net_recv(ctx, buf, len);
}

/*
 * Write at most 'len' characters
 */
int mbedtls_net_send( void *ctx, const unsigned char *buf, size_t len )
{
#if defined(LPC_WIFI)
	int ret = 0;
	int fd = ((mbedtls_net_context*)ctx)->fd;

    ret = mwm_send(fd, (void*)buf, len);

    if (ret <= 0)
    {
        return( MBEDTLS_ERR_NET_SEND_FAILED );
    }

    return ret;
#else
    return -1;
#endif // LPC_WIFI
}

/*
 * Gracefully close the connection
 */
void mbedtls_net_free( mbedtls_net_context *ctx )
{
#if defined(LPC_WIFI)
    if( ctx->fd == -1 )
        return;

    mwm_close(ctx->fd);

    ctx->fd = -1;
#endif // LPC_WIFI
}

#endif

