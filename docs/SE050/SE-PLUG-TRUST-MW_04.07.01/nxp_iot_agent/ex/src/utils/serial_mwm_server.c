/*
 * Copyright 2020-2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "serial_mwm_server.h"
#include "board.h"
#include "FreeRTOS.h"
#include "task.h"


#if defined(LPC_WIFI)

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define MWM_BUFFER_SIZE     1024u

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

extern int mwm_tx(uint8_t *write_buf, uint32_t len);
extern int mwm_rx(uint8_t *read_buf, uint32_t len);

/*******************************************************************************
 * Variables
 ******************************************************************************/
static uint8_t s_buff[MWM_BUFFER_SIZE];

/*******************************************************************************
 * Code
 ******************************************************************************/

static int read_string_max(uint8_t *s, uint32_t max_len)
{
    int ret;
    int idx = 0;
    uint8_t c;

    do
    {
        ret = mwm_rx(&c, 1);
        if (ret != 0)
        {
            return -1;
        }

        s[idx++] = c;

    } while ((c != 0u) && ((uint32_t)idx < max_len));

    if ((c != 0u) && ((uint32_t)idx == max_len))
    {
        return -1;
    }

    return idx;
}

static int read_int(int *val)
{
    int ret;

    ret = read_string_max(s_buff, MWM_BUFFER_SIZE);
    if (ret < 0)
    {
        return -1;
    }

    /* Parse int */
    *val = strtol((char *)s_buff, NULL, 10);

    return 0;
}

static int read_string(const char *s)
{
    int ret;
    size_t n;

    n   = strlen(s);
    ret = mwm_rx(s_buff, n);
    if (ret < 0)
    {
        return ret;
    }

    if (strncmp((char *)s_buff, s, n) != 0)
    {
        return -1;
    }

    return 0;
}

/* Read 1 byte which should be equal to "\0" */
static int read_end(void)
{
    int ret;
    uint8_t c;

    ret = mwm_rx(&c, 1);
    if (ret < 0)
    {
        return ret;
    }

    /* Check value */
    if (c != 0u)
    {
        return -1;
    }

    return 0;
}

static int read_errno(int *errno)
{
    int ret;
    ret = read_string("errno:");
    if (ret < 0)
    {
        return ret;
    }

    ret = read_int(errno);
    if (ret < 0)
    {
        return ret;
    }

    ret = read_end();
    if (ret < 0)
    {
        return ret;
    }

    return 0;
}

/* Send cmd and return status code of received response */
static int mwm_cmd(char *cmd)
{
    int ret;
    size_t cmd_len;

    cmd_len = strlen(cmd);
    ret     = mwm_tx((uint8_t *)cmd, (uint32_t)cmd_len);
    if (ret < 0)
    {
        return -1;
    }

    int status_code = -1;
    ret             = read_int(&status_code);
    if (ret < 0)
    {
        return ret;
    }

    if (status_code == MWM_SOCKET_ERROR)
    {
        int errno = 1;
        ret       = read_errno(&errno);
        if (ret < 0)
        {
            return ret;
        }

        return -errno;
    }

    return status_code;
}

int mwm_bind(int socket, mwm_sockaddr_t *addr, uint32_t addrlen)
{
    int ret = -1;
    ret     = snprintf((char *)s_buff, MWM_BUFFER_SIZE, "mwm+nbind=%d,%s,%d\n", socket, addr->host, addr->port);
    //ret     = snprintf((char *)s_buff, MWM_BUFFER_SIZE, "mwm+nbind=%d,,%d\n", socket, addr->port);
    if ((ret <= 0) || ((uint32_t)ret > MWM_BUFFER_SIZE))
    {
        return -1;
    }

    ret = mwm_cmd((char *)s_buff);
    if (ret < 0)
    {
        return ret;
    }

    /* Read end of response */
    ret = read_end();

    return ret;
}


int mwm_listen(int socket, int backlog)
{
    int ret = -1;
    ret     = snprintf((char *)s_buff, MWM_BUFFER_SIZE, "mwm+nlisten=%d,%d\n", socket, backlog);
    if ((ret <= 0) || ((uint32_t)ret > MWM_BUFFER_SIZE))
    {
        return -1;
    }

    ret = mwm_cmd((char *)s_buff);
    if (ret < 0)
    {
        return ret;
    }

    /* Read end of response */
    ret = read_end();

    return ret;
}

int mwm_accept(int socket)
{
    int ret = -1;

    do {
        ret     = snprintf((char *)s_buff, MWM_BUFFER_SIZE, "mwm+naccept=%d\n", socket);
        if ((ret <= 0) || ((uint32_t)ret > MWM_BUFFER_SIZE))
        {
            return -1;
        }
    	ret = mwm_cmd((char *)s_buff);
    } while(ret == -11);

    if (ret < 0)
    {
    	return ret;
    }

    ret = read_string("handle:");
    if (ret < 0)
    {
        return ret;
    }

    int handle = 0;
    ret = read_int(&handle);
    if (ret < 0)
    {
        return ret;
    }

    /* Read end of response */
    ret = read_end();
    if (ret < 0)
    {
        return ret;
    }

    return handle;
}

#endif //LPC_WIFI
