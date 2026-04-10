/**
 * @file smComSocket_linux.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2016,2020,2025 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 *
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <netdb.h>

#include "smCom.h"
#include "smComSocket.h"
#include "sm_printf.h"
#include "sm_types.h"
#include "nxLog_smCom.h"
#include "nxEnsure.h"

// Enable define of LOG_SOCK to echo APDU cmd/rsp
// #define LOG_SOCK

// Enable define of CHECK_ON_ATR to enable check on returned ATR (don't enable this when using the Smart Card Server ...)
// #define CHECK_ON_ATR

#define REMOTE_JC_SHELL_HEADER_LEN             (4)
#define REMOTE_JC_SHELL_MSG_TYPE_APDU_DATA  (0x01)

#include "sm_apdu.h"

#define MAX_BUF_SIZE                (MAX_APDU_BUF_LENGTH)

typedef struct
{
    int sockfd;
    char * ipString;
} socket_Context_t;

static socket_Context_t* gpSockCtx = NULL;

static U32 smComSocket_GetATR(socket_Context_t* pSockCtx, U8* pAtr, U16* atrLen);

U16 smComSocket_Close(void* conn_ctx)
{
    socket_Context_t* pSockCtx = (socket_Context_t*)conn_ctx;
    if (pSockCtx != NULL){
        if (pSockCtx->ipString != NULL)
            free(pSockCtx->ipString);
        pSockCtx->ipString = NULL;
        close(pSockCtx->sockfd);
        if (pSockCtx == gpSockCtx){
            gpSockCtx = NULL;
        }
        free(pSockCtx);
    }
    return SW_OK;
}

U16 smComSocket_Open(void** conn_ctx, U8 *pIpAddrString, U16 portNo, U8* pAtr, U16* atrLen)
{
    int portno;
    int nAtr = 0;
#ifdef ACCESS_MGR_UNIX_SOCKETS
    struct sockaddr_un serv_addr;
#else
    struct sockaddr_in serv_addr;
#endif
    struct hostent *server;
    U16 sw = SMCOM_COM_FAILED;

    ENSURE_OR_GO_EXIT(pIpAddrString != NULL);

    socket_Context_t* pSockCtx = malloc(sizeof(socket_Context_t));
    ENSURE_OR_GO_EXIT(pSockCtx != NULL);

    portno = portNo;
#ifdef ACCESS_MGR_UNIX_SOCKETS
    pSockCtx->sockfd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
#else
    pSockCtx->sockfd = socket(AF_INET, SOCK_STREAM, 0);
#endif
    if (pSockCtx->sockfd < 0)
    {
        printf("ERROR opening socket");
        return SMCOM_COM_FAILED;
    }

#ifdef ACCESS_MGR_UNIX_SOCKETS
    memset(&serv_addr, 0, sizeof(struct sockaddr_un));
    serv_addr.sun_family = AF_UNIX;
    if (strlen(pIpAddrString) > sizeof(serv_addr.sun_path) - 1) {
        return SMCOM_COM_FAILED;
    }
    strcpy(serv_addr.sun_path, pIpAddrString);
#else
    pSockCtx->ipString = malloc(strlen((char*)pIpAddrString)+1);
    strcpy(pSockCtx->ipString, (char*)pIpAddrString);

    server = gethostbyname(pSockCtx->ipString);
    if (server == NULL)
    {
        fprintf(stderr,"ERROR, no such host: %s\r\n", pSockCtx->ipString);
        return SMCOM_COM_FAILED;
    }
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy((char *)&serv_addr.sin_addr.s_addr,
        (char *)server->h_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);
#endif
    if (connect(pSockCtx->sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
    {
        printf("ERROR connecting\r\n");
        return SMCOM_PROTOCOL_FAILED;
    }

    sw = smCom_Init(smComSocket_Transceive, smComSocket_TransceiveRaw);
    if (sw != SMCOM_OK)
        goto exit;

    nAtr = smComSocket_GetATR(pSockCtx, pAtr, atrLen);
#ifdef CHECK_ON_ATR
    // Be aware that the smart card server (java app on PC) does not return the ATR value
    // Do not enable this code when using the smart card server
    if (nAtr == 0)
    {
        sw = SMCOM_NO_ATR;
    }
#endif

    if (conn_ctx != NULL){
        *conn_ctx = pSockCtx;
    }
    else {
        gpSockCtx = pSockCtx;
    }

exit:
    return sw;
}

/**
    Remote JC Terminal spec:
    Wait for card (MTY=0x00)
    The payload contains four bytes denoting the time in milliseconds the remote part will wait for card insertion.
    The bytes are sent in big endian format.

    The reply message contains the full ATR as payload.
    A reply message with 0 bytes length means that the terminal could not trigger an ATR (reason might be retrieved using MTY=3 or MTY=2.
*/
static U32 smComSocket_GetATR(socket_Context_t* pSockCtx, U8* pAtr, U16* atrLen)
{
    return smComSocket_GetATRFD(pSockCtx->sockfd, pAtr, atrLen);
}

U32 smComSocket_Transceive(void* conn_ctx, apdu_t * pApdu)
{
    socket_Context_t* pSockCtx = (conn_ctx == NULL)? gpSockCtx :(socket_Context_t*)conn_ctx;
    return smComSocket_TransceiveFD(pSockCtx->sockfd, pApdu);
}

U32 smComSocket_TransceiveRaw(void* conn_ctx, U8 * pTx, U16 txLen, U8 * pRx, U32 * pRxLen)
{
    socket_Context_t* pSockCtx = (conn_ctx == NULL)? gpSockCtx :(socket_Context_t*)conn_ctx;
    return smComSocket_TransceiveRawFD(pSockCtx->sockfd, pTx, txLen, pRx, pRxLen);
}


U32 smComSocket_LockChannel(void *conn_ctx)
{
    socket_Context_t* pSockCtx = (conn_ctx == NULL)? gpSockCtx :(socket_Context_t*)conn_ctx;
    return smComSocket_LockChannelFD(pSockCtx->sockfd);
}

U32 smComSocket_UnlockChannel(void *conn_ctx)
{
    socket_Context_t* pSockCtx = (conn_ctx == NULL)? gpSockCtx :(socket_Context_t*)conn_ctx;
    return smComSocket_UnlockChannelFD(pSockCtx->sockfd);
}

U32 smComSocket_AmResetI2C(void *conn_ctx)
{
    socket_Context_t* pSockCtx = (conn_ctx == NULL)? gpSockCtx :(socket_Context_t*)conn_ctx;
    return smComSocket_AmResetI2CFD(pSockCtx->sockfd);
}