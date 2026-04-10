/**
 * @file mainRjct.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Connection Oriented TCP/IP Server implementing Remote JCTerminal Protocol.
 * The server can connect to the secure element via the
 * - SCI2C protocol
 * - T1oI2C protocol
 * @par History
 *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>

#include "rjct.h"

#if defined(SCI2C)
#include "apduComm.h"
#include "sci2c.h"
#endif

#define PORT "8050"  // the port users will be connecting to
#define BACKLOG 1     // how many pending connections queue will hold

#define APP_BUFFER 2048

#if defined(SCI2C)
#define MAX_READ_SOCKET 2000
#elif defined(TDA8029_UART)
#define MAX_READ_SOCKET 500
#elif defined(PCSC)
#define MAX_READ_SOCKET 1024
#elif defined(SMCOM_JRCP_V2)
// TODO: Check value
#define MAX_READ_SOCKET 2000
#elif defined(T1oI2C)
// TODO: Check value
#define MAX_READ_SOCKET 2000
#else
    #error "No communication channel defined"
#endif

#define ERROR_VERBOSE

#ifndef FLOW_VERBOSE
#define FLOW_VERBOSE
#endif

// #define DBG_VERBOSE

#ifdef ERROR_VERBOSE
#define EPRINTF(...) printf (__VA_ARGS__)
#else
#define EPRINTF(...)
#endif

#ifdef FLOW_VERBOSE
#define FPRINTF(...) printf (__VA_ARGS__)
#else
#define FPRINTF(...)
#endif

#ifdef DBG_VERBOSE
#define DPRINTF(...) printf (__VA_ARGS__)
#else
#define DPRINTF(...)
#endif


static void sigchld_handler(int s)
{
    AX_UNUSED_ARG(s);
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

// get sockaddr, IPv4 or IPv6:
static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(void)
{
    int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo = NULL, *p = NULL;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    U8 targetBuffer[APP_BUFFER];
    U16 targetBufferLen = sizeof(targetBuffer);
    U16 statusValue = 0;
    U8 respBuf[APP_BUFFER] = {0};
    U16 respBufLen = sizeof(respBuf);
    static bool sessionOpen =  FALSE;

    // U8 result = 1;
    U16 connectStatus = 0;
#if defined(TDA8029_UART) || defined(SCI2C) || defined(PCSC) || defined(SMCOM_JRCP_V2) || defined(T1oI2C)
    U8 Atr[64];
    U16 AtrLen = sizeof(Atr);
    SmCommStateRjct_t commState;
    // Scp03SessionState_t sessionState;
#endif

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0)
    {
        EPRINTF("getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        EPRINTF("server: failed to bind\n");
        if(servinfo){
            freeaddrinfo(servinfo); // all done with this structure
        }
        return 2;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }

#if defined(TDA8029_UART)
    printf("RemoteJCShell Terminal Server (supporting TDA-8029-UART to smartcard) Rev 0.91\n");
#elif defined(SCI2C)
    printf("RemoteJCShell Terminal Server (supporting SCI2C) Rev 0.92\n");
    #if defined(TGT_A71CH) || defined(TGT_A71CL)
        printf("A71 (I2C_CLK_MAX = 400 kHz) - Effective Master Clock depends on Host Platform.\n");
    #else
        printf("A70 (I2C_CLK_MAX = 100 kHz) - Effective Master Clock depends on Host Platform.\n");
    #endif
#elif defined (PCSC)
    printf("RemoteJCShell Terminal Server (supporting PCSC) Rev 0.92\n");
#elif defined(SMCOM_JRCP_V2)
    printf("RemoteJCShell Terminal Server (supporting JRCPv2 Client Side)\n");
#elif defined(T1oI2C)
    printf("RemoteJCShell Terminal Server (supporting T1oI2C Client Side)\n");
#else
    #error "No interconnect defined: supported are TDA8029_UART, SCI2C and PCSC"
#endif
    printf("******************************************************************************\n");
    printf("Establish a connection via JCShell:\n");
    printf("\t/term Remote|<ip-address>:<port>\n");
    printf("\t e.g.\n");
    printf("\t /term Remote|192.168.1.27:8050\n");
    printf("\n");
    printf("Server: waiting for connections...\n");

    while (1)  // main accept() loop
    {
        sin_size = sizeof their_addr;

        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1)
        {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        FPRINTF("Server: got connection from %s\n", s);

        if (!fork())
        { // this is the child process
            unsigned int nExpectedPayload = 0;

            close(sockfd); // child doesn't need the listener

            while(1)
            {
                U8 rcvBuf[APP_BUFFER];
                int nRcv;
                int nRcvAcc;
                int i;
                U8 emptyDbgInfo[] = {DEBUG_INFORMATION, 0x00, 0x00, 0x00};
                U8 emptyTerminalInfo[] = {TERMINAL_INFO, 0x00, 0x00, 0x00};
                nRcv = recv(new_fd, rcvBuf, 4, MSG_WAITALL);
                nRcvAcc = nRcv;

                switch (nRcv)
                {
                    case -1:
                        perror("recv");
                        FPRINTF("recv() failed: %d\n", nRcv);
                        exit(0);
                    break;

                    case 0:
                        FPRINTF("Connection closed by client (%d)\n", nRcv);
#if defined(SCI2C)
                        sci2c_TerminateI2C(1);
#endif
                        exit(0);
                    break;

                    default:
                        DPRINTF("Received: \n");
                        for (i=0; i<nRcv; i++)
                        {
                            DPRINTF("0x%02X:", rcvBuf[i]);
                        }
                        DPRINTF("\n");
                        if (nRcv < 4)
                        {
                            EPRINTF("nRcv = %d (nRcv = 0x%08X).\n", nRcv, nRcv);
                            EPRINTF("Did not expect a payload less than 4 byte. Closing socket. Bye!\n");
                            close(new_fd);
                            exit(0);
                        }
                        nExpectedPayload = (rcvBuf[2] << 8) + rcvBuf[3];
                        if ((unsigned int)nRcv < (nExpectedPayload + 4))
                        {
                            // Read more data from socket
                            if (nExpectedPayload > MAX_READ_SOCKET)
                            {
                                EPRINTF("nExpectPayload too big %u (limit=%d).\n", nExpectedPayload, MAX_READ_SOCKET);
                                exit(0);
                            }
                            nRcv = recv(new_fd, rcvBuf+4, nExpectedPayload, 0);
                            if (nRcv == -1)
                            {
                                perror("Error on additional read");
                                exit(0);
                            }
                            else if (nRcv == 0)
                            {
                                EPRINTF("Connection was closed by client on additional read.\n");
                                exit(0);
                            }
                            else if (nRcv < 0)
                            {
                                EPRINTF("recv returns error on additional read. nRcv = %d (nRcv = 0x%08X).\n", nRcv, nRcv);
                                exit(0);
                            }
                            else
                            {
                                DPRINTF("Received: \n");
                                for (i=0; i<nRcv; i++)
                                {
                                    DPRINTF("0x%02X:", rcvBuf[nRcvAcc+i]);
                                }
                                DPRINTF("\n");
                                if (((nRcv > 0) && (nRcvAcc > (INT_MAX - nRcv))) || ((nRcv < 0) && (nRcvAcc < (INT_MIN - nRcv)))) {
                                    exit(0);
                                }
                                nRcvAcc += nRcv;
                            }
                        }

                        if ((unsigned int)nRcvAcc == (nExpectedPayload + 4))
                        {
                            // Interpret the message contained in rcvBuf
                            switch (rcvBuf[0])
                            {
                            case WAIT_FOR_CARD:
                                //Hanle reset
                                if(sessionOpen)
                                {
                                    /*session is already open close the session first */
                                    connectStatus = SM_CloseRjct(1);
                                    if (connectStatus != SW_OK)
                                    {
                                        U8 errMsg[] = {WAIT_FOR_CARD, 0x00, 0x00, 0x00};
                                        EPRINTF("Failed to establish connection to Secure Module: 0x%04X\n", connectStatus);
                                        if (send(new_fd, errMsg, sizeof(errMsg), 0) == -1)
                                        {
                                            perror("send");
                                            close(new_fd);
                                            exit(0);
                                        }
                                    }
                                    sessionOpen = FALSE;
                                }
                                DPRINTF("Establish connection and issue an ATR.\n");
                                AtrLen = sizeof(Atr);
                                connectStatus = SM_ConnectRjct(&commState, Atr, &AtrLen);
                                if (connectStatus != SW_OK)
                                {
                                    U8 errMsg[] = {WAIT_FOR_CARD, 0x00, 0x00, 0x00};
                                    EPRINTF("Failed to establish connection to Secure Module: 0x%04X\n", connectStatus);
                                    if (send(new_fd, errMsg, sizeof(errMsg), 0) == -1)
                                    {
                                        perror("send");
                                        close(new_fd);
                                        exit(0);
                                    }
                                }
                                else
                                {
                                    int i=0;
                                    FPRINTF("ATR=0x");
                                    for (i=0; i<AtrLen; i++) printf("%02X.", Atr[i]);
                                    FPRINTF("\n");
#if defined(TDA8029_UART)
                                    FPRINTF("UART Baudrate Idx: 0x%02X\n", commState.param2);
                                    FPRINTF("T=1           TA1: 0x%02X\n", commState.param1);
#endif
                                    targetBufferLen = sizeof(targetBuffer);
                                    statusValue = rjctPackageApduResponse(WAIT_FOR_CARD, 0x00, Atr, AtrLen, targetBuffer, &targetBufferLen);
                                    if (statusValue == RJCT_OK)
                                    {
                                        if (send(new_fd, targetBuffer, targetBufferLen, 0) == -1)
                                        {
                                            EPRINTF("Returning ATR to JCShell client failed\n");
                                            close(new_fd);
                                            exit(0);
                                        }
                                    }
                                    else
                                    {
                                        EPRINTF("Could not package APDU response (Line=%d).\n", __LINE__);
                                    }
                                    sessionOpen = TRUE;
                                }
                                break;
                            case APDU_DATA:
                                respBufLen = sizeof(respBuf);
                                statusValue = SM_SendAPDURjct(&rcvBuf[4], nExpectedPayload, respBuf, &respBufLen);
                                if (statusValue == SW_OK)
                                {
                                    targetBufferLen = sizeof(targetBuffer);
                                    statusValue = rjctPackageApduResponse(APDU_DATA, 0x00, respBuf, respBufLen, targetBuffer, &targetBufferLen);
                                    if (statusValue == RJCT_OK)
                                    {
                                        int nRet = send(new_fd, targetBuffer, targetBufferLen, 0);
                                        if (nRet == -1)
                                        {
                                            perror("send (Returning APDU Response to JCShell client failed)");
                                            close(new_fd);
                                            exit(0);
                                        }
                                        else if (nRet != targetBufferLen)
                                        {
                                            EPRINTF("Did not return full response, fix TCP/IP server.\n");
                                            close(new_fd);
                                            exit(0);
                                        }
                                    }
                                    else
                                    {
                                        EPRINTF("Could not package APDU response (Line=%d).\n", __LINE__);
                                    }
                                }
                                else
                                {
                                    EPRINTF("SM_SendAPDU failed with statusValue: 0x%04X.\n", statusValue);
                                    EPRINTF("*********************************************");
                                    close(new_fd);
                                    exit(0);
                                }
                                break;
                            case DEBUG_INFORMATION:
                                printf("Received a debug info message. Return DEBUG_INFO without data payload.\n");
                                if (send(new_fd, emptyDbgInfo, sizeof(emptyDbgInfo), 0) == -1)
                                {
                                    perror("Send failed.\n");
                                    close(new_fd);
                                    exit(0);
                                }
                                break;
                            case TERMINAL_INFO:
                                printf("Received a terminal info message. Return TERMINAL_INFO without data payload.\n");
                                if (send(new_fd, emptyTerminalInfo, sizeof(emptyTerminalInfo), 0) == -1)
                                {
                                    perror("Send failed.\n");
                                    close(new_fd);
                                    exit(0);
                                }
                                break;
                            case STATUS:
                            case ERROR_MSG:
                            case INITIALIZATION_DATA:
                            case INFORMATION_TEXT:
                                EPRINTF("Don't know how to deal with Message Type 0x%02X.\n", rcvBuf[0]);
                                exit(0);
                                break;
                            default:
                                EPRINTF("Don't know how to deal with Message Type 0x%02X.\n", rcvBuf[0]);
                                exit(0);
                                break;
                            }
                        }
                        else
                        {
                            EPRINTF("Expected the full payload. nRcvAcc=%d, nExpectedPayload=%u, sizeofInt(%d)\n", nRcvAcc, nExpectedPayload, (int)sizeof(nRcvAcc));
                            EPRINTF("NOTE: nRcvAcc should equal (nExpectPayload + 4)\n");
                            close(new_fd);
                            exit(0);
                        }
                    break;
                }
            }
            exit(0);
        }
        close(new_fd);  // parent doesn't need this
    }

    return 0;
}
