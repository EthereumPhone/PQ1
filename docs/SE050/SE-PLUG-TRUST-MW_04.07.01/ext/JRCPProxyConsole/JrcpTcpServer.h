/* Copyright 2019 NXP
 *
 * This software is owned or controlled by NXP and may only be used
 * strictly in accordance with the applicable license terms.  By expressly
 * accepting such terms or by downloading, installing, activating and/or
 * otherwise using the software, you are agreeing that you have read, and
 * that you agree to comply with and are bound by, such license terms.  If
 * you do not agree to be bound by the applicable license terms, then you
 * may not retain, install, activate or otherwise use the software.
 */

#pragma once

#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
using namespace std;

#include "smComSerial_wrapper.hpp"


// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 4096
#define DEFAULT_PORT "8050"

class JrcpTcpServer
{
public:
	JrcpTcpServer();
	JrcpTcpServer(char* port, char* Vport);
	virtual ~JrcpTcpServer();

public:
	void disconnect();
	void listenAndConnect();
	int doTranscieve();
	void closeOnExit(bool);

private:
	WSADATA wsaData;
	int iResult;

	SOCKET ListenSocket;
	SOCKET ClientSocket;

	struct addrinfo *result;
	struct addrinfo hints;

	int iSendResult;
	int recvbuflen;
	char* port;
	char* VcomPort;

	SmComSerialWrapper *scw;
	friend class SmComSerialWrapper;
};

