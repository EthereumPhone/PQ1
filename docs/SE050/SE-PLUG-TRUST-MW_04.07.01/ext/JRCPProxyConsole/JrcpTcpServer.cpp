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

#include "JrcpTcpServer.h"

JrcpTcpServer::JrcpTcpServer()
{
	port = DEFAULT_PORT;
}

JrcpTcpServer::JrcpTcpServer(char* iport, char* Vport)
{
	recvbuflen = DEFAULT_BUFLEN;
	ListenSocket = INVALID_SOCKET;
	ClientSocket = INVALID_SOCKET;
	result = NULL;
	port = iport;
	VcomPort = Vport;
}

JrcpTcpServer::~JrcpTcpServer()
{

}

void JrcpTcpServer::disconnect()
{

	scw->smComVCom_Close();

	iResult = shutdown(ClientSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		/***/printf("shutdown failed with error: %d\n", WSAGetLastError());
	}

	// cleanup
	closesocket(ClientSocket);
	WSACleanup();
}

void JrcpTcpServer::closeOnExit(bool coe)
{
	scw->closeOn_exit = coe;
}

void JrcpTcpServer::listenAndConnect()
{
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		/***/printf("WSAStartup failed with error: %d\n", iResult);
		return;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, port, &hints, &result);
	if (iResult != 0) {
		/***/printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return;
	}

	// Create a SOCKET for connecting to server
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		/***/printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		/***/printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return;
	}
	freeaddrinfo(result);


	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		/***/printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return;
	}

	// Accept a client socket
	printf("Waiting for connection\n");
	ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		/***/printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return;
	}
	//No longer need server socket
	closesocket(ListenSocket);

	//Open and connect to Scard.
	scw = new SmComSerialWrapper(ClientSocket);
	iResult = scw->smComVCom_Open(VcomPort);
	if (iResult != 0) {
		disconnect();
		return;
	}
}



int JrcpTcpServer::doTranscieve()
{
	iResult = scw->smComVcom_JrcpTransceive();
	if (iResult != 0) {
		return iResult;
	}
	return 0;
}
