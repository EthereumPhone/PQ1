/**
 * @file smComSerial.h
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 * Copyright(C) NXP Semiconductors, 2017
 * All rights reserved.
 *
 * This software is owned or controlled by NXP and may only be used
 * strictly in accordance with the applicable license terms.  By expressly
 * accepting such terms or by downloading, installing, activating and/or
 * otherwise using the software, you are agreeing that you have read, and
 * that you agree to comply with and are bound by, such license terms.  If
 * you do not agree to be bound by the applicable license terms, then you
 * may not retain, install, activate or otherwise use the software.
 *
 * @par Description
 *
 *****************************************************************************/


#include "smCom.h"
#include "windows.h"


#define REMOTE_JC_SHELL_HEADER_LEN          (4)
#define REMOTE_JC_SHELL_MSG_TYPE_APDU_DATA  (0x01)
#include "sm_apdu.h"
#define MAX_BUF_SIZE                (MAX_APDU_BUF_LENGTH)
#define JRCP_HEADER_LENGTH  4
#define JRCP_MTY_OFFSET  0
#define JRCP_NAD_OFFSET  1
#define JRCP_LNH_OFFSET  2
#define JRCP_LNL_OFFSET  3
#define JRCP_PAYLOAD_OFFSET  4

#define JRCP_WAIT_FOR_CARD  0
#define JRCP_APDU_DATA  1
#define JRCP_STATUS  2
#define JRCP_ERROR_MESSAGE  3
#define JRCP_TERMINAL_INFO  4
#define JRCP_INIT_INFO  5
#define JRCP_ECHO  6
#define JRCP_DEBUG  7
#define SMARTCARD_ERROR_NONE 0
#define JCSHELL_ERROR_NONE  0x9000

class SmComSerialWrapper
{

public:
	SmComSerialWrapper(SOCKET socket);
	virtual ~SmComSerialWrapper() { }

	U32 smComVCom_Open(const char *pComPortString);
	U16 smComVCom_Close(void);
	U32 smComVCom_Transceive(apdu_t *pApdu);
	U32 smComVCom_TransceiveRaw(U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen);
	U32 smComVCom_GetATR(U8* pAtr, U16* atrLen);
	int smComVcom_JrcpTransceive();
	bool closeOn_exit;
private:
    U32 smComVCom_CloseConn(U8* pRx, U16* pRxLen);
	U32 smComVCom_SetState(void);
	int JrcpReceiveMsg(void *ptr_msg_buff, unsigned int data_len);
	int JrcpSendMsg(void *ptr_msg_buff, unsigned int len);
	int jrcp_send_response();

	unsigned char headerBuffer[REMOTE_JC_SHELL_HEADER_LEN];
	int headerBuffer_len;
	unsigned char dataBuffer[MAX_BUF_SIZE];
	int dataBuffer_len;
	unsigned char outBuffer[MAX_BUF_SIZE];
	U32 outBuffer_len;

	apdu_t recvbuf;
	SOCKET clientSocket;
	void updateHeaderLen(unsigned char * header, int len);
	void jcrp_failed_status(void);
	void loopbackTest(void);
	void replyTerminalInfo(void);
};
